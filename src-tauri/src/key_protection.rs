//! Emergency access verifiers, recovery, and migration of legacy protected keys.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use aegis::aegis256::Aegis256;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
use zeroize::Zeroizing;

use crate::commands::{self, lock, AppState, AppStatus};
use crate::crypto::{self, CryptoError};
use crate::{emergency, file_guard, key_file, source::Source};

const HEADER: &str = "FileEncrypt-Key-v3";
const ROUNDS: u32 = 600_000;
const PENDING_LIFETIME: Duration = Duration::from_secs(600);
const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct Session {
    pending: Option<Pending>,
    failures: u8,
    retry_after: Option<Instant>,
    attempting: bool,
    setup_marker: Option<PathBuf>,
    setup_required: bool,
    needs_current_reference: bool,
    access_path: Option<PathBuf>,
    setup_upgrade: bool,
}

struct Pending {
    token: String,
    path: PathBuf,
    revision: u64,
    identity: Option<file_guard::Identity>,
    source_hash: Option<[u8; 32]>,
    text: Zeroizing<String>,
    access_hash: Option<[u8; 32]>,
    access_identity: Option<file_guard::Identity>,
    key_update: Option<Migration>,
    backup_path: Option<PathBuf>,
    expires: Instant,
    recovery: bool,
    first_run: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared {
    token: String,
    recovery_code: String,
    key_path: String,
    migration_backup_path: Option<String>,
}

const SETUP_COMPLETE: &[u8] = b"FileEncrypt-Access-Setup-v1\n";
const ACCESS_HEADER: &str = "FileEncrypt-Emergency-Access-v1";

struct AccessRecord {
    rounds: u32,
    salt: [u8; 16],
    password_tag: [u8; 32],
    recovery_tag: [u8; 32],
}

impl AccessRecord {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| "Emergency access settings are damaged.")?;
        let lines: Vec<_> = text.lines().collect();
        if bytes.len() > 4096 || lines.len() != 5 || lines[0] != ACCESS_HEADER {
            return Err("Emergency access settings are damaged.".into());
        }
        let rounds = lines[1]
            .strip_prefix("pbkdf2-sha256:")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| (600_000..=2_000_000).contains(v))
            .ok_or("Emergency access settings are damaged.")?;
        Ok(Self {
            rounds,
            salt: *decode::<16>(lines[2]).map_err(|e| e.to_string())?,
            password_tag: *decode::<32>(lines[3]).map_err(|e| e.to_string())?,
            recovery_tag: *decode::<32>(lines[4]).map_err(|e| e.to_string())?,
        })
    }

    fn mac(&self, key: &[u8], purpose: &str) -> Hmac<Sha256> {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(
            format!(
                "{ACCESS_HEADER}\npbkdf2-sha256:{}\n{}\n{purpose}",
                self.rounds,
                STANDARD.encode(self.salt)
            )
            .as_bytes(),
        );
        mac
    }

    fn verify(&self, password: Option<&str>, recovery: Option<&str>) -> Result<(), String> {
        let (key, tag, purpose) = if let Some(code) = recovery {
            (
                recovery_material(code).map_err(|e| e.to_string())?,
                &self.recovery_tag,
                "recovery",
            )
        } else {
            let password = password
                .filter(|v| !v.is_empty())
                .ok_or("Enter your emergency password.")?;
            (
                key_file::derive_passphrase_key(password, &self.salt, self.rounds)
                    .map_err(|e| e.to_string())?,
                &self.password_tag,
                "password",
            )
        };
        self.mac(key.as_slice(), purpose)
            .verify_slice(tag)
            .map_err(|_| "Incorrect emergency password or recovery code.".into())
    }
}

fn access_text(password: &str) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
    let random = key_file::generate_key();
    let mut record = AccessRecord {
        rounds: ROUNDS,
        salt: [0; 16],
        password_tag: [0; 32],
        recovery_tag: [0; 32],
    };
    record.salt.copy_from_slice(&random[..16]);
    let derived = key_file::derive_passphrase_key(password, &record.salt, ROUNDS)
        .map_err(|e| e.to_string())?;
    let (recovery, code) = new_recovery();
    record.password_tag = record
        .mac(derived.as_slice(), "password")
        .finalize()
        .into_bytes()
        .into();
    record.recovery_tag = record
        .mac(recovery.as_slice(), "recovery")
        .finalize()
        .into_bytes()
        .into();
    let text = Zeroizing::new(format!(
        "{ACCESS_HEADER}\npbkdf2-sha256:{ROUNDS}\n{}\n{}\n{}\n",
        STANDARD.encode(record.salt),
        STANDARD.encode(record.password_tag),
        STANDARD.encode(record.recovery_tag)
    ));
    Ok((text, code))
}

// A staged migration keeps its key encrypted until the recovery acknowledgement.
struct Migration {
    nonce: Zeroizing<[u8; 32]>,
    body: Zeroizing<Vec<u8>>,
}

impl Migration {
    fn new(key: &[u8; 32], code: &str) -> Result<Self, String> {
        let recovery = recovery_material(code).map_err(|e| e.to_string())?;
        let nonce = key_file::generate_key();
        let mut body = Zeroizing::new(key.to_vec());
        let tag = Aegis256::<32>::new(&recovery, &nonce)
            .encrypt_in_place(&mut body, b"FileEncrypt emergency migration");
        body.extend_from_slice(&tag);
        Ok(Self { nonce, body })
    }

    fn open(&self, code: &str) -> Result<Zeroizing<[u8; 32]>, String> {
        let recovery = recovery_material(code).map_err(|e| e.to_string())?;
        let mut body = self.body.clone();
        let mut tag = [0; 32];
        tag.copy_from_slice(&body[32..]);
        Aegis256::<32>::new(&recovery, &self.nonce)
            .decrypt_in_place(&mut body[..32], &tag, b"FileEncrypt emergency migration")
            .map_err(|_| "Invalid setup recovery code.")?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&body[..32]);
        Ok(key)
    }
}

fn access_path(state: &AppState) -> Result<PathBuf, String> {
    lock(&state.protection)
        .access_path
        .clone()
        .ok_or("Emergency access storage is unavailable.".into())
}

pub(crate) fn verify_emergency_password(
    state: &AppState,
    password: Option<&str>,
) -> Result<(), String> {
    let path = access_path(state)?;
    let bytes = match key_file::read_key_snapshot(&path) {
        Ok(bytes) => bytes,
        Err(_) if setup_required(state) => {
            // Upgrade an already locked profile from the earlier implementation.
            // Only a protected legacy key can prove its existing password here.
            let key_path = lock(&state.key_path)
                .clone()
                .ok_or("Emergency access setup is incomplete.")?;
            let key_bytes = key_file::read_key_snapshot(&key_path)
                .map_err(|_| "Emergency access setup is incomplete or unavailable.")?;
            observe_key_file(state, &key_bytes);
            if !needs_current_reference(state) {
                return Err("Emergency access setup is incomplete.".into());
            }
            key_file::parse_key_snapshot(&key_path, &key_bytes, password)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        Err(_) => return Err("Emergency access setup is incomplete or unavailable.".into()),
    };
    AccessRecord::parse(&bytes)?.verify(password, None)
}

#[cfg(test)]
pub(crate) fn set_test_access(state: &AppState, marker: PathBuf, password: &str) {
    restore_setup(state, marker);
    let (text, _) = access_text(password).unwrap();
    crypto::atomic_write(&access_path(state).unwrap(), text.as_bytes()).unwrap();
    lock(&state.protection).setup_required = false;
}

pub(crate) fn restore(app: &tauri::AppHandle, state: &AppState) -> tauri::Result<()> {
    restore_setup(
        state,
        app.path().app_config_dir()?.join("access-setup.complete"),
    );
    Ok(())
}

pub(crate) fn restore_setup(state: &AppState, marker: PathBuf) {
    let access = marker.with_file_name("emergency-access.verifier");
    let completed =
        key_file::read_key_snapshot(&access).is_ok_and(|bytes| AccessRecord::parse(&bytes).is_ok());
    let mut session = lock(&state.protection);
    session.access_path = Some(access);
    session.setup_upgrade =
        !completed && std::fs::read(&marker).is_ok_and(|bytes| bytes == SETUP_COMPLETE);
    session.setup_required = !completed;
    session.setup_marker = Some(marker);
}

pub(crate) fn setup_required(state: &AppState) -> bool {
    lock(&state.protection).setup_required
}

pub(crate) fn setup_is_upgrade(state: &AppState) -> bool {
    let session = lock(&state.protection);
    session.setup_upgrade || session.needs_current_reference
}

pub(crate) fn observe_key_file(state: &AppState, bytes: &[u8]) {
    let protected = is_recoverable(bytes)
        || std::str::from_utf8(bytes).is_ok_and(|text| {
            text.trim_start_matches('\u{feff}')
                .lines()
                .next()
                .is_some_and(|line| line.trim() == "FileEncrypt-Key-v2")
        });
    lock(&state.protection).needs_current_reference = protected;
}

pub(crate) fn needs_current_reference(state: &AppState) -> bool {
    lock(&state.protection).needs_current_reference
}

pub(crate) fn default_key_path(state: &AppState) -> Option<PathBuf> {
    lock(&state.protection)
        .setup_marker
        .as_ref()
        .and_then(|path| path.parent())
        .map(|dir| dir.join("workspace.key"))
}

pub(crate) fn cancel(state: &AppState) {
    lock(&state.protection).pending = None;
}

/// Serialize credential checks and throttle repeated failures in this process.
pub(crate) struct Attempt<'a> {
    state: &'a AppState,
    succeeded: bool,
}

impl<'a> Attempt<'a> {
    pub(crate) fn begin(state: &'a AppState) -> Result<Self, String> {
        let mut session = lock(&state.protection);
        if session.attempting
            || session
                .retry_after
                .is_some_and(|until| until > Instant::now())
        {
            return Err("Unable to check the key reference. Wait a minute and try again.".into());
        }
        session.attempting = true;
        Ok(Self {
            state,
            succeeded: false,
        })
    }

    pub(crate) fn success(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        let mut session = lock(&self.state.protection);
        session.attempting = false;
        if self.succeeded {
            session.failures = 0;
            session.retry_after = None;
        } else {
            session.failures = session.failures.saturating_add(1);
            if session.failures >= 5 {
                session.failures = 0;
                session.retry_after = Some(Instant::now() + COOLDOWN);
            }
        }
    }
}

pub(crate) fn is_recoverable(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.trim_start_matches('\u{feff}')
            .lines()
            .next()
            .is_some_and(|line| line.trim() == HEADER)
    })
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::InvalidKeyFile(message.into())
}

fn decode<const N: usize>(text: &str) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let bytes = Zeroizing::new(
        STANDARD
            .decode(text)
            .map_err(|_| invalid("invalid protected key"))?,
    );
    if bytes.len() != N {
        return Err(invalid("invalid protected key length"));
    }
    let mut value = Zeroizing::new([0; N]);
    value.copy_from_slice(&bytes);
    Ok(value)
}

fn recovery_material(code: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if code.len() > 128 {
        return Err(invalid("invalid recovery code"));
    }
    let compact = Zeroizing::new(
        code.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    let hex = Zeroizing::new(
        compact
            .strip_prefix("FE-R1-")
            .ok_or_else(|| invalid("invalid recovery code"))?
            .replace('-', ""),
    );
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid("invalid recovery code"));
    }
    let mut key = Zeroizing::new([0; 32]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid recovery code"))?;
    }
    Ok(key)
}

fn new_recovery() -> (Zeroizing<[u8; 32]>, Zeroizing<String>) {
    use std::fmt::Write;
    let key = key_file::generate_key();
    let mut code = Zeroizing::new(String::from("FE-R1"));
    for chunk in key.chunks(4) {
        code.push('-');
        for byte in chunk {
            write!(&mut *code, "{byte:02X}").expect("String write");
        }
    }
    (key, code)
}

#[cfg(test)]
fn seal_slot(key: &[u8; 32], wrapping: &[u8; 32], nonce: &[u8; 32], aad: &[u8]) -> String {
    let mut sealed = Zeroizing::new(key.to_vec());
    let tag = Aegis256::<32>::new(wrapping, nonce).encrypt_in_place(&mut sealed, aad);
    sealed.extend_from_slice(&tag);
    STANDARD.encode(sealed.as_slice())
}

#[cfg(test)]
fn protected_text(
    key: &[u8; 32],
    passphrase: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>), CryptoError> {
    let random = key_file::generate_key();
    let mut salt = [0; 16];
    salt.copy_from_slice(&random[..16]);
    let nonce = key_file::generate_key();
    let recovery_nonce = key_file::generate_key();
    let metadata = format!(
        "{HEADER}\npbkdf2-sha256:{ROUNDS}\n{}\n{}\n{}\n",
        STANDARD.encode(salt),
        STANDARD.encode(*nonce),
        STANDARD.encode(*recovery_nonce)
    );
    let wrapping = key_file::derive_passphrase_key(passphrase, &salt, ROUNDS)?;
    let (recovery, code) = new_recovery();
    let text = Zeroizing::new(format!(
        "{metadata}{}\n{}\n",
        seal_slot(
            key,
            &wrapping,
            &nonce,
            format!("{metadata}passphrase").as_bytes()
        ),
        seal_slot(
            key,
            &recovery,
            &recovery_nonce,
            format!("{metadata}recovery").as_bytes()
        )
    ));
    // Verify both envelopes before allowing this file to replace the original.
    if open(text.as_bytes(), Some(passphrase), None)?.as_slice() != key
        || open(text.as_bytes(), None, Some(&code))?.as_slice() != key
    {
        return Err(invalid("protected key verification failed"));
    }
    Ok((text, code))
}

pub(crate) fn open(
    bytes: &[u8],
    passphrase: Option<&str>,
    recovery: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if bytes.len() > 4096 {
        return Err(invalid("key file is too large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid protected key"))?;
    let lines: Vec<_> = text
        .trim_start_matches('\u{feff}')
        .lines()
        .map(str::trim)
        .collect();
    if lines.len() != 7 || lines[0] != HEADER {
        return Err(invalid("this key file has no recovery code"));
    }
    let rounds = lines[1]
        .strip_prefix("pbkdf2-sha256:")
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| (600_000..=2_000_000).contains(v))
        .ok_or_else(|| invalid("invalid key derivation settings"))?;
    let salt = decode::<16>(lines[2])?;
    let nonce = decode::<32>(lines[3])?;
    let recovery_nonce = decode::<32>(lines[4])?;
    let mut primary = decode::<64>(lines[5])?;
    let mut backup = decode::<64>(lines[6])?;
    let metadata = format!("{}\n", lines[..5].join("\n"));
    let (wrapping, nonce, sealed, purpose) = if let Some(code) = recovery {
        (
            recovery_material(code)?,
            &*recovery_nonce,
            &mut *backup,
            "recovery",
        )
    } else {
        let value = passphrase
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("this key file needs its key reference"))?;
        (
            key_file::derive_passphrase_key(value, &salt, rounds)?,
            &*nonce,
            &mut *primary,
            "passphrase",
        )
    };
    let mut tag = [0; 32];
    tag.copy_from_slice(&sealed[32..]);
    Aegis256::<32>::new(&wrapping, nonce)
        .decrypt_in_place(
            &mut sealed[..32],
            &tag,
            format!("{metadata}{purpose}").as_bytes(),
        )
        .map_err(|_| invalid("incorrect key reference or damaged key file"))?;
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&sealed[..32]);
    Ok(key)
}

fn read_source(path: &Path) -> Result<(Source, Zeroizing<Vec<u8>>), String> {
    let mut source = Source::open(path, false).map_err(|e| e.to_string())?;
    if source.len() > 4096 {
        return Err("The selected key file is too large.".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut source.file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    source.check().map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("The selected key file changed.".into());
    }
    Ok((source, bytes))
}

fn prepare(
    state: &AppState,
    passphrase: Option<&str>,
    new_passphrase: &str,
    confirmation: &str,
    recovery_code: Option<&str>,
) -> Result<Prepared, String> {
    prepare_for_path(
        state,
        passphrase,
        new_passphrase,
        confirmation,
        recovery_code,
        None,
    )
}

fn prepare_for_path(
    state: &AppState,
    passphrase: Option<&str>,
    new_passphrase: &str,
    confirmation: &str,
    recovery_code: Option<&str>,
    first_run_path: Option<&Path>,
) -> Result<Prepared, String> {
    if new_passphrase.trim().chars().count() < 12 || new_passphrase.len() > 1024 {
        return Err(
            "Use an emergency password of at least 12 characters (at most 1024 bytes).".into(),
        );
    }
    if new_passphrase != confirmation {
        return Err("The new passwords do not match.".into());
    }
    let recovery = recovery_code.is_some();
    let first_run = first_run_path.is_some();
    let (revision, path, current, expected_hash, remembered) = {
        let _change = lock(&state.key_change);
        if first_run && !setup_required(state) {
            return Err("Access setup is already complete.".into());
        }
        if state.running.load(Ordering::Acquire) {
            return Err("Finish the file job before changing emergency access.".into());
        }
        if !recovery {
            emergency::ensure_unlocked(state)?;
        }
        let remembered = lock(&state.key_path).clone();
        let path = remembered
            .clone()
            .or_else(|| first_run_path.map(Path::to_path_buf))
            .unwrap_or_default();
        (
            state.key_revision.load(Ordering::Acquire),
            path,
            lock(&state.key).clone(),
            *lock(&state.key_file_hash),
            remembered.is_some(),
        )
    };
    let mut attempt = Attempt::begin(state)?;
    let access = access_path(state)?;
    let (access_hash, access_identity) = if access.try_exists().map_err(|e| e.to_string())? {
        let (source, bytes) = read_source(&access)?;
        AccessRecord::parse(&bytes)?.verify(passphrase, recovery_code)?;
        (
            Some(Sha256::digest(bytes.as_slice()).into()),
            Some(file_guard::identity(&source.file).map_err(|e| e.to_string())?),
        )
    } else {
        if !first_run {
            return Err("Complete emergency access setup first.".into());
        }
        (None, None)
    };
    let create_new = first_run && !remembered && !path.try_exists().map_err(|e| e.to_string())?;
    if create_new && recovery {
        return Err("Choose the existing key file to recover the previous setup.".into());
    }
    let (identity, source_hash, migration_key) = if first_run && !create_new {
        let (source, bytes) = read_source(&path)?;
        observe_key_file(state, &bytes);
        let needs_migration = needs_current_reference(state);
        // The previous implementation protected the file with the emergency
        // password. Reuse that one password, never ask for a second credential.
        let key = if needs_migration && recovery {
            open(&bytes, None, recovery_code)
        } else {
            key_file::parse_key_snapshot(&path, &bytes, Some(new_passphrase))
        }
        .map_err(|_| {
            if needs_migration {
                "Enter the password from your previous setup, or use its recovery code.".to_string()
            } else {
                "The saved key file could not be loaded.".to_string()
            }
        })?;
        let hash: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        if current
            .as_ref()
            .is_some_and(|value| value.as_slice() != key.as_slice())
            || (current.is_some() && expected_hash.is_some_and(|expected| expected != hash))
        {
            return Err("The saved key changed. Start setup again.".into());
        }
        source.check().map_err(|e| e.to_string())?;
        (
            Some(file_guard::identity(&source.file).map_err(|e| e.to_string())?),
            Some(hash),
            if needs_migration { Some(key) } else { None },
        )
    } else if create_new {
        (None, None, Some(key_file::generate_key()))
    } else {
        (None, None, None)
    };
    attempt.success();
    let (text, code) = access_text(new_passphrase)?;
    let key_update = migration_key
        .as_ref()
        .map(|key| Migration::new(key, &code))
        .transpose()?;
    let _change = lock(&state.key_change);
    if state.key_revision.load(Ordering::Acquire) != revision
        || state.running.load(Ordering::Acquire)
    {
        return Err("Key access changed. Start setup again.".into());
    }
    if !recovery {
        emergency::ensure_unlocked(state)?;
    }
    let token = crypto::opaque_file_name().to_string_lossy().into_owned();
    let backup_path = if identity.is_some() && key_update.is_some() {
        Some(path.with_file_name(format!("emergency-migration-backup-{token}.key")))
    } else {
        None
    };
    let prepared = Prepared {
        token: token.clone(),
        recovery_code: code.to_string(),
        key_path: path.display().to_string(),
        migration_backup_path: backup_path.as_ref().map(|path| path.display().to_string()),
    };
    lock(&state.protection).pending = Some(Pending {
        token,
        path,
        revision,
        identity,
        source_hash,
        text,
        access_hash,
        access_identity,
        key_update,
        backup_path,
        expires: Instant::now() + PENDING_LIFETIME,
        recovery,
        first_run,
    });
    Ok(prepared)
}

#[cfg(test)]
fn commit(state: &AppState, token: &str, recovery_saved: bool) -> Result<(), String> {
    commit_with_activation(state, token, recovery_saved, None, None)
}

fn commit_with_activation(
    state: &AppState,
    token: &str,
    recovery_saved: bool,
    activation_code: Option<&str>,
    settings_path: Option<&Path>,
) -> Result<(), String> {
    if !recovery_saved {
        return Err("Save the recovery code separately before continuing.".into());
    }
    let _change = lock(&state.key_change);
    let mut session = lock(&state.protection);
    if session
        .pending
        .as_ref()
        .is_none_or(|pending| pending.token != token)
    {
        return Err("Start access setup again.".into());
    }
    let pending = session.pending.take().unwrap();
    drop(session);
    if pending.expires < Instant::now()
        || pending.revision != state.key_revision.load(Ordering::Acquire)
        || state.running.load(Ordering::Acquire)
    {
        return Err("Key access changed or setup expired. Start setup again.".into());
    }
    if !pending.recovery {
        emergency::ensure_unlocked(state)?;
    }
    let access = access_path(state)?;
    if let Some(identity) = pending.access_identity {
        let (source, bytes) = read_source(&access)?;
        if file_guard::identity(&source.file).map_err(|e| e.to_string())? != identity
            || Some(<[u8; 32]>::from(Sha256::digest(bytes.as_slice()))) != pending.access_hash
        {
            return Err("Emergency access settings changed. Start setup again.".into());
        }
    } else if access.try_exists().map_err(|e| e.to_string())? {
        return Err("Emergency access settings changed. Start setup again.".into());
    }
    let mut activated_key = None;
    if pending.first_run {
        if !setup_required(state) {
            return Err("Access setup is already complete.".into());
        }
        let code = activation_code.ok_or("Save the displayed recovery code before continuing.")?;
        AccessRecord::parse(pending.text.as_bytes())?.verify(None, Some(code))?;
        if let Some(identity) = pending.identity {
            let (source, bytes) = read_source(&pending.path)?;
            if file_guard::identity(&source.file).map_err(|e| e.to_string())? != identity
                || Some(<[u8; 32]>::from(Sha256::digest(bytes.as_slice()))) != pending.source_hash
            {
                return Err(
                    "The saved key file changed. The original was preserved; start setup again."
                        .into(),
                );
            }
            source.check().map_err(|e| e.to_string())?;
            if let Some(backup) = &pending.backup_path {
                crypto::write_transformed(backup, false, |writer| {
                    writer.write_all(bytes.as_slice())?;
                    Ok(())
                })
                .map_err(|e| {
                    format!("Could not back up the original key; it was left unchanged. {e}")
                })?;
                let saved_backup =
                    key_file::read_key_snapshot(backup).map_err(|e| e.to_string())?;
                if saved_backup.as_slice() != bytes.as_slice() {
                    return Err("The original key backup could not be verified; the key was left unchanged.".into());
                }
                source.check().map_err(|e| e.to_string())?;
            }
            if pending.key_update.is_none() {
                activated_key = Some(
                    key_file::parse_key_snapshot(&pending.path, &bytes, None)
                        .map_err(|e| e.to_string())?,
                );
            }
        }
        if let Some(migration) = &pending.key_update {
            let key = migration.open(code)?;
            let text = Zeroizing::new(format!("FileEncrypt-Key-v1\n{}\n", STANDARD.encode(*key)));
            if pending.identity.is_some() {
                crypto::atomic_write(&pending.path, text.as_bytes()).map_err(|e| e.to_string())?;
            } else {
                crypto::write_transformed(&pending.path, false, |writer| {
                    writer.write_all(text.as_bytes())?;
                    Ok(())
                })
                .map_err(|e| e.to_string())?;
            }
            activated_key = Some(key);
        }
    }
    // New installations never replace an unexpected credential file.
    if pending.access_identity.is_some() {
        crypto::atomic_write(&access, pending.text.as_bytes()).map_err(|e| e.to_string())?;
    } else {
        if let Some(parent) = access.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        crypto::write_transformed(&access, false, |writer| {
            writer.write_all(pending.text.as_bytes())?;
            Ok(())
        })
        .map_err(|e| e.to_string())?;
    }
    let saved = key_file::read_key_snapshot(&access).map_err(|e| e.to_string())?;
    if saved.as_slice() != pending.text.as_bytes() {
        return Err("Emergency access could not be verified. Keep the recovery code.".into());
    }
    if let Some(key) = activated_key {
        let bytes = key_file::read_key_snapshot(&pending.path).map_err(|e| e.to_string())?;
        let reopened =
            key_file::parse_key_snapshot(&pending.path, &bytes, None).map_err(|e| e.to_string())?;
        if reopened.as_slice() != key.as_slice() {
            return Err("The saved key changed. Reload it before continuing.".into());
        }
        lock(&state.emergency).disarm();
        crate::sandbox::revoke(state);
        *lock(&state.key_path) = Some(pending.path.clone());
        if !state.emergency_locked.load(Ordering::Acquire) {
            *lock(&state.key) = Some(key);
            *lock(&state.key_file_hash) = Some(Sha256::digest(bytes.as_slice()).into());
            commands::finish_emergency_unlock(state);
        } else {
            state.key_revision.fetch_add(1, Ordering::AcqRel);
        }
        lock(&state.protection).needs_current_reference = false;
    } else {
        state.key_revision.fetch_add(1, Ordering::AcqRel);
    }
    if pending.first_run {
        if let Some(path) = settings_path {
            commands::write_settings_to_path(state, path)?;
        }
        let marker = lock(&state.protection)
            .setup_marker
            .clone()
            .ok_or("Setup storage is unavailable.")?;
        crypto::atomic_write(&marker, SETUP_COMPLETE).map_err(|e| e.to_string())?;
        lock(&state.protection).setup_required = false;
    }
    Ok(())
}

#[tauri::command]
pub async fn prepare_first_run(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    path: String,
    passphrase: Option<String>,
    new_passphrase: String,
    confirmation: String,
    recovery_code: Option<String>,
) -> Result<Prepared, String> {
    let passphrase = passphrase.map(Zeroizing::new);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let confirmation = Zeroizing::new(confirmation);
    let recovery_code = recovery_code.map(Zeroizing::new);
    if window.label() != "main" {
        return Err("Set up access from the main window.".into());
    }
    let path = PathBuf::from(path.trim());
    if path.as_os_str().is_empty() {
        return Err("Choose a key file location before continuing.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        prepare_for_path(
            &app.state::<AppState>(),
            passphrase.as_deref().map(String::as_str),
            &new_passphrase,
            &confirmation,
            recovery_code.as_deref().map(String::as_str),
            Some(&path),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn prepare_key_protection(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    passphrase: Option<String>,
    new_passphrase: String,
    confirmation: String,
    recovery_code: Option<String>,
) -> Result<Prepared, String> {
    if window.label() != "main" {
        return Err("Use access settings from the main window.".into());
    }
    let passphrase = passphrase.map(Zeroizing::new);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let confirmation = Zeroizing::new(confirmation);
    let recovery_code = recovery_code.map(Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        prepare(
            &app.state::<AppState>(),
            passphrase.as_deref().map(String::as_str),
            &new_passphrase,
            &confirmation,
            recovery_code.as_deref().map(String::as_str),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn commit_key_protection(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    token: String,
    recovery_saved: bool,
    activation_code: Option<String>,
) -> Result<AppStatus, String> {
    let activation_code = activation_code.map(Zeroizing::new);
    if window.label() != "main" {
        return Err("Use access settings from the main window.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let settings = commands::settings_path(&app)?;
        commit_with_activation(
            &state,
            &token,
            recovery_saved,
            activation_code.as_deref().map(String::as_str),
            Some(&settings),
        )?;
        crate::sandbox::close_invalid_previews(&app);
        let status = commands::status(&state);
        let _ = app.emit("key-status-changed", &status);
        Ok(status)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn cancel_key_protection(
    state: tauri::State<'_, AppState>,
    window: tauri::WebviewWindow,
    token: String,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Use access settings from the main window.".into());
    }
    let mut session = lock(&state.protection);
    if session
        .pending
        .as_ref()
        .is_some_and(|pending| pending.token == token)
    {
        session.pending = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    const PASSPHRASE: &str = "a long unique key reference";
    const REPLACEMENT: &str = "a different long key reference";

    fn fixture() -> (TestDir, AppState, PathBuf) {
        let dir = TestDir::new();
        let state = AppState::default();
        let path = dir.0.join("saved.key");
        key_file::write_key_file(&path, &[42; 32]).unwrap();
        commands::restore_saved_key_from_path(&state, &path);
        restore_setup(&state, dir.0.join("access-setup.complete"));
        emergency::set_test_marker(&state, dir.0.join("emergency.lock"));
        (dir, state, path)
    }

    #[test]
    fn both_credentials_open_the_same_key_without_persisting_secrets_and_reject_tampering() {
        let (text, code) = protected_text(&[42; 32], PASSPHRASE).unwrap();
        assert!(!text.contains(PASSPHRASE));
        assert!(!text.contains(code.as_str()));
        assert!(!text.contains(&STANDARD.encode([42; 32])));
        assert!(open(text.as_bytes(), None, None).is_err());
        assert!(open(text.as_bytes(), Some("incorrect reference"), None).is_err());
        assert!(open(text.as_bytes(), None, Some(&new_recovery().1)).is_err());
        assert_eq!(
            open(text.as_bytes(), None, Some(&code)).unwrap().as_slice(),
            &[42; 32]
        );
        assert_eq!(
            key_file::parse_key_snapshot(Path::new("saved.key"), text.as_bytes(), Some(PASSPHRASE))
                .unwrap()
                .as_slice(),
            &[42; 32]
        );
        // Each envelope authenticates the common metadata and its own purpose.
        for index in 1..7 {
            let mut lines: Vec<_> = text.lines().map(str::to_owned).collect();
            if index == 1 {
                lines[index] = "pbkdf2-sha256:600001".into();
            } else {
                let replacement = if lines[index].starts_with('A') {
                    "B"
                } else {
                    "A"
                };
                lines[index].replace_range(..1, replacement);
            }
            let damaged = lines.join("\n");
            // A damaged primary ciphertext need not prevent legitimate recovery.
            if index != 5 {
                assert!(open(damaged.as_bytes(), None, Some(&code)).is_err());
            }
        }
        let mut lines: Vec<_> = text.lines().collect();
        lines.swap(5, 6);
        assert!(open(lines.join("\n").as_bytes(), None, Some(&code)).is_err());
        assert!(open(text.as_bytes(), None, Some("FE-R1-invalid")).is_err());
        assert!(open(
            text.replace("600000", "1").as_bytes(),
            Some(PASSPHRASE),
            None
        )
        .is_err());
    }

    fn first_setup(state: &AppState, path: &Path) -> Prepared {
        let setup =
            prepare_for_path(state, None, PASSPHRASE, PASSPHRASE, None, Some(path)).unwrap();
        commit_with_activation(state, &setup.token, true, Some(&setup.recovery_code), None)
            .unwrap();
        setup
    }

    #[test]
    fn staging_preserves_key_and_credentials_until_acknowledgement_and_rejects_replaced_files() {
        let (_dir, state, path) = fixture();
        let original = std::fs::read(&path).unwrap();
        assert!(prepare_for_path(&state, None, "short", "short", None, Some(&path)).is_err());
        assert!(
            prepare_for_path(&state, None, PASSPHRASE, "different", None, Some(&path)).is_err()
        );
        let setup =
            prepare_for_path(&state, None, PASSPHRASE, PASSPHRASE, None, Some(&path)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!access_path(&state).unwrap().exists());
        assert!(commit(&state, &setup.token, false).is_err());
        assert!(commit(&state, "unrelated token", true).is_err());
        key_file::write_key_file(&path, &[7; 32]).unwrap();
        let changed = std::fs::read(&path).unwrap();
        assert!(commit_with_activation(
            &state,
            &setup.token,
            true,
            Some(&setup.recovery_code),
            None
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), changed);
        assert!(!access_path(&state).unwrap().exists());
        assert!(lock(&state.protection).pending.is_none());
    }

    #[test]
    fn recovery_changes_only_emergency_credentials_and_never_clears_the_lock() {
        let (dir, state, path) = fixture();
        let original = std::fs::read(&path).unwrap();
        let setup = first_setup(&state, &path);
        let first_access = key_file::read_key_snapshot(&access_path(&state).unwrap()).unwrap();
        assert_eq!(
            key_file::read_key_file(&path).unwrap().as_slice(),
            &[42; 32]
        );
        emergency::lock_key(&state).unwrap();
        assert!(prepare(&state, Some(PASSPHRASE), REPLACEMENT, REPLACEMENT, None).is_err());
        let recovered = prepare(
            &state,
            None,
            REPLACEMENT,
            REPLACEMENT,
            Some(&setup.recovery_code),
        )
        .unwrap();
        assert_eq!(
            key_file::read_key_snapshot(&access_path(&state).unwrap())
                .unwrap()
                .as_slice(),
            first_access.as_slice()
        );
        commit(&state, &recovered.token, true).unwrap();
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(dir.0.join("emergency.lock").exists());
        assert!(lock(&state.key).is_none());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let saved = key_file::read_key_snapshot(&access_path(&state).unwrap()).unwrap();
        let record = AccessRecord::parse(&saved).unwrap();
        assert!(record.verify(Some(PASSPHRASE), None).is_err());
        assert!(record.verify(None, Some(&setup.recovery_code)).is_err());
        record.verify(None, Some(&recovered.recovery_code)).unwrap();
        assert!(emergency::unlock_key(&state, None).is_err());
        assert!(emergency::unlock_key(&state, Some(PASSPHRASE)).is_err());
        emergency::unlock_key(&state, Some(REPLACEMENT)).unwrap();
        assert_eq!(lock(&state.key).as_ref().unwrap().as_slice(), &[42; 32]);
        assert!(!dir.0.join("emergency.lock").exists());
        let restarted = AppState::default();
        restore_setup(&restarted, dir.0.join("access-setup.complete"));
        commands::restore_saved_key_from_path(&restarted, &path);
        assert!(lock(&restarted.key).is_some());
    }

    #[test]
    fn legacy_setup_migrates_the_same_key_with_one_password_or_its_recovery_code() {
        for recovery in [false, true] {
            let (dir, state, path) = fixture();
            let (legacy, old_code) = protected_text(&[42; 32], PASSPHRASE).unwrap();
            crypto::atomic_write(&path, legacy.as_bytes()).unwrap();
            commands::restore_saved_key_from_path(&state, &path);
            assert!(lock(&state.key).is_none());
            assert!(setup_required(&state));
            if recovery {
                emergency::lock_key(&state).unwrap();
            }
            let password = if recovery { REPLACEMENT } else { PASSPHRASE };
            let setup = prepare_for_path(
                &state,
                None,
                password,
                password,
                if recovery { Some(&old_code) } else { None },
                Some(&path),
            )
            .unwrap();
            assert_eq!(
                key_file::read_key_snapshot(&path).unwrap().as_slice(),
                legacy.as_bytes()
            );
            commit_with_activation(&state, &setup.token, true, Some(&setup.recovery_code), None)
                .unwrap();
            let backup = PathBuf::from(setup.migration_backup_path.as_ref().unwrap());
            assert_eq!(std::fs::read(&backup).unwrap(), legacy.as_bytes());
            assert_eq!(
                open(&std::fs::read(&backup).unwrap(), None, Some(&old_code))
                    .unwrap()
                    .as_slice(),
                &[42; 32]
            );
            assert_eq!(
                key_file::read_key_file(&path).unwrap().as_slice(),
                &[42; 32]
            );
            verify_emergency_password(&state, Some(password)).unwrap();
            if recovery {
                assert!(state.emergency_locked.load(Ordering::Acquire));
                assert!(lock(&state.key).is_none());
                assert!(dir.0.join("emergency.lock").exists());
                emergency::unlock_key(&state, Some(password)).unwrap();
            }
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert!(commands::refresh_key_file(&state));
            assert!(lock(&state.key).is_none());
            std::fs::write(&path, &bytes).unwrap();
            assert!(commands::refresh_key_file(&state));
            assert_eq!(lock(&state.key).as_ref().unwrap().as_slice(), &[42; 32]);
            let restarted = AppState::default();
            restore_setup(&restarted, dir.0.join("access-setup.complete"));
            commands::restore_saved_key_from_path(&restarted, &path);
            assert_eq!(lock(&restarted.key).as_ref().unwrap().as_slice(), &[42; 32]);
        }
    }

    #[test]
    fn verifier_contains_no_credentials_and_changed_settings_cannot_be_overwritten() {
        let (_dir, state, path) = fixture();
        let setup = first_setup(&state, &path);
        let access = access_path(&state).unwrap();
        let bytes = std::fs::read(&access).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(PASSPHRASE));
        assert!(!text.contains(&setup.recovery_code));
        assert!(!text.contains(&STANDARD.encode([42; 32])));
        assert!(prepare(&state, Some("incorrect"), REPLACEMENT, REPLACEMENT, None).is_err());
        let next = prepare(&state, Some(PASSPHRASE), REPLACEMENT, REPLACEMENT, None).unwrap();
        let (changed, _) = access_text("another valid emergency password").unwrap();
        crypto::atomic_write(&access, changed.as_bytes()).unwrap();
        assert!(commit(&state, &next.token, true).is_err());
        assert_eq!(std::fs::read(&access).unwrap(), changed.as_bytes());
    }

    #[test]
    fn a_failed_migration_backup_preserves_the_original_key_and_does_not_publish_credentials() {
        let (_dir, state, path) = fixture();
        key_file::write_protected_key_file(&path, &[42; 32], PASSPHRASE).unwrap();
        let original = std::fs::read(&path).unwrap();
        commands::restore_saved_key_from_path(&state, &path);
        let setup =
            prepare_for_path(&state, None, PASSPHRASE, PASSPHRASE, None, Some(&path)).unwrap();
        let backup = PathBuf::from(setup.migration_backup_path.as_ref().unwrap());
        std::fs::write(&backup, "existing backup").unwrap();
        assert!(commit_with_activation(
            &state,
            &setup.token,
            true,
            Some(&setup.recovery_code),
            None
        )
        .unwrap_err()
        .contains("back up"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "existing backup");
        assert!(!access_path(&state).unwrap().exists());
        assert!(lock(&state.key).is_none());
    }

    #[test]
    fn emergency_password_recovery_works_without_the_key_drive_but_does_not_unlock_it() {
        let (_dir, state, path) = fixture();
        let setup = first_setup(&state, &path);
        let bytes = std::fs::read(&path).unwrap();
        emergency::lock_key(&state).unwrap();
        std::fs::remove_file(&path).unwrap();
        let recovered = prepare(
            &state,
            None,
            REPLACEMENT,
            REPLACEMENT,
            Some(&setup.recovery_code),
        )
        .unwrap();
        commit(&state, &recovered.token, true).unwrap();
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(!path.exists());
        assert!(lock(&state.key).is_none());
        std::fs::write(&path, bytes).unwrap();
        assert!(!commands::refresh_key_file(&state));
        assert!(lock(&state.key).is_none());
        emergency::unlock_key(&state, Some(REPLACEMENT)).unwrap();
        assert_eq!(lock(&state.key).as_ref().unwrap().as_slice(), &[42; 32]);
    }

    #[test]
    fn failed_attempts_are_serialized_and_throttled_without_disabling_the_lock() {
        let (_dir, state, _) = fixture();
        emergency::lock_key(&state).unwrap();
        for _ in 0..5 {
            let attempt = Attempt::begin(&state).unwrap();
            assert!(Attempt::begin(&state).is_err());
            drop(attempt);
        }
        assert!(Attempt::begin(&state).is_err());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        lock(&state.protection).retry_after = Some(Instant::now() - Duration::from_secs(1));
        let mut attempt = Attempt::begin(&state).unwrap();
        attempt.success();
        drop(attempt);
        assert_eq!(lock(&state.protection).failures, 0);
        assert!(lock(&state.protection).retry_after.is_none());
    }

    #[test]
    fn first_launch_keeps_key_loading_automatic_and_creates_only_emergency_verifiers_after_acknowledgement(
    ) {
        let dir = TestDir::new();
        let state = AppState::default();
        let marker = dir.0.join("access-setup.complete");
        restore_setup(&state, marker.clone());
        assert!(setup_required(&state));
        let path = default_key_path(&state).unwrap();
        let settings = dir.0.join("settings.json");
        let setup =
            prepare_for_path(&state, None, PASSPHRASE, PASSPHRASE, None, Some(&path)).unwrap();
        assert!(!path.exists());
        assert!(!marker.exists());
        assert!(lock(&state.key).is_none());
        assert!(commit_with_activation(
            &state,
            &setup.token,
            false,
            Some(&setup.recovery_code),
            Some(&settings)
        )
        .is_err());
        assert!(!path.exists());
        assert!(setup_required(&state));
        commit_with_activation(
            &state,
            &setup.token,
            true,
            Some(&setup.recovery_code),
            Some(&settings),
        )
        .unwrap();
        assert!(!setup_required(&state));
        let active = lock(&state.key).clone().unwrap();
        assert!(key_file::read_key_file(&path).is_ok());
        verify_emergency_password(&state, Some(PASSPHRASE)).unwrap();
        assert_eq!(
            key_file::read_key_file_with_passphrase(&path, None)
                .unwrap()
                .as_slice(),
            active.as_slice()
        );
        assert_eq!(std::fs::read(&marker).unwrap(), SETUP_COMPLETE);
        let preferences = std::fs::read_to_string(&settings).unwrap();
        assert!(!preferences.contains(PASSPHRASE));
        assert!(!preferences.contains(&setup.recovery_code));
        let saved_path: serde_json::Value = serde_json::from_str(&preferences).unwrap();
        assert_eq!(
            PathBuf::from(saved_path["key_path"].as_str().unwrap()),
            path
        );
        let restarted = AppState::default();
        restore_setup(&restarted, marker);
        assert!(!setup_required(&restarted));
        commands::restore_saved_key_from_path(&restarted, &path);
        assert!(lock(&restarted.key).is_some());
    }

    #[test]
    fn an_existing_dev_profile_requires_setup_and_preserves_its_original_key() {
        let (dir, state, path) = fixture();
        restore_setup(&state, dir.0.join("access-setup.complete"));
        assert!(setup_required(&state));
        let other_path = dir.0.join("different.key");
        let setup = prepare_for_path(
            &state,
            None,
            PASSPHRASE,
            PASSPHRASE,
            None,
            Some(&other_path),
        )
        .unwrap();
        assert_eq!(setup.key_path, path.display().to_string());
        assert_eq!(
            key_file::read_key_file(&path).unwrap().as_slice(),
            &[42; 32]
        );
        commit_with_activation(&state, &setup.token, true, Some(&setup.recovery_code), None)
            .unwrap();
        assert_eq!(lock(&state.key).as_ref().unwrap().as_slice(), &[42; 32]);
        assert!(!other_path.exists());
        assert!(!setup_required(&state));
        assert!(prepare_for_path(
            &state,
            Some(PASSPHRASE),
            REPLACEMENT,
            REPLACEMENT,
            None,
            Some(&path)
        )
        .is_err());
    }

    #[test]
    fn incomplete_or_missing_setup_repeats_and_a_missing_saved_key_is_never_replaced() {
        let (dir, state, path) = fixture();
        let marker = dir.0.join("access-setup.complete");
        std::fs::write(&marker, "incomplete").unwrap();
        restore_setup(&state, marker.clone());
        assert!(setup_required(&state));
        std::fs::remove_file(&path).unwrap();
        let alternate = dir.0.join("replacement.key");
        assert!(
            prepare_for_path(&state, None, PASSPHRASE, PASSPHRASE, None, Some(&alternate)).is_err()
        );
        assert!(!path.exists());
        assert!(!alternate.exists());
        let restarted = AppState::default();
        restore_setup(&restarted, marker);
        assert!(setup_required(&restarted));
    }
}
