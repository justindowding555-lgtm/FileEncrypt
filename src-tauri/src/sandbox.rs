//! Read-only previews. Plaintext is bounded, authenticated in memory, and never
//! passed to a filesystem writer or an external application.
use std::collections::HashSet;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::commands::{lock, AppState};
use crate::{archive_read, crypto, key_file, source::Source};

const MAX_ITEMS: usize = 10_000;
const MAX_PREVIEW_BYTES: usize = 32 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const LOCKED: &str =
    "Sandbox locked. The loaded key or its readable key file is no longer available.";

#[derive(Default)]
pub(crate) struct Registry {
    revision: u64,
    current: Option<Arc<Session>>,
}

struct Session {
    id: String,
    key: Zeroizing<[u8; 32]>,
    key_path: PathBuf,
    file_hash: [u8; 32],
    revoked: AtomicBool,
    reading: AtomicBool,
    items: Vec<Item>,
}

struct Item {
    source: PathBuf,
    zip_index: Option<usize>,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    session_id: String,
    items: Vec<CatalogItem>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct CatalogItem {
    id: usize,
    name: String,
    kind: &'static str,
}

#[derive(Serialize)]
pub struct Content {
    kind: &'static str,
    mime: &'static str,
    data: String,
}

impl Drop for Content {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

fn format(name: &str) -> (&'static str, &'static str) {
    let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "txt" | "md" | "csv" | "tsv" | "json" | "jsonl" | "log" | "xml" | "yaml" | "yml"
        | "toml" | "ini" | "conf" | "html" | "htm" | "svg" | "css" | "js" | "ts" | "jsx"
        | "tsx" | "rs" | "py" | "sql" | "sh" | "ps1" | "c" | "h" | "cpp" | "java" => {
            ("text", "text/plain")
        }
        "png" => ("image", "image/png"),
        "jpg" | "jpeg" => ("image", "image/jpeg"),
        "gif" => ("image", "image/gif"),
        "webp" => ("image", "image/webp"),
        "bmp" => ("image", "image/bmp"),
        "ico" => ("image", "image/x-icon"),
        "mp3" => ("audio", "audio/mpeg"),
        "wav" => ("audio", "audio/wav"),
        "ogg" | "oga" => ("audio", "audio/ogg"),
        "m4a" => ("audio", "audio/mp4"),
        "flac" => ("audio", "audio/flac"),
        "mp4" | "m4v" => ("video", "video/mp4"),
        "webm" => ("video", "video/webm"),
        "ogv" => ("video", "video/ogg"),
        _ => ("unsupported", "application/octet-stream"),
    }
}

pub(crate) fn revoke(state: &AppState) {
    let mut registry = lock(&state.sandbox);
    registry.revision = registry.revision.wrapping_add(1);
    if let Some(session) = registry.current.take() {
        session.revoked.store(true, Ordering::Release);
    }
}

fn revoke_session(state: &AppState, session: &Session) {
    session.revoked.store(true, Ordering::Release);
    let mut registry = lock(&state.sandbox);
    if registry
        .current
        .as_ref()
        .is_some_and(|current| current.id == session.id)
    {
        registry.current = None;
        registry.revision = registry.revision.wrapping_add(1);
    }
}

impl Session {
    fn validate(&self, state: &AppState) -> Result<(), String> {
        if self.revoked.load(Ordering::Acquire)
            || lock(&state.key).as_deref() != Some(&*self.key)
            || lock(&state.key_path).as_ref() != Some(&self.key_path)
            || *lock(&state.key_file_hash) != Some(self.file_hash)
        {
            return Err(LOCKED.into());
        }
        // Open the path anew on every check: a cached handle can outlive removal
        // or a disconnected drive. Hash all bytes, not just metadata/existence.
        let bytes = key_file::read_key_snapshot(&self.key_path).map_err(|_| LOCKED.to_string())?;
        let actual: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        if actual != self.file_hash || self.revoked.load(Ordering::Acquire) {
            return Err(LOCKED.into());
        }
        Ok(())
    }
}

fn current(state: &AppState, id: &str) -> Result<Arc<Session>, String> {
    let session = lock(&state.sandbox).current.clone().ok_or(LOCKED)?;
    if session.id != id {
        return Err(LOCKED.into());
    }
    if let Err(error) = session.validate(state) {
        revoke_session(state, &session);
        return Err(error);
    }
    Ok(session)
}

fn open(state: &AppState, paths: Vec<String>) -> Result<Catalog, String> {
    if paths.is_empty() || paths.len() > MAX_ITEMS {
        return Err("Select between 1 and 10,000 encrypted files.".into());
    }
    revoke(state);
    let revision = lock(&state.sandbox).revision;
    let key = lock(&state.key)
        .clone()
        .ok_or("Load a saved key file first.")?;
    let key_path = lock(&state.key_path).clone().ok_or("Sandbox viewing requires a saved key file. Session-only keys cannot keep a sandbox active." )?;
    let file_hash =
        lock(&state.key_file_hash).ok_or("Reload the saved key file to enable sandbox viewing.")?;
    let mut session = Session {
        id: revision.to_string(),
        key,
        key_path,
        file_hash,
        revoked: AtomicBool::new(false),
        reading: AtomicBool::new(false),
        items: Vec::new(),
    };
    session.validate(state)?;
    let mut warnings = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        let path = PathBuf::from(path);
        if !seen.insert(path.clone()) {
            continue;
        }
        session.validate(state)?;
        let mut source = Source::open(&path, false).map_err(|error| error.to_string())?;
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            let entries = archive_read::entries_from_reader(&mut source.file)
                .map_err(|error| error.to_string())?;
            if session.items.len() + entries.len() > MAX_ITEMS {
                return Err(
                    "The sandbox supports at most 10,000 files, including ZIP contents.".into(),
                );
            }
            let (names, authenticated) =
                archive_read::inspect_names_from_reader(&mut source.file, &session.key, &entries)
                    .map_err(|error| error.to_string())?;
            if !authenticated {
                warnings.push(format!("{}: older ZIP; each opened file is authenticated, but bundle completeness cannot be checked.", path.display()));
            }
            for (zip_index, name) in names.into_iter().enumerate() {
                session.items.push(Item {
                    source: path.clone(),
                    zip_index: Some(zip_index),
                    name,
                });
            }
        } else {
            if session.items.len() == MAX_ITEMS {
                return Err("The sandbox supports at most 10,000 files.".into());
            }
            let name = crypto::sandbox_name(&session.key, &path, &mut source.file)
                .map_err(|error| error.to_string())?;
            session.items.push(Item {
                source: path,
                zip_index: None,
                name,
            });
        }
        source.check().map_err(|error| error.to_string())?;
    }
    session.validate(state)?;
    let catalog = Catalog {
        session_id: session.id.clone(),
        warnings,
        items: session
            .items
            .iter()
            .enumerate()
            .map(|(id, item)| CatalogItem {
                id,
                name: item.name.clone(),
                kind: format(&item.name).0,
            })
            .collect(),
    };
    let mut registry = lock(&state.sandbox);
    if registry.revision != revision {
        return Err(LOCKED.into());
    }
    registry.current = Some(Arc::new(session));
    Ok(catalog)
}

struct MemoryWriter<'a> {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    revoked: &'a AtomicBool,
}

impl Write for MemoryWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, LOCKED));
        }
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "This file exceeds the sandbox preview limit of {} MiB.",
                    self.limit / (1024 * 1024)
                ),
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read(state: &AppState, id: &str, item_id: usize) -> Result<Content, String> {
    let session = current(state, id)?;
    if session
        .reading
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("A preview is loading. Try again when it finishes.".into());
    }
    struct Reading<'a>(&'a AtomicBool);
    impl Drop for Reading<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _reading = Reading(&session.reading);
    let item = session.items.get(item_id).ok_or("Unknown sandbox file.")?;
    let (kind, mime) = format(&item.name);
    if kind == "unsupported" {
        return Err("This file type has no in-app preview. The sandbox supports UTF-8 text, images, audio, and video; PDF and Office files are not supported.".into());
    }
    let limit = if kind == "text" {
        MAX_TEXT_BYTES
    } else {
        MAX_PREVIEW_BYTES
    };
    let mut writer = MemoryWriter {
        // Reserve once so Vec growth cannot leave unwiped old allocations.
        bytes: Zeroizing::new(Vec::with_capacity(limit)),
        limit,
        revoked: &session.revoked,
    };
    let mut source = Source::open(&item.source, false).map_err(|error| error.to_string())?;
    if let Some(index) = item.zip_index {
        let entries = archive_read::entries_from_reader(&mut source.file)
            .map_err(|error| error.to_string())?;
        let (names, _) =
            archive_read::inspect_names_from_reader(&mut source.file, &session.key, &entries)
                .map_err(|error| error.to_string())?;
        if names.get(index) != Some(&item.name) {
            return Err("The encrypted ZIP changed. Close and reopen the sandbox.".into());
        }
        let entry = entries.get(index).ok_or("The encrypted ZIP changed.")?;
        let mut reader = archive_read::entry_reader(&mut source.file, entry, None)
            .map_err(|error| error.to_string())?;
        crypto::sandbox_decrypt_entry(&session.key, &mut reader, &mut writer)
            .map_err(|error| error.to_string())?;
    } else {
        let mut reader = BufReader::new(&mut source.file);
        if crypto::sandbox_name(&session.key, &item.source, &mut reader)
            .map_err(|error| error.to_string())?
            != item.name
        {
            return Err("The encrypted file changed. Close and reopen the sandbox.".into());
        }
        crypto::sandbox_decrypt(&session.key, &mut reader, &mut writer)
            .map_err(|error| error.to_string())?;
    }
    source.check().map_err(|error| error.to_string())?;
    if kind == "text" && std::str::from_utf8(&writer.bytes).is_err() {
        return Err("This text file is not UTF-8 and cannot be previewed.".into());
    }
    current(state, id)?;
    // Only return bytes after the final authentication tag, source checks, and
    // a fresh key-file read have all succeeded.
    Ok(Content {
        kind,
        mime,
        data: STANDARD.encode(writer.bytes.as_slice()),
    })
}

#[tauri::command]
pub async fn open_sandbox(app: tauri::AppHandle, paths: Vec<String>) -> Result<Catalog, String> {
    tauri::async_runtime::spawn_blocking(move || open(app.state::<AppState>().inner(), paths))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn read_sandbox_file(
    app: tauri::AppHandle,
    session_id: String,
    item_id: usize,
) -> Result<Content, String> {
    tauri::async_runtime::spawn_blocking(move || {
        read(app.state::<AppState>().inner(), &session_id, item_id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn check_sandbox(app: tauri::AppHandle, session_id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        current(app.state::<AppState>().inner(), &session_id).map(|_| ())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn close_sandbox(state: tauri::State<'_, AppState>, session_id: Option<String>) {
    if let Some(id) = session_id {
        let session = lock(&state.sandbox).current.clone();
        if let Some(session) = session.filter(|session| session.id == id) {
            revoke_session(&state, &session);
        }
    } else {
        revoke(&state);
    }
}

pub(crate) fn start_monitor(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if app.get_webview_window("main").is_none() {
            break;
        }
        let state = app.state::<AppState>();
        let session = lock(&state.sandbox).current.clone();
        if let Some(session) = session {
            if session.validate(&state).is_err() {
                revoke_session(&state, &session);
                let _ = app.emit("sandbox-locked", &session.id);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive, crypto::JobOptions, test_support::TestDir};
    use std::fs;

    fn fixture() -> (TestDir, AppState, PathBuf, [u8; 32]) {
        let dir = TestDir::new();
        let key_path = dir.0.join("vault.key");
        let key = [42; 32];
        key_file::write_key_file(&key_path, &key).unwrap();
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new(key));
        *lock(&state.key_path) = Some(key_path.clone());
        *lock(&state.key_file_hash) =
            Some(key_file::checked_file_hash(&key_path, &key, None).unwrap());
        (dir, state, key_path, key)
    }

    fn options() -> JobOptions {
        JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        }
    }

    fn encrypted(dir: &TestDir, name: &str, bytes: &[u8], key: &[u8; 32]) -> String {
        let path = dir.0.join(name);
        fs::write(&path, bytes).unwrap();
        let encrypted = crypto::encrypt_file(key, &path, &options()).unwrap();
        fs::remove_file(path).unwrap();
        encrypted.display().to_string()
    }

    fn files(dir: &TestDir) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(&dir.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    #[test]
    fn authenticated_preview_never_creates_a_plaintext_file() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let before = files(&dir);
        let catalog = open(&state, vec![path]).unwrap();
        assert_eq!(catalog.items[0].name, "private.txt");
        let content = read(&state, &catalog.session_id, 0).unwrap();
        assert_eq!(STANDARD.decode(&content.data).unwrap(), b"private contents");
        assert_eq!(files(&dir), before);
        revoke(&state);
        assert!(read(&state, &catalog.session_id, 0).is_err());
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn removed_or_changed_key_revokes_access_despite_cached_master_key() {
        for removed in [true, false] {
            let (dir, state, key_path, key) = fixture();
            let path = encrypted(&dir, "private.txt", b"private contents", &key);
            let catalog = open(&state, vec![path]).unwrap();
            let original = fs::read(&key_path).unwrap();
            if removed {
                fs::remove_file(&key_path).unwrap();
            } else {
                key_file::write_key_file(&key_path, &[43; 32]).unwrap();
            }
            assert!(lock(&state.key).is_some());
            assert!(current(&state, &catalog.session_id).is_err());
            assert!(lock(&state.sandbox).current.is_none());
            fs::write(&key_path, original).unwrap();
            assert!(
                read(&state, &catalog.session_id, 0).is_err(),
                "reconnecting cannot revive a revoked session"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_but_unreadable_key_file_locks_the_sandbox() {
        use std::os::windows::fs::OpenOptionsExt;
        let (dir, state, key_path, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        let _exclusive = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&key_path)
            .unwrap();
        assert!(key_path.exists());
        assert!(current(&state, &catalog.session_id).is_err());
    }

    #[test]
    fn session_only_keys_and_key_switches_cannot_authorize_a_preview() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path.clone()]).unwrap();
        *lock(&state.key) = Some(Zeroizing::new([9; 32]));
        assert!(read(&state, &catalog.session_id, 0).is_err());
        *lock(&state.key) = Some(Zeroizing::new(key));
        *lock(&state.key_path) = None;
        assert!(open(&state, vec![path]).is_err());
    }

    #[test]
    fn protected_keys_are_rechecked_without_retaining_a_passphrase() {
        let (dir, state, key_path, key) = fixture();
        key_file::write_protected_key_file(&key_path, &key, "sandbox test passphrase").unwrap();
        *lock(&state.key_file_hash) = Some(
            key_file::checked_file_hash(&key_path, &key, Some("sandbox test passphrase")).unwrap(),
        );
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        assert!(read(&state, &catalog.session_id, 0).is_ok());
        let mut bytes = fs::read(&key_path).unwrap();
        let index = bytes.len() - 4;
        bytes[index] ^= 1;
        fs::write(&key_path, bytes).unwrap();
        assert!(current(&state, &catalog.session_id).is_err());
    }

    #[test]
    fn damaged_ciphertext_returns_no_partial_plaintext() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![path]).unwrap();
        assert!(read(&state, &catalog.session_id, 0).is_err());
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn compressed_zip_previews_keep_paths_without_extracting_files() {
        let (dir, state, _, key) = fixture();
        let folder = dir.0.join("notes");
        fs::create_dir(&folder).unwrap();
        let input = folder.join("private.txt");
        fs::write(&input, b"compressed private contents").unwrap();
        let zipped = archive::encrypt_to_zip_with_progress(
            &key,
            &[input.clone()],
            &JobOptions {
                output_dir: Some(dir.0.clone()),
                ..options()
            },
            Some(&dir.0),
            true,
            None,
            None,
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![zipped.path.display().to_string()]).unwrap();
        assert_eq!(catalog.items[0].name, "notes/private.txt");
        assert!(catalog.warnings.is_empty());
        let content = read(&state, &catalog.session_id, 0).unwrap();
        assert_eq!(
            STANDARD.decode(&content.data).unwrap(),
            b"compressed private contents"
        );
        assert_eq!(files(&dir), before);
        assert_eq!(fs::read_dir(folder).unwrap().count(), 0);
    }

    #[test]
    fn decompression_is_bounded_by_the_preview_limit() {
        let (dir, state, _, key) = fixture();
        let input = dir.0.join("oversized.txt");
        fs::write(&input, vec![b'x'; MAX_TEXT_BYTES + 1]).unwrap();
        let zipped = archive::encrypt_to_zip_with_progress(
            &key,
            &[input.clone()],
            &options(),
            None,
            true,
            None,
            None,
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![zipped.path.display().to_string()]).unwrap();
        assert!(read(&state, &catalog.session_id, 0)
            .err()
            .unwrap()
            .contains("limit"));
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn unsupported_formats_and_non_utf8_text_are_never_opened_externally() {
        let (dir, state, _, key) = fixture();
        let unsupported = encrypted(&dir, "private.docx", b"not a document preview", &key);
        let invalid_text = encrypted(&dir, "private.txt", &[255, 254], &key);
        let catalog = open(&state, vec![unsupported, invalid_text]).unwrap();
        assert_eq!(catalog.items[0].kind, "unsupported");
        assert!(read(&state, &catalog.session_id, 0)
            .err()
            .unwrap()
            .contains("no in-app preview"));
        assert!(read(&state, &catalog.session_id, 1)
            .err()
            .unwrap()
            .contains("not UTF-8"));
    }
}
