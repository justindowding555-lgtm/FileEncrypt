//! Text key file the window can write and read back.
//!
//! ```text
//! FileEncrypt-Key-v1
//! <32-byte key, standard base64>
//! ```
//!
//! The second line may also be 64 hex characters. Files this app writes
//! always use base64.

use std::fs;
use std::path::Path;

use aegis::aegis256::Aegis256;
use aes_gcm::aead::{KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError};

const HEADER: &str = "FileEncrypt-Key-v1";
const PROTECTED_HEADER: &str = "FileEncrypt-Key-v2";
const KDF_ROUNDS: u32 = 600_000;
const MAX_KEY_FILE_BYTES: u64 = 4096;

pub fn generate_key() -> Zeroizing<[u8; 32]> {
    let mut generated = Aes256Gcm::generate_key(OsRng);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(generated.as_slice());
    Zeroize::zeroize(generated.as_mut_slice());
    key
}

pub fn fingerprint(key: &[u8]) -> String {
    let digest = Sha256::digest(key);
    let hex: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02X}"))
        .collect();
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex is utf-8"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<(), CryptoError> {
    let encoded = STANDARD.encode(key);
    let mut body = format!("{HEADER}\n{encoded}\n");
    let result = crypto::atomic_write(path, body.as_bytes());
    body.zeroize();
    result
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8; 16],
    rounds: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if passphrase.is_empty() || passphrase.len() > 1024 || !(600_000..=2_000_000).contains(&rounds)
    {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(pbkdf2_sha256(passphrase.as_bytes(), salt, rounds))
}

fn pbkdf2_sha256(passphrase: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 32]> {
    // PBKDF2-HMAC-SHA256, one block for a 32-byte derived key.
    let base =
        <Hmac<Sha256> as Mac>::new_from_slice(passphrase).expect("HMAC accepts any key length");
    let mut mac = base.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut block = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(&block);
    for _ in 1..rounds {
        let mut mac = base.clone();
        mac.update(&block);
        block = mac.finalize().into_bytes();
        for (out, part) in output.iter_mut().zip(block.iter()) {
            *out ^= *part;
        }
    }
    block.as_mut_slice().zeroize();
    output
}

pub fn write_protected_key_file(
    path: &Path,
    key: &[u8; 32],
    passphrase: &str,
) -> Result<(), CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::InvalidKeyFile(
            "enter a passphrase to protect the key".into(),
        ));
    }
    let random = Aes256Gcm::generate_key(OsRng);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&random[..16]);
    let nonce_random = Aes256Gcm::generate_key(OsRng);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_random);
    let wrapping = derive_passphrase_key(passphrase, &salt, KDF_ROUNDS)?;
    let mut body = key.to_vec();
    let tag = Aegis256::<32>::new(&wrapping, &nonce)
        .encrypt_in_place(&mut body, PROTECTED_HEADER.as_bytes());
    body.extend_from_slice(&tag);
    let mut text = format!(
        "{PROTECTED_HEADER}\npbkdf2-sha256:{KDF_ROUNDS}\n{}\n{}\n{}\n",
        STANDARD.encode(salt),
        STANDARD.encode(nonce),
        STANDARD.encode(&body)
    );
    let result = crypto::atomic_write(path, text.as_bytes());
    body.zeroize();
    text.zeroize();
    result
}

pub fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    read_key_file_with_passphrase(path, None)
}

pub fn read_key_file_with_passphrase(
    path: &Path,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let meta = fs::metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            CryptoError::InvalidKeyFile(format!("key file not found: {}", path.display()))
        } else {
            CryptoError::Io(err)
        }
    })?;
    if !meta.is_file() {
        return Err(CryptoError::NotAFile(format!(
            "not a file: {}",
            path.display()
        )));
    }
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(CryptoError::InvalidKeyFile(format!(
            "{} is too large to be a key file",
            path.display()
        )));
    }
    let mut text = fs::read_to_string(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::InvalidData {
            CryptoError::InvalidKeyFile(format!("{} is not valid text", path.display()))
        } else {
            CryptoError::Io(err)
        }
    })?;
    let parsed = parse_key_file(path, &text, passphrase);
    text.zeroize();
    parsed
}

pub fn parse_key_material(text: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let compact: String = text
        .trim()
        .trim_start_matches('\u{feff}')
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if compact.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    decode_key_bytes(&compact)
}

fn parse_key_file(
    path: &Path,
    text: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let text = text.trim_start_matches('\u{feff}');
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() == 5 && lines[0] == PROTECTED_HEADER {
        let passphrase = passphrase
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CryptoError::InvalidKeyFile("this key file needs its passphrase".into())
            })?;
        let rounds: u32 = lines[1]
            .strip_prefix("pbkdf2-sha256:")
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| CryptoError::InvalidKeyFile("invalid key derivation settings".into()))?;
        let salt = STANDARD
            .decode(lines[2])
            .map_err(|_| CryptoError::InvalidKeyFile("invalid key salt".into()))?;
        let nonce = STANDARD
            .decode(lines[3])
            .map_err(|_| CryptoError::InvalidKeyFile("invalid key nonce".into()))?;
        let mut sealed = STANDARD
            .decode(lines[4])
            .map_err(|_| CryptoError::InvalidKeyFile("invalid protected key".into()))?;
        if salt.len() != 16 || nonce.len() != 32 || sealed.len() != 64 {
            sealed.zeroize();
            return Err(CryptoError::InvalidKeyFile(
                "invalid protected key length".into(),
            ));
        }
        let wrapping =
            derive_passphrase_key(passphrase, salt.as_slice().try_into().unwrap(), rounds)?;
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&sealed[32..]);
        sealed.truncate(32);
        Aegis256::<32>::new(&wrapping, nonce.as_slice().try_into().unwrap())
            .decrypt_in_place(&mut sealed, &tag, PROTECTED_HEADER.as_bytes())
            .map_err(|_| {
                CryptoError::InvalidKeyFile("wrong passphrase or damaged key file".into())
            })?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&sealed);
        sealed.zeroize();
        return Ok(key);
    }
    if lines.len() != 2 || lines[0] != HEADER {
        return Err(CryptoError::InvalidKeyFile(format!(
            "{} is not a FileEncrypt key file. Expected a FileEncrypt-Key-v1 line, then the key",
            path.display()
        )));
    }
    parse_key_material(lines[1]).map_err(|_| {
        CryptoError::InvalidKeyFile(format!(
            "{}: the key line must be 32 bytes in hex or standard base64",
            path.display()
        ))
    })
}

fn decode_key_bytes(compact: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return decode_hex(compact);
    }
    let mut bytes = match STANDARD.decode(compact) {
        Ok(bytes) => bytes,
        Err(_) => match STANDARD_NO_PAD.decode(compact) {
            Ok(bytes) => bytes,
            Err(_) => return Err(CryptoError::InvalidKeyMaterial),
        },
    };
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn decode_hex(text: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let bytes = text.as_bytes();
    for index in 0..32 {
        let pair = &bytes[index * 2..index * 2 + 2];
        let encoded = std::str::from_utf8(pair).map_err(|_| CryptoError::InvalidKeyMaterial)?;
        key[index] =
            u8::from_str_radix(encoded, 16).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "fileencrypt-key-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn written_key_roundtrips_and_is_not_raw_bytes() {
        let dir = TempDir::new();
        let path = dir.path.join("vault.key");
        let key = generate_key();
        write_key_file(&path, &key).unwrap();
        let loaded = read_key_file(&path).unwrap();
        assert_eq!(loaded.as_slice(), key.as_slice());
        assert_eq!(fingerprint(loaded.as_slice()), fingerprint(key.as_slice()));

        let stored = fs::read(&path).unwrap();
        assert!(!stored.windows(32).any(|window| window == key.as_slice()));
        let text = String::from_utf8(stored).unwrap();
        assert!(text.starts_with("FileEncrypt-Key-v1\n"));

        let replacement = [0x22u8; 32];
        write_key_file(&path, &replacement).unwrap();
        assert_eq!(read_key_file(&path).unwrap().as_slice(), &replacement);
    }

    #[test]
    fn hex_whitespace_and_unpadded_base64_are_accepted() {
        let dir = TempDir::new();
        let path = dir.path.join("hex.key");
        let key = [0xabu8; 32];
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        fs::write(&path, format!("\u{feff}FileEncrypt-Key-v1\n{hex}\n")).unwrap();
        assert_eq!(read_key_file(&path).unwrap().as_slice(), &key);

        let encoded = STANDARD.encode(key);
        let unpadded = encoded.trim_end_matches('=');
        let spaced = format!("FileEncrypt-Key-v1\n\n{unpadded}\n");
        fs::write(&path, spaced).unwrap();
        assert_eq!(read_key_file(&path).unwrap().as_slice(), &key);

        let parsed = parse_key_material(&format!("  {encoded}  ")).unwrap();
        assert_eq!(parsed.as_slice(), &key);
    }

    #[test]
    fn malformed_key_files_are_rejected() {
        let dir = TempDir::new();
        let path = dir.path.join("bad.key");

        fs::write(&path, "nope\n").unwrap();
        assert!(matches!(
            read_key_file(&path),
            Err(CryptoError::InvalidKeyFile(_))
        ));

        fs::write(&path, "FileEncrypt-Key-v1\nYQ==\n").unwrap();
        assert!(matches!(
            read_key_file(&path),
            Err(CryptoError::InvalidKeyFile(_))
        ));

        let good = STANDARD.encode([1u8; 32]);
        fs::write(&path, format!("FileEncrypt-Key-v1\n{good}\nextra\n")).unwrap();
        assert!(matches!(
            read_key_file(&path),
            Err(CryptoError::InvalidKeyFile(_))
        ));

        fs::write(&path, vec![0, 159, 146, 150]).unwrap();
        assert!(read_key_file(&path).is_err());
        assert!(parse_key_material("  ").is_err());
        assert_ne!(fingerprint(&[1u8; 32]), fingerprint(&[2u8; 32]));
    }

    #[test]
    fn protected_key_requires_the_right_passphrase() {
        let dir = TempDir::new();
        let path = dir.path.join("protected.key");
        let key = [0x5a; 32];
        write_protected_key_file(&path, &key, "a long backup passphrase").unwrap();
        assert!(read_key_file(&path).is_err());
        assert!(read_key_file_with_passphrase(&path, Some("wrong passphrase")).is_err());
        assert_eq!(
            read_key_file_with_passphrase(&path, Some("a long backup passphrase"))
                .unwrap()
                .as_slice(),
            &key
        );
        assert!(!fs::read(&path).unwrap().windows(32).any(|part| part == key));
    }

    #[test]
    fn pbkdf2_matches_published_sha256_vector() {
        let derived = pbkdf2_sha256(b"password", b"salt", 1);
        let actual: String = derived.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            actual,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }
}
