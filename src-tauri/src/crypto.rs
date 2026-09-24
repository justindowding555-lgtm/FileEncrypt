//! On-disk encryption for one file at a time.
//!
//! New files use AEGIS-256 with a 256-bit tag. The stored master key is not
//! the body key: HKDF-SHA256 derives a wrap key, and that wrap key seals a
//! fresh 32-byte file key under a random 256-bit nonce. The original file
//! name is encrypted in a fixed-size slot, and the file on disk is given a
//! random name ending in `.fenc`. Decrypt writes the original name again.
//! The body is split into 64 KiB chunks. Each chunk nonce is a 192-bit
//! random prefix plus a counter, and the last chunk sets the high bit so a
//! shortened file fails authentication.
//!
//! Files written by the first version of this app are AES-256-GCM in the
//! STREAM construction and still decrypt. Their header is:
//!
//! ```text
//! offset  size  field
//! 0       4     magic b"FENC"
//! 4       1     version (1)
//! 5       4     plaintext chunk size, big-endian
//! 9       7     STREAM nonce prefix
//! 16      …     AES-256-GCM STREAM chunks, each with a 16-byte tag
//! ```

use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use aegis::aegis256::Aegis256;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::DecryptorBE32;
#[cfg(test)]
use aes_gcm::aead::stream::EncryptorBE32;
#[cfg(test)]
use aes_gcm::aead::AeadCore;
use aes_gcm::aead::{KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"FENC";
const LEGACY_VERSION: u8 = 1;
const AEGIS_VERSION: u8 = 2;
const NAMED_VERSION: u8 = 3;
const BUNDLE_VERSION: u8 = 4;
const COMPRESSED_BUNDLE_VERSION: u8 = 5;
const AEGIS_TAG_LEN: usize = 32;
const STREAM_PREFIX_LEN: usize = 24;
const AEGIS_HEADER_LEN: usize = 4 + 1 + 4 + 32 + 32 + AEGIS_TAG_LEN + STREAM_PREFIX_LEN;
const NAME_SLOT: usize = 512;
const NAME_FRAME_LEN: usize = NAME_SLOT + AEGIS_TAG_LEN;
const NONCE_PREFIX_LEN: usize = 7;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
const HEADER_LEN: usize = 16;
const AAD_LEN: usize = 9;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    NotAFile(String),
    #[error("output already exists: {0}")]
    OutputExists(String),
    #[error("input and output are the same file")]
    SamePath,
    #[error("that path is the key file. Choose a different file")]
    KeyFileConflict,
    #[error("this file is not a FileEncrypt file")]
    NotEncrypted,
    #[error("unsupported FileEncrypt version {0}")]
    UnsupportedVersion(u8),
    #[error("encrypted file has an invalid chunk size")]
    BadChunkSize,
    #[error("encrypted file is truncated or damaged")]
    Truncated,
    #[error("decryption failed. The key is wrong, or the file was changed")]
    AuthenticationFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("{0}")]
    InvalidKeyFile(String),
    #[error("the key must be 32 bytes, written as 64 hex characters or standard base64")]
    InvalidKeyMaterial,
    #[error("the stored file name is not a single file name")]
    BadEncryptedName,
    #[error("wrote {output}, but could not delete the original file: {source}")]
    OriginalRemains { output: String, source: io::Error },
}

#[derive(Debug, Clone)]
pub struct JobOptions {
    pub overwrite: bool,
    pub remove_original: bool,
    pub key_file: Option<PathBuf>,
    /// When set, results go in this folder under the output file name.
    /// When empty, each result stays beside its input.
    pub output_dir: Option<PathBuf>,
}

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct DeleteOnDrop<'a> {
    path: &'a Path,
}

impl Drop for DeleteOnDrop<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.path);
    }
}

struct OpenedHeader {
    aad: [u8; AAD_LEN],
    nonce: [u8; NONCE_PREFIX_LEN],
    chunk_size: usize,
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

#[cfg(test)]
pub fn encrypt_file(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
) -> Result<PathBuf, CryptoError> {
    transform(Direction::Encrypt, key, input, options, None)
}

#[cfg(test)]
pub fn decrypt_file(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
) -> Result<PathBuf, CryptoError> {
    transform(Direction::Decrypt, key, input, options, None)
}

pub type ProgressCallback<'a> = dyn Fn(u64) -> io::Result<()> + Sync + 'a;

struct ProgressReader<'a, R> {
    inner: R,
    callback: &'a ProgressCallback<'a>,
}

struct CountingReader<'a, R> {
    inner: R,
    count: &'a Cell<u64>,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.count
            .set(self.count.get().saturating_add(count as u64));
        Ok(count)
    }
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (self.callback)(0)?;
        let count = self.inner.read(buffer)?;
        if count > 0 {
            (self.callback)(count as u64)?;
        }
        Ok(count)
    }
}

pub fn encrypt_file_with_progress(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: &ProgressCallback<'_>,
) -> Result<PathBuf, CryptoError> {
    transform(Direction::Encrypt, key, input, options, Some(callback))
}

pub fn encrypt_bundle_entry_with_progress(
    key: &[u8; 32],
    input: &Path,
    relative_name: &str,
    compress: bool,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    validate_relative_name(relative_name)?;
    let input_size = fs::metadata(input)?.len();
    let output = opaque_output_path(input, options.output_dir.as_deref(), options.overwrite)?;
    finish_job(input, output, options, |destination| {
        write_transformed(destination, options.overwrite, |writer| {
            let count = Cell::new(0u64);
            let reader = CountingReader {
                inner: BufReader::new(File::open(input)?),
                count: &count,
            };
            let mut reader: Box<dyn Read + '_> = if let Some(callback) = callback {
                Box::new(ProgressReader {
                    inner: reader,
                    callback,
                })
            } else {
                Box::new(reader)
            };
            if compress {
                let mut compressed =
                    flate2::read::ZlibEncoder::new(&mut reader, flate2::Compression::default());
                encrypt_aegis(
                    key,
                    relative_name,
                    &mut compressed,
                    writer,
                    COMPRESSED_BUNDLE_VERSION,
                    Some(input_size),
                )?;
            } else {
                encrypt_aegis(
                    key,
                    relative_name,
                    &mut reader,
                    writer,
                    BUNDLE_VERSION,
                    None,
                )?;
            }
            if count.get() != input_size || fs::metadata(input)?.len() != input_size {
                return Err(CryptoError::NotAFile(format!(
                    "source file changed while encrypting: {}",
                    input.display()
                )));
            }
            check_progress(callback)
        })
    })
}

enum PipeMessage {
    Data(SecretBytes),
    Done,
    Failed(String),
}

struct PipeWriter(SyncSender<PipeMessage>);

impl Write for PipeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .send(PipeMessage::Data(SecretBytes(bytes.to_vec())))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "rotation stopped"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    receiver: Receiver<PipeMessage>,
    pending: SecretBytes,
    offset: usize,
    done: bool,
}

impl Read for PipeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.done {
            return Ok(0);
        }
        loop {
            if self.offset < self.pending.0.len() {
                let count = bytes.len().min(self.pending.0.len() - self.offset);
                bytes[..count].copy_from_slice(&self.pending.0[self.offset..self.offset + count]);
                self.pending.0[self.offset..self.offset + count].zeroize();
                self.offset += count;
                return Ok(count);
            }
            self.pending.0.clear();
            self.offset = 0;
            match self.receiver.recv() {
                Ok(PipeMessage::Data(data)) => self.pending = data,
                Ok(PipeMessage::Done) => {
                    self.done = true;
                    return Ok(0);
                }
                Ok(PipeMessage::Failed(message)) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, message))
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "rotation stopped",
                    ))
                }
            }
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.pending.0.zeroize();
    }
}

pub fn rotate_file_with_progress(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    let version = legacy_version(input)?.ok_or(CryptoError::NotEncrypted)?;
    let output = opaque_output_path(input, options.output_dir.as_deref(), false)?;
    finish_job(input, output, options, |destination| {
        let source = BufReader::new(File::open(input)?);
        let mut source: Box<dyn Read + Send + '_> = if let Some(callback) = callback {
            Box::new(ProgressReader {
                inner: source,
                callback,
            })
        } else {
            Box::new(source)
        };
        let opened = if matches!(
            version,
            NAMED_VERSION | BUNDLE_VERSION | COMPRESSED_BUNDLE_VERSION
        ) {
            Some(open_named(&mut source, old_key)?)
        } else {
            None
        };
        let (name, size, target_version) = if let Some(opened) = &opened {
            (opened.name.clone(), opened.original_size, opened.version)
        } else if matches!(version, LEGACY_VERSION | AEGIS_VERSION) {
            (
                decrypted_file_name(file_name(input)?)?
                    .to_str()
                    .ok_or(CryptoError::BadEncryptedName)?
                    .to_string(),
                None,
                NAMED_VERSION,
            )
        } else {
            return Err(CryptoError::UnsupportedVersion(version));
        };
        let result = write_transformed(destination, false, |writer| {
            std::thread::scope(|scope| {
                let (sender, receiver) = sync_channel(2);
                let reader = PipeReader {
                    receiver,
                    pending: SecretBytes(Vec::new()),
                    offset: 0,
                    done: false,
                };
                let worker = scope.spawn(move || {
                    let result = {
                        let mut sink = PipeWriter(sender.clone());
                        match opened {
                            Some(opened) => decrypt_named_body(&mut source, &mut sink, &opened),
                            None if version == AEGIS_VERSION => {
                                decrypt_aegis(old_key, &mut source, &mut sink)
                            }
                            None => decrypt_stream(old_key, &mut source, &mut sink),
                        }
                    };
                    let _ = sender.send(match &result {
                        Ok(()) => PipeMessage::Done,
                        Err(err) => PipeMessage::Failed(err.to_string()),
                    });
                    result
                });
                let mut reader = reader;
                let encrypted = if target_version == COMPRESSED_BUNDLE_VERSION {
                    let mut compressed =
                        flate2::read::ZlibEncoder::new(&mut reader, flate2::Compression::default());
                    encrypt_aegis(
                        new_key,
                        &name,
                        &mut compressed,
                        writer,
                        target_version,
                        size,
                    )
                } else {
                    encrypt_aegis(new_key, &name, &mut reader, writer, target_version, None)
                };
                drop(reader);
                let decrypted = worker.join().map_err(|_| CryptoError::EncryptFailed)?;
                decrypted?;
                encrypted?;
                check_progress(callback)
            })
        });
        result
    })
}

pub fn decrypt_file_with_progress(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: &ProgressCallback<'_>,
) -> Result<PathBuf, CryptoError> {
    transform(Direction::Decrypt, key, input, options, Some(callback))
}

pub fn inspect_output_name(
    key: &[u8; 32],
    input: &Path,
) -> Result<std::ffi::OsString, CryptoError> {
    match legacy_version(input)? {
        Some(NAMED_VERSION | BUNDLE_VERSION | COMPRESSED_BUNDLE_VERSION) => {
            let mut reader = BufReader::new(File::open(input)?);
            Ok(open_named(&mut reader, key)?.name.into())
        }
        Some(LEGACY_VERSION | AEGIS_VERSION) => decrypted_file_name(file_name(input)?),
        Some(version) => Err(CryptoError::UnsupportedVersion(version)),
        None => Err(CryptoError::NotEncrypted),
    }
}

pub(crate) fn named_file_name_from_reader(
    key: &[u8; 32],
    reader: &mut dyn Read,
) -> Result<String, CryptoError> {
    Ok(open_named(reader, key)?.name)
}

pub fn verify_file(
    key: &[u8; 32],
    input: &Path,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<(), CryptoError> {
    let file = File::open(input)?;
    let mut reader = BufReader::new(file);
    let mut sink = io::sink();
    if let Some(callback) = callback {
        let mut reader = ProgressReader {
            inner: reader,
            callback,
        };
        verify_reader(key, input, &mut reader, &mut sink)
    } else {
        verify_reader(key, input, &mut reader, &mut sink)
    }
}

fn verify_reader(
    key: &[u8; 32],
    input: &Path,
    reader: &mut dyn Read,
    sink: &mut dyn Write,
) -> Result<(), CryptoError> {
    match legacy_version(input)? {
        Some(NAMED_VERSION | BUNDLE_VERSION | COMPRESSED_BUNDLE_VERSION) => {
            let opened = open_named(reader, key)?;
            decrypt_named_body(reader, sink, &opened)
        }
        Some(AEGIS_VERSION) => decrypt_aegis(key, reader, sink),
        Some(LEGACY_VERSION) => decrypt_stream(key, reader, sink),
        Some(version) => Err(CryptoError::UnsupportedVersion(version)),
        None => Err(CryptoError::NotEncrypted),
    }
}

pub(crate) fn atomic_write(destination: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let partial = sibling(
        destination,
        &format!(".partial-{}", opaque_file_name().to_string_lossy()),
    )?;
    let _guard = DeleteOnDrop { path: &partial };
    {
        let mut file = create_private_file(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    commit_partial(&partial, destination, true)?;
    Ok(())
}

fn transform(
    direction: Direction,
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    if !input.exists() {
        return Err(CryptoError::NotAFile(format!(
            "file not found: {}",
            input.display()
        )));
    }
    if !input.is_file() {
        return Err(CryptoError::NotAFile(format!(
            "not a file: {}",
            input.display()
        )));
    }

    match direction {
        Direction::Encrypt => {
            let output =
                opaque_output_path(input, options.output_dir.as_deref(), options.overwrite)?;
            let original_name = file_name_utf8(input)?;
            finish_job(input, output, options, |destination| {
                let input_file = File::open(input)?;
                let mut reader = BufReader::new(input_file);
                write_transformed(destination, options.overwrite, |writer| {
                    let result = if let Some(callback) = callback {
                        let mut reader = ProgressReader {
                            inner: reader,
                            callback,
                        };
                        encrypt_aegis(
                            key,
                            &original_name,
                            &mut reader,
                            writer,
                            NAMED_VERSION,
                            None,
                        )
                    } else {
                        encrypt_aegis(
                            key,
                            &original_name,
                            &mut reader,
                            writer,
                            NAMED_VERSION,
                            None,
                        )
                    };
                    result?;
                    check_progress(callback)
                })
            })
        }
        Direction::Decrypt => match legacy_version(input)? {
            Some(LEGACY_VERSION) => {
                let output = output_path(input, options.output_dir.as_deref(), Direction::Decrypt)?;
                finish_job(input, output, options, |destination| {
                    let input_file = File::open(input)?;
                    let mut reader = BufReader::new(input_file);
                    write_transformed(destination, options.overwrite, |writer| {
                        let result = if let Some(callback) = callback {
                            let mut reader = ProgressReader {
                                inner: reader,
                                callback,
                            };
                            decrypt_stream(key, &mut reader, writer)
                        } else {
                            decrypt_stream(key, &mut reader, writer)
                        };
                        result?;
                        check_progress(callback)
                    })
                })
            }
            Some(AEGIS_VERSION) => {
                let output = output_path(input, options.output_dir.as_deref(), Direction::Decrypt)?;
                finish_job(input, output, options, |destination| {
                    let input_file = File::open(input)?;
                    let mut reader = BufReader::new(input_file);
                    write_transformed(destination, options.overwrite, |writer| {
                        let result = if let Some(callback) = callback {
                            let mut reader = ProgressReader {
                                inner: reader,
                                callback,
                            };
                            decrypt_aegis(key, &mut reader, writer)
                        } else {
                            decrypt_aegis(key, &mut reader, writer)
                        };
                        result?;
                        check_progress(callback)
                    })
                })
            }
            Some(NAMED_VERSION | BUNDLE_VERSION | COMPRESSED_BUNDLE_VERSION) => {
                decrypt_named(key, input, options, callback)
            }
            Some(version) => Err(CryptoError::UnsupportedVersion(version)),
            None => Err(CryptoError::NotEncrypted),
        },
    }
}

fn check_progress(callback: Option<&ProgressCallback<'_>>) -> Result<(), CryptoError> {
    if let Some(callback) = callback {
        callback(0)?;
    }
    Ok(())
}

fn finish_job(
    input: &Path,
    output: PathBuf,
    options: &JobOptions,
    write: impl FnOnce(&Path) -> Result<(), CryptoError>,
) -> Result<PathBuf, CryptoError> {
    ensure_distinct(input, &output, options.key_file.as_deref())?;
    match fs::symlink_metadata(&output) {
        Ok(_) if !options.overwrite => {
            return Err(CryptoError::OutputExists(output.display().to_string()))
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(CryptoError::NotAFile(format!(
                "existing output is not a regular file: {}",
                output.display()
            )))
        }
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err.into()),
        _ => {}
    }
    write(&output)?;
    if options.remove_original {
        if let Err(source) = fs::remove_file(input) {
            return Err(CryptoError::OriginalRemains {
                output: output.display().to_string(),
                source,
            });
        }
    }
    Ok(output)
}

fn decrypt_named(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    let input_file = File::open(input)?;
    let reader = BufReader::new(input_file);
    let mut reader: Box<dyn Read + '_> = if let Some(callback) = callback {
        Box::new(ProgressReader {
            inner: reader,
            callback,
        })
    } else {
        Box::new(reader)
    };
    let opened = open_named(&mut reader, key)?;
    let output = place(
        input,
        options.output_dir.as_deref(),
        std::ffi::OsStr::new(&opened.name),
    )?;
    if opened.version != NAMED_VERSION {
        let root = options
            .output_dir
            .as_deref()
            .or_else(|| input.parent())
            .ok_or(CryptoError::BadEncryptedName)?;
        ensure_no_linked_parent(root, &output)?;
    }
    finish_job(input, output, options, |destination| {
        write_transformed(destination, options.overwrite, |writer| {
            decrypt_named_body(&mut reader, writer, &opened)?;
            check_progress(callback)
        })
    })
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut generated = Aes256Gcm::generate_key(OsRng);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(generated.as_slice());
    generated.as_mut_slice().zeroize();
    key
}

fn wrap_key(master: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"FileEncrypt-v2"), master);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"aegis256-file-wrap", key.as_mut())
        .map_err(|_| CryptoError::EncryptFailed)?;
    Ok(key)
}

fn chunk_nonce(
    prefix: &[u8; STREAM_PREFIX_LEN],
    index: u64,
    last: bool,
) -> Result<[u8; 32], CryptoError> {
    if index & (1 << 63) != 0 {
        return Err(CryptoError::EncryptFailed);
    }
    let mut nonce = [0u8; 32];
    nonce[..STREAM_PREFIX_LEN].copy_from_slice(prefix);
    let marked = if last { index | (1 << 63) } else { index };
    nonce[STREAM_PREFIX_LEN..].copy_from_slice(&marked.to_be_bytes());
    Ok(nonce)
}

fn seal(key: &[u8; 32], nonce: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    let tag = Aegis256::<AEGIS_TAG_LEN>::new(key, nonce).encrypt_in_place(&mut buf, aad);
    buf.extend_from_slice(&tag);
    buf
}

fn open_sealed(
    key: &[u8; 32],
    nonce: &[u8; 32],
    aad: &[u8],
    framed: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    if framed.len() < AEGIS_TAG_LEN {
        return Err(CryptoError::Truncated);
    }
    let split = framed.len() - AEGIS_TAG_LEN;
    let (body, tag_bytes) = framed.split_at_mut(split);
    let mut tag = [0u8; AEGIS_TAG_LEN];
    tag.copy_from_slice(tag_bytes);
    Aegis256::<AEGIS_TAG_LEN>::new(key, nonce)
        .decrypt_in_place(body, &tag, aad)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    framed.truncate(split);
    Ok(())
}

fn encrypt_aegis(
    master: &[u8; 32],
    original_name: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    version: u8,
    original_size: Option<u64>,
) -> Result<(), CryptoError> {
    let wrap_key = wrap_key(master)?;
    let file_key = random_key();
    let wrap_nonce = random_key();
    let prefix_bytes = random_key();
    let mut prefix = [0u8; STREAM_PREFIX_LEN];
    prefix.copy_from_slice(&prefix_bytes[..STREAM_PREFIX_LEN]);
    let name_nonce = random_key();

    let mut header = [0u8; AEGIS_HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = version;
    header[5..9].copy_from_slice(&CHUNK_SIZE.to_be_bytes());
    header[9..41].copy_from_slice(wrap_nonce.as_slice());
    let mut wrapped = file_key.to_vec();
    let tag = Aegis256::<AEGIS_TAG_LEN>::new(&wrap_key, &wrap_nonce)
        .encrypt_in_place(&mut wrapped, &header[..9]);
    header[41..73].copy_from_slice(&wrapped);
    header[73..105].copy_from_slice(&tag);
    header[105..AEGIS_HEADER_LEN].copy_from_slice(&prefix);
    wrapped.zeroize();

    let mut slot = pack_name(original_name, original_size)?;
    let sealed_name = seal(&file_key, &name_nonce, &header, slot.as_slice());
    slot.zeroize();

    let mut preamble = Vec::with_capacity(AEGIS_HEADER_LEN + 32 + sealed_name.len());
    preamble.extend_from_slice(&header);
    preamble.extend_from_slice(name_nonce.as_slice());
    preamble.extend_from_slice(&sealed_name);
    writer.write_all(&preamble)?;

    let mut index = 0u64;
    let mut current = SecretBytes(read_up_to(reader, CHUNK_SIZE as usize)?);
    loop {
        let next = SecretBytes(read_up_to(reader, CHUNK_SIZE as usize)?);
        let last = next.0.is_empty();
        let nonce = chunk_nonce(&prefix, index, last)?;
        let sealed = seal(&file_key, &nonce, &preamble, &current.0);
        writer.write_all(&sealed)?;
        index = index.checked_add(1).ok_or(CryptoError::EncryptFailed)?;
        if last {
            break;
        }
        current = next;
    }
    Ok(())
}

struct OpenedNamed {
    file_key: Zeroizing<[u8; 32]>,
    prefix: [u8; STREAM_PREFIX_LEN],
    chunk_size: usize,
    body_aad: Vec<u8>,
    name: String,
    original_size: Option<u64>,
    version: u8,
}

fn open_named(reader: &mut dyn Read, master: &[u8; 32]) -> Result<OpenedNamed, CryptoError> {
    let mut header = [0u8; AEGIS_HEADER_LEN];
    reader.read_exact(&mut header).map_err(short_read)?;
    if &header[0..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    if !matches!(
        header[4],
        NAMED_VERSION | BUNDLE_VERSION | COMPRESSED_BUNDLE_VERSION
    ) {
        return Err(CryptoError::UnsupportedVersion(header[4]));
    }
    let chunk_size = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::BadChunkSize);
    }
    let file_key = unwrap_file_key(master, &header)?;
    let mut prefix = [0u8; STREAM_PREFIX_LEN];
    prefix.copy_from_slice(&header[105..AEGIS_HEADER_LEN]);

    let mut name_nonce = [0u8; 32];
    reader.read_exact(&mut name_nonce).map_err(short_read)?;
    let mut sealed_name = read_exact_vec(reader, NAME_FRAME_LEN)?;
    let mut body_aad = Vec::with_capacity(AEGIS_HEADER_LEN + 32 + sealed_name.len());
    body_aad.extend_from_slice(&header);
    body_aad.extend_from_slice(&name_nonce);
    body_aad.extend_from_slice(&sealed_name);
    open_sealed(&file_key, &name_nonce, &header, &mut sealed_name)?;
    let (name, original_size) = unpack_name(&sealed_name, header[4])?;
    sealed_name.zeroize();

    Ok(OpenedNamed {
        file_key,
        prefix,
        chunk_size: chunk_size as usize,
        body_aad,
        name,
        original_size,
        version: header[4],
    })
}

fn unwrap_file_key(
    master: &[u8; 32],
    header: &[u8; AEGIS_HEADER_LEN],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let wrap_key = wrap_key(master)?;
    let mut wrap_nonce = [0u8; 32];
    wrap_nonce.copy_from_slice(&header[9..41]);
    let mut wrapped = header[41..105].to_vec();
    open_sealed(&wrap_key, &wrap_nonce, &header[..9], &mut wrapped)?;
    if wrapped.len() != 32 {
        wrapped.zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }
    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&wrapped);
    wrapped.zeroize();
    Ok(file_key)
}

fn pack_name(
    name: &str,
    original_size: Option<u64>,
) -> Result<Zeroizing<[u8; NAME_SLOT]>, CryptoError> {
    let bytes = name.as_bytes();
    let trailing = if original_size.is_some() { 8 } else { 0 };
    if bytes.is_empty() || bytes.len() > NAME_SLOT - 2 - trailing {
        return Err(CryptoError::NotAFile(format!(
            "cannot encrypt this file name: {name}"
        )));
    }
    let mut slot = Zeroizing::new([0u8; NAME_SLOT]);
    let len = u16::try_from(bytes.len()).map_err(|_| CryptoError::EncryptFailed)?;
    slot[0..2].copy_from_slice(&len.to_be_bytes());
    slot[2..2 + bytes.len()].copy_from_slice(bytes);
    if let Some(size) = original_size {
        slot[2 + bytes.len()..2 + bytes.len() + 8].copy_from_slice(&size.to_be_bytes());
    }
    Ok(slot)
}

fn unpack_name(slot: &[u8], version: u8) -> Result<(String, Option<u64>), CryptoError> {
    if slot.len() != NAME_SLOT {
        return Err(CryptoError::AuthenticationFailed);
    }
    let len = u16::from_be_bytes([slot[0], slot[1]]) as usize;
    let trailing = if version == COMPRESSED_BUNDLE_VERSION {
        8
    } else {
        0
    };
    if len > NAME_SLOT - 2 - trailing {
        return Err(CryptoError::AuthenticationFailed);
    }
    if slot[2 + len + trailing..].iter().any(|byte| *byte != 0) {
        return Err(CryptoError::AuthenticationFailed);
    }
    let name = std::str::from_utf8(&slot[2..2 + len]).map_err(|_| CryptoError::BadEncryptedName)?;
    if version == NAMED_VERSION {
        validate_file_name(name)?;
    } else {
        validate_relative_name(name)?;
    }
    let size = if trailing == 8 {
        Some(u64::from_be_bytes(
            slot[2 + len..2 + len + 8].try_into().unwrap(),
        ))
    } else {
        None
    };
    Ok((name.to_string(), size))
}

pub(crate) fn validate_relative_name(name: &str) -> Result<(), CryptoError> {
    if name.is_empty()
        || name.len() > NAME_SLOT - 10
        || name.starts_with('/')
        || name.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with([' ', '.'])
                || part.chars().any(|ch| matches!(ch, '\\' | '\0' | ':'))
        })
    {
        return Err(CryptoError::BadEncryptedName);
    }
    Ok(())
}

fn ensure_no_linked_parent(root: &Path, output: &Path) -> Result<(), CryptoError> {
    let relative = output
        .strip_prefix(root)
        .map_err(|_| CryptoError::BadEncryptedName)?;
    let mut parent = root.to_path_buf();
    for part in relative
        .components()
        .take(relative.components().count().saturating_sub(1))
    {
        parent.push(part);
        match fs::symlink_metadata(&parent) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err(CryptoError::NotAFile(format!(
                    "unsafe output folder: {}",
                    parent.display()
                )))
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

struct BoundedWriter<'a> {
    inner: &'a mut dyn Write,
    remaining: u64,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed file exceeds its stored size",
            ));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn decrypt_named_body(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    opened: &OpenedNamed,
) -> Result<(), CryptoError> {
    if opened.version == COMPRESSED_BUNDLE_VERSION {
        let mut bounded = BoundedWriter {
            inner: writer,
            remaining: opened
                .original_size
                .ok_or(CryptoError::AuthenticationFailed)?,
        };
        let mut decoder = flate2::write::ZlibDecoder::new(&mut bounded);
        decrypt_chunks(
            reader,
            &mut decoder,
            &opened.file_key,
            &opened.prefix,
            opened.chunk_size,
            &opened.body_aad,
        )?;
        decoder.finish()?;
        if bounded.remaining != 0 {
            return Err(CryptoError::Truncated);
        }
        Ok(())
    } else {
        decrypt_chunks(
            reader,
            writer,
            &opened.file_key,
            &opened.prefix,
            opened.chunk_size,
            &opened.body_aad,
        )
    }
}

fn validate_file_name(name: &str) -> Result<(), CryptoError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.chars().any(|ch| matches!(ch, '/' | '\\' | '\0' | ':'))
    {
        return Err(CryptoError::BadEncryptedName);
    }
    Ok(())
}

fn short_read(err: io::Error) -> CryptoError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        CryptoError::Truncated
    } else {
        CryptoError::Io(err)
    }
}

fn read_exact_vec(reader: &mut dyn Read, len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(short_read)?;
    Ok(buf)
}

fn decrypt_aegis(
    master: &[u8; 32],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    let mut header = [0u8; AEGIS_HEADER_LEN];
    reader.read_exact(&mut header).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::Truncated
        } else {
            CryptoError::Io(err)
        }
    })?;
    if &header[0..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    if header[4] != AEGIS_VERSION {
        return Err(CryptoError::UnsupportedVersion(header[4]));
    }
    let chunk_size = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::BadChunkSize);
    }

    let file_key = unwrap_file_key(master, &header)?;
    let mut prefix = [0u8; STREAM_PREFIX_LEN];
    prefix.copy_from_slice(&header[105..AEGIS_HEADER_LEN]);
    decrypt_chunks(
        reader,
        writer,
        &file_key,
        &prefix,
        chunk_size as usize,
        &header,
    )
}

fn decrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    file_key: &[u8; 32],
    prefix: &[u8; STREAM_PREFIX_LEN],
    chunk_size: usize,
    aad: &[u8],
) -> Result<(), CryptoError> {
    let frame = chunk_size + AEGIS_TAG_LEN;
    let mut index = 0u64;
    let mut current = SecretBytes(read_up_to(reader, frame)?);
    if current.0.is_empty() {
        return Err(CryptoError::Truncated);
    }
    loop {
        let next = SecretBytes(read_up_to(reader, frame)?);
        let last = next.0.is_empty();
        if !last && current.0.len() != frame {
            return Err(CryptoError::Truncated);
        }
        let nonce = chunk_nonce(prefix, index, last)?;
        open_sealed(file_key, &nonce, aad, &mut current.0)?;
        writer.write_all(&current.0)?;
        index = index.checked_add(1).ok_or(CryptoError::EncryptFailed)?;
        if last {
            break;
        }
        current = next;
    }
    Ok(())
}

fn legacy_version(path: &Path) -> Result<Option<u8>, CryptoError> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 5];
    let read = file.read(&mut header)?;
    if read < header.len() || &header[..4] != MAGIC {
        return Ok(None);
    }
    Ok(Some(header[4]))
}

#[cfg(test)]
fn encrypt_stream(
    key: &[u8; 32],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    let nonce_prefix = random_nonce_prefix();
    let header = file_header(CHUNK_SIZE, &nonce_prefix);
    writer.write_all(&header)?;

    let nonce = GenericArray::from_slice(&nonce_prefix);
    let mut encryptor = EncryptorBE32::<Aes256Gcm>::new(Key::<Aes256Gcm>::from_slice(key), nonce);
    let aad = &header[..AAD_LEN];
    let chunk = CHUNK_SIZE as usize;

    let mut current = SecretBytes(read_up_to(reader, chunk)?);
    loop {
        let next = SecretBytes(read_up_to(reader, chunk)?);
        if next.0.is_empty() {
            encryptor
                .encrypt_last_in_place(aad, &mut current.0)
                .map_err(|_| CryptoError::EncryptFailed)?;
            writer.write_all(&current.0)?;
            break;
        }
        encryptor
            .encrypt_next_in_place(aad, &mut current.0)
            .map_err(|_| CryptoError::EncryptFailed)?;
        writer.write_all(&current.0)?;
        current = next;
    }
    Ok(())
}

fn decrypt_stream(
    key: &[u8; 32],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    let header = read_header(reader)?;
    let nonce = GenericArray::from_slice(&header.nonce);
    let mut decryptor = DecryptorBE32::<Aes256Gcm>::new(Key::<Aes256Gcm>::from_slice(key), nonce);
    let frame = header.chunk_size + TAG_LEN;
    let aad = header.aad.as_slice();

    let mut current = SecretBytes(read_up_to(reader, frame)?);
    if current.0.is_empty() {
        return Err(CryptoError::Truncated);
    }
    loop {
        let next = SecretBytes(read_up_to(reader, frame)?);
        if next.0.is_empty() {
            if current.0.len() < TAG_LEN {
                return Err(CryptoError::Truncated);
            }
            decryptor
                .decrypt_last_in_place(aad, &mut current.0)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            writer.write_all(&current.0)?;
            break;
        }
        if current.0.len() != frame {
            return Err(CryptoError::Truncated);
        }
        decryptor
            .decrypt_next_in_place(aad, &mut current.0)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        writer.write_all(&current.0)?;
        current = next;
    }
    Ok(())
}

#[cfg(test)]
fn random_nonce_prefix() -> [u8; NONCE_PREFIX_LEN] {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    prefix.copy_from_slice(&nonce[..NONCE_PREFIX_LEN]);
    prefix
}

#[cfg(test)]
fn file_header(chunk_size: u32, nonce: &[u8; NONCE_PREFIX_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = LEGACY_VERSION;
    header[5..9].copy_from_slice(&chunk_size.to_be_bytes());
    header[9..16].copy_from_slice(nonce);
    header
}

fn read_header(reader: &mut dyn Read) -> Result<OpenedHeader, CryptoError> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::NotEncrypted
        } else {
            CryptoError::Io(err)
        }
    })?;
    if &header[0..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    if header[4] != LEGACY_VERSION {
        return Err(CryptoError::UnsupportedVersion(header[4]));
    }
    let chunk_size = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::BadChunkSize);
    }
    let mut aad = [0u8; AAD_LEN];
    aad.copy_from_slice(&header[..AAD_LEN]);
    let mut nonce = [0u8; NONCE_PREFIX_LEN];
    nonce.copy_from_slice(&header[AAD_LEN..]);
    Ok(OpenedHeader {
        aad,
        nonce,
        chunk_size: chunk_size as usize,
    })
}

fn read_up_to(reader: &mut dyn Read, max: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; max];
    let mut filled = 0;
    while filled < max {
        let read = match reader.read(&mut buf[filled..]) {
            Ok(read) => read,
            Err(err) => {
                buf.zeroize();
                return Err(err.into());
            }
        };
        match read {
            0 => break,
            n => filled += n,
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

pub(crate) fn write_transformed(
    output: &Path,
    overwrite: bool,
    produce: impl FnOnce(&mut dyn Write) -> Result<(), CryptoError>,
) -> Result<(), CryptoError> {
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let partial = sibling(
        output,
        &format!(".partial-{}", opaque_file_name().to_string_lossy()),
    )?;
    let _guard = DeleteOnDrop { path: &partial };
    {
        let file = create_private_file(&partial)?;
        let mut writer = BufWriter::new(file);
        produce(&mut writer)?;
        writer.flush()?;
        let file = writer.into_inner().map_err(|err| err.into_error())?;
        file.sync_all()?;
    }
    commit_partial(&partial, output, overwrite)?;
    Ok(())
}

fn commit_partial(partial: &Path, output: &Path, overwrite: bool) -> Result<(), CryptoError> {
    let existing = match fs::symlink_metadata(output) {
        Ok(metadata) => Some(metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    if let Some(metadata) = existing {
        if !overwrite {
            return Err(CryptoError::OutputExists(output.display().to_string()));
        }
        if !metadata.is_file() {
            return Err(CryptoError::NotAFile(format!(
                "existing output is not a regular file: {}",
                output.display()
            )));
        }
        let backup = sibling(
            output,
            &format!(".fileencrypt-bak-{}", opaque_file_name().to_string_lossy()),
        )?;
        fs::rename(output, &backup)?;
        if let Err(err) = fs::rename(partial, output) {
            let _ = fs::rename(&backup, output);
            return Err(err.into());
        }
        let _ = fs::remove_file(&backup);
        return Ok(());
    }
    if overwrite {
        fs::rename(partial, output)?;
    } else {
        // Creating the hard link fails if another process created the output after preflight.
        fs::hard_link(partial, output)?;
        fs::remove_file(partial)?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn output_path(
    input: &Path,
    output_dir: Option<&Path>,
    direction: Direction,
) -> Result<PathBuf, CryptoError> {
    let name = match direction {
        Direction::Encrypt => opaque_file_name(),
        Direction::Decrypt => decrypted_file_name(file_name(input)?)?,
    };
    place(input, output_dir, &name)
}

fn opaque_output_path(
    input: &Path,
    output_dir: Option<&Path>,
    overwrite: bool,
) -> Result<PathBuf, CryptoError> {
    for _ in 0..8 {
        let path = place(input, output_dir, &opaque_file_name())?;
        if overwrite || !path.exists() {
            return Ok(path);
        }
    }
    Err(CryptoError::EncryptFailed)
}

pub(crate) fn opaque_file_name() -> std::ffi::OsString {
    let bytes = random_key();
    let hex: String = bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut name = std::ffi::OsString::from(hex);
    name.push(".fenc");
    name
}

fn file_name_utf8(path: &Path) -> Result<String, CryptoError> {
    let name = file_name(path)?;
    name.to_str().map(str::to_string).ok_or_else(|| {
        CryptoError::NotAFile(format!("file name is not valid text: {}", path.display()))
    })
}

fn place(
    input: &Path,
    output_dir: Option<&Path>,
    name: &std::ffi::OsStr,
) -> Result<PathBuf, CryptoError> {
    match output_dir {
        Some(dir) if !dir.as_os_str().is_empty() => {
            if dir.exists() && !dir.is_dir() {
                return Err(CryptoError::NotAFile(format!(
                    "output folder is not a folder: {}",
                    dir.display()
                )));
            }
            Ok(dir.join(name))
        }
        _ => Ok(input.with_file_name(name)),
    }
}

fn decrypted_file_name(name: &std::ffi::OsStr) -> Result<std::ffi::OsString, CryptoError> {
    if let Some(text) = name.to_str() {
        if let Some(stripped) = text.strip_suffix(".fenc") {
            if !stripped.is_empty() {
                return Ok(std::ffi::OsString::from(stripped));
            }
        }
        return Ok(std::ffi::OsString::from(format!("{text}.dec")));
    }
    let mut raw = name.to_os_string();
    raw.push(".dec");
    Ok(raw)
}

fn file_name(path: &Path) -> Result<&std::ffi::OsStr, CryptoError> {
    path.file_name()
        .ok_or_else(|| CryptoError::NotAFile(path.display().to_string()))
}

pub(crate) fn ensure_distinct(
    input: &Path,
    output: &Path,
    key_file: Option<&Path>,
) -> Result<(), CryptoError> {
    if same_path(input, output) {
        return Err(CryptoError::SamePath);
    }
    if let Some(key_file) = key_file {
        if same_path(input, key_file) || same_path(output, key_file) {
            return Err(CryptoError::KeyFileConflict);
        }
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    normalize(left) == normalize(right)
}

fn normalize(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return parent.join(name);
        }
    }
    path.to_path_buf()
}

fn sibling(path: &Path, suffix: &str) -> Result<PathBuf, CryptoError> {
    let mut name = file_name(path)?.to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "fileencrypt-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn is_opaque_name(path: &Path) -> bool {
        let name = path.file_name().unwrap().to_string_lossy();
        name.len() == 32 + 5
            && name.ends_with(".fenc")
            && name.as_bytes()[..32]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit())
    }

    fn options(overwrite: bool, remove_original: bool) -> JobOptions {
        JobOptions {
            overwrite,
            remove_original,
            key_file: None,
            output_dir: None,
        }
    }

    fn roundtrip(data: &[u8]) {
        let dir = TempDir::new();
        let input = dir.path().join("payload.bin");
        fs::write(&input, data).unwrap();
        let key = test_key(3);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        assert!(is_opaque_name(&encrypted));
        assert_eq!(encrypted.parent(), Some(dir.path()));
        fs::remove_file(&input).unwrap();
        let decrypted = decrypt_file(&key, &encrypted, &options(false, false)).unwrap();
        assert_eq!(decrypted, input);
        assert_eq!(fs::read(decrypted).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty_small_and_binary() {
        roundtrip(b"");
        roundtrip(b"hello");
        let mixed: Vec<u8> = (0..=255).cycle().take(1000).collect();
        roundtrip(&mixed);
    }

    #[test]
    fn roundtrip_chunk_boundaries() {
        let chunk = CHUNK_SIZE as usize;
        roundtrip(&vec![7u8; chunk - 1]);
        roundtrip(&vec![8u8; chunk]);
        roundtrip(&vec![9u8; chunk + 1]);
        let mut multi = vec![4u8; chunk * 2];
        multi.extend_from_slice(b"tail");
        roundtrip(&multi);
    }

    #[test]
    fn rotation_streams_plaintext_without_publishing_a_partial_file() {
        let dir = TempDir::new();
        let source = dir.path().join("payload.txt");
        let body = vec![b'R'; 250_000];
        fs::write(&source, &body).unwrap();
        let old = test_key(16);
        let new = test_key(17);
        let encrypted = encrypt_file(&old, &source, &options(false, false)).unwrap();
        fs::remove_file(&source).unwrap();
        assert!(
            rotate_file_with_progress(&new, &old, &encrypted, &options(false, false), None)
                .is_err()
        );
        let rotated =
            rotate_file_with_progress(&old, &new, &encrypted, &options(false, false), None)
                .unwrap();
        assert!(encrypted.exists());
        assert!(verify_file(&old, &rotated, None).is_err());
        verify_file(&new, &rotated, None).unwrap();
        let restored = decrypt_file(&new, &rotated, &options(false, false)).unwrap();
        assert_eq!(fs::read(restored).unwrap(), body);
    }

    #[test]
    fn ciphertext_hides_a_plaintext_marker_and_changes_nonce() {
        let dir = TempDir::new();
        let input = dir.path().join("secret.txt");
        let marker = b"UNIQUE-PLAINTEXT-MARKER-9f3a-7c21";
        fs::write(&input, marker).unwrap();
        let key = test_key(9);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        let first = fs::read(&encrypted).unwrap();
        assert!(!first.windows(marker.len()).any(|window| window == marker));
        assert!(first.starts_with(b"FENC"));
        assert_eq!(first[4], NAMED_VERSION);
        assert!(!first
            .windows(b"secret.txt".len())
            .any(|window| window == b"secret.txt"));

        let again = encrypt_file(&key, &input, &options(true, false)).unwrap();
        let second = fs::read(&again).unwrap();
        assert_ne!(first, second);
        fs::remove_file(&input).unwrap();
        assert_eq!(
            fs::read(decrypt_file(&key, &again, &options(false, false)).unwrap()).unwrap(),
            marker
        );
    }

    #[test]
    fn wrong_key_tamper_and_truncation_fail_cleanly() {
        let dir = TempDir::new();
        let input = dir.path().join("notes.txt");
        fs::write(&input, b"keep this").unwrap();
        let key = test_key(1);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        fs::remove_file(&input).unwrap();

        let wrong = test_key(2);
        let err = decrypt_file(&wrong, &encrypted, &options(false, false)).unwrap_err();
        assert!(matches!(err, CryptoError::AuthenticationFailed));
        assert!(!input.exists());
        assert!(!dir.path().join("notes.txt.fenc.partial").exists());

        let mut bytes = fs::read(&encrypted).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x5a;
        fs::write(&encrypted, &bytes).unwrap();
        assert!(decrypt_file(&key, &encrypted, &options(false, false)).is_err());
        assert!(!dir.path().join("notes.txt.fenc.partial").exists());

        bytes.truncate(bytes.len() / 2);
        fs::write(&encrypted, &bytes).unwrap();
        assert!(decrypt_file(&key, &encrypted, &options(false, false)).is_err());
        assert!(!dir.path().join("notes.txt.partial").exists());
    }

    #[test]
    fn legacy_aes_gcm_files_still_decrypt() {
        let dir = TempDir::new();
        let input = dir.path().join("old.txt");
        let data = b"written by the first version";
        fs::write(&input, data).unwrap();
        let key = test_key(11);
        let encrypted = dir.path().join("old.txt.fenc");
        let mut reader = BufReader::new(File::open(&input).unwrap());
        write_transformed(&encrypted, false, |writer| {
            encrypt_stream(&key, &mut reader, writer)
        })
        .unwrap();
        assert!(fs::read(&encrypted).unwrap().starts_with(b"FENC"));
        fs::remove_file(&input).unwrap();
        let decrypted = decrypt_file(&key, &encrypted, &options(false, false)).unwrap();
        assert_eq!(fs::read(&decrypted).unwrap(), data);
        fs::remove_file(decrypted).unwrap();

        let mut bytes = fs::read(&encrypted).unwrap();
        bytes[4] = 9;
        fs::write(&encrypted, &bytes).unwrap();
        let err = decrypt_file(&key, &encrypted, &options(false, false)).unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedVersion(9)));
    }

    #[test]
    fn refuses_to_clobber_existing_output_or_the_key_file() {
        let dir = TempDir::new();
        let input = dir.path().join("report.pdf");
        fs::write(&input, b"pdf").unwrap();
        let key = test_key(4);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        let first = fs::read(&encrypted).unwrap();
        let again = encrypt_file(&key, &input, &options(false, false)).unwrap();
        assert_ne!(again, encrypted);
        assert_eq!(fs::read(&encrypted).unwrap(), first);

        let err = decrypt_file(&key, &encrypted, &options(false, false)).unwrap_err();
        assert!(matches!(err, CryptoError::OutputExists(_)));
        assert_eq!(fs::read(&input).unwrap(), b"pdf");

        let key_file = dir.path().join("vault.key");
        fs::write(&key_file, b"key").unwrap();
        let mut guarded = options(false, false);
        guarded.key_file = Some(key_file.clone());
        let err = encrypt_file(&key, &key_file, &guarded).unwrap_err();
        assert!(matches!(err, CryptoError::KeyFileConflict));
        assert_eq!(fs::read(&key_file).unwrap(), b"key");
    }

    #[test]
    fn overwrite_never_replaces_an_output_directory() {
        let dir = TempDir::new();
        let input = dir.path().join("report.txt");
        fs::write(&input, b"secret").unwrap();
        let key = test_key(4);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        fs::remove_file(&input).unwrap();
        fs::create_dir(&input).unwrap();
        let child = input.join("keep.txt");
        fs::write(&child, b"keep").unwrap();

        let err = decrypt_file(&key, &encrypted, &options(true, true)).unwrap_err();
        assert!(matches!(err, CryptoError::NotAFile(_)));
        assert_eq!(fs::read(&child).unwrap(), b"keep");
        assert!(encrypted.exists());
    }

    #[test]
    fn output_dir_collects_results_and_keeps_names_distinct() {
        let dir = TempDir::new();
        let out = dir.path().join("collected");
        let source_a = dir.path().join("a");
        let source_b = dir.path().join("b");
        fs::create_dir_all(&source_a).unwrap();
        fs::create_dir_all(&source_b).unwrap();
        let first = source_a.join("notes.txt");
        let second = source_b.join("notes.txt");
        fs::write(&first, b"one").unwrap();
        fs::write(&second, b"two").unwrap();
        let key = test_key(8);
        let mut job = options(false, false);
        job.output_dir = Some(out.clone());

        let encrypted = encrypt_file(&key, &first, &job).unwrap();
        let other = encrypt_file(&key, &second, &job).unwrap();
        assert!(is_opaque_name(&encrypted));
        assert!(is_opaque_name(&other));
        assert_ne!(encrypted.file_name(), other.file_name());
        assert!(!source_a.join("notes.txt.fenc").exists());

        let decrypted = decrypt_file(&key, &encrypted, &job).unwrap();
        assert_eq!(decrypted, out.join("notes.txt"));
        assert_eq!(fs::read(&decrypted).unwrap(), b"one");
        let err = decrypt_file(&key, &other, &job).unwrap_err();
        assert!(matches!(err, CryptoError::OutputExists(_)));
        assert_eq!(fs::read(&second).unwrap(), b"two");
    }

    #[test]
    fn remove_original_after_success_and_renamed_decrypt() {
        let dir = TempDir::new();
        let input = dir.path().join("archive.tar.gz");
        let data = b"tar-bytes";
        fs::write(&input, data).unwrap();
        let key = test_key(6);
        let encrypted = encrypt_file(&key, &input, &options(false, true)).unwrap();
        assert!(!input.exists());
        assert!(is_opaque_name(&encrypted));

        let renamed = dir.path().join("blob.bin");
        fs::rename(&encrypted, &renamed).unwrap();
        let decrypted = decrypt_file(&key, &renamed, &options(false, false)).unwrap();
        assert_eq!(decrypted.file_name().unwrap(), "archive.tar.gz");
        assert_eq!(fs::read(decrypted).unwrap(), data);
    }

    #[test]
    fn hidden_name_is_absent_from_the_file_and_paths_are_rejected() {
        let dir = TempDir::new();
        let input = dir.path().join("quarterly-report.txt");
        fs::write(&input, b"numbers").unwrap();
        let encrypted = encrypt_file(&test_key(12), &input, &options(false, false)).unwrap();
        let stored = fs::read(&encrypted).unwrap();
        assert!(!stored
            .windows(b"quarterly-report.txt".len())
            .any(|window| window == b"quarterly-report.txt"));
        fs::remove_file(&input).unwrap();
        let decrypted = decrypt_file(&test_key(12), &encrypted, &options(false, false)).unwrap();
        assert_eq!(decrypted.file_name().unwrap(), "quarterly-report.txt");

        let mut slot = [0u8; NAME_SLOT];
        let sneaky = b"../secret.txt";
        slot[0..2].copy_from_slice(&(sneaky.len() as u16).to_be_bytes());
        slot[2..2 + sneaky.len()].copy_from_slice(sneaky);
        assert!(matches!(
            unpack_name(&slot, NAMED_VERSION),
            Err(CryptoError::BadEncryptedName)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn remove_original_reports_when_the_file_stays_locked() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = TempDir::new();
        let input = dir.path().join("locked.txt");
        fs::write(&input, b"data").unwrap();
        let _lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&input)
            .unwrap();
        let err = encrypt_file(&test_key(5), &input, &options(false, true)).unwrap_err();
        match err {
            CryptoError::OriginalRemains { output, .. } => {
                assert!(Path::new(&output).is_file());
                assert!(output.ends_with(".fenc"));
                assert!(!output.to_lowercase().contains("locked"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(fs::read(&input).unwrap(), b"data");
    }

    #[test]
    fn cancelled_encryption_does_not_publish_partial_output() {
        let dir = TempDir::new();
        let input = dir.path().join("large.bin");
        fs::write(&input, vec![4u8; CHUNK_SIZE as usize * 3]).unwrap();
        let callback = |bytes: u64| -> io::Result<()> {
            if bytes > 0 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            } else {
                Ok(())
            }
        };
        assert!(
            encrypt_file_with_progress(&[1u8; 32], &input, &options(false, false), &callback)
                .is_err()
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(input.exists());
    }
}
