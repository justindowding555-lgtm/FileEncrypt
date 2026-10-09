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
use std::io::{self, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::source::Source;
use crate::{
    deletion::{self, Removal},
    publication::{self, PublishedFile},
};
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
const AUTH_BUNDLE_VERSION: u8 = 6;
const AUTH_COMPRESSED_BUNDLE_VERSION: u8 = 7;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BundleBinding {
    pub id: [u8; 16],
    pub count: u32,
}
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
    #[error("output published at {output}, but durability could not be confirmed; original retained: {source}")]
    PublicationUncertain { output: String, source: io::Error },
    #[error("{cause}; temporary cleanup failed at {path}: {source}")]
    CleanupFailed {
        cause: Box<CryptoError>,
        path: String,
        source: io::Error,
    },
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
    transform(Direction::Encrypt, key, input, options, None).map(|result| result.path)
}

#[cfg(test)]
pub fn decrypt_file(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
) -> Result<PathBuf, CryptoError> {
    transform(Direction::Decrypt, key, input, options, None).map(|result| result.path)
}

#[derive(Debug)]
pub struct TransformOutcome {
    pub path: PathBuf,
    pub removal: Removal,
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
) -> Result<TransformOutcome, CryptoError> {
    transform(Direction::Encrypt, key, input, options, Some(callback))
}

pub(crate) fn encrypt_bundle_reader(
    key: &[u8; 32],
    source: &Source,
    name: &str,
    compress: bool,
    binding: BundleBinding,
    writer: &mut dyn Write,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<(), CryptoError> {
    validate_relative_name(name)?;
    let count = Cell::new(0);
    let reader = CountingReader {
        inner: BufReader::new(source.file.try_clone()?),
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
        encrypt_aegis_bound(
            key,
            name,
            &mut compressed,
            writer,
            AUTH_COMPRESSED_BUNDLE_VERSION,
            Some(source.len()),
            Some(binding),
        )?;
    } else {
        encrypt_aegis_bound(
            key,
            name,
            &mut reader,
            writer,
            AUTH_BUNDLE_VERSION,
            None,
            Some(binding),
        )?;
    }
    if count.get() != source.len() {
        return Err(CryptoError::Truncated);
    }
    check_progress(callback)?;
    source.check()?;
    Ok(())
}

pub(crate) fn inspect_named_reader(
    key: &[u8; 32],
    reader: &mut dyn Read,
) -> Result<(String, Option<BundleBinding>), CryptoError> {
    let opened = open_named(reader, key)?;
    Ok((opened.name, opened.binding))
}

pub(crate) fn verify_named_reader(
    key: &[u8; 32],
    reader: &mut dyn Read,
) -> Result<String, CryptoError> {
    let opened = open_named(reader, key)?;
    decrypt_named_body(reader, &mut io::sink(), &opened)?;
    Ok(opened.name)
}

/// Inspect/decrypt the same opened source used by the in-memory viewer. These
/// functions never create an output path or publish partially authenticated data.
pub(crate) fn sandbox_name<R: Read + Seek>(
    key: &[u8; 32],
    input: &Path,
    reader: &mut R,
) -> Result<String, CryptoError> {
    let version = sandbox_version(reader)?;
    match version {
        NAMED_VERSION
        | BUNDLE_VERSION
        | COMPRESSED_BUNDLE_VERSION
        | AUTH_BUNDLE_VERSION
        | AUTH_COMPRESSED_BUNDLE_VERSION => Ok(open_named(reader, key)?.name),
        LEGACY_VERSION | AEGIS_VERSION => Ok(decrypted_file_name(file_name(input)?)?
            .to_string_lossy()
            .into_owned()),
        version => Err(CryptoError::UnsupportedVersion(version)),
    }
}

fn sandbox_version<R: Read + Seek>(reader: &mut R) -> Result<u8, CryptoError> {
    reader.rewind()?;
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).map_err(short_read)?;
    reader.rewind()?;
    if &header[..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    Ok(header[4])
}

pub(crate) fn sandbox_decrypt<R: Read + Seek>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    match sandbox_version(reader)? {
        NAMED_VERSION
        | BUNDLE_VERSION
        | COMPRESSED_BUNDLE_VERSION
        | AUTH_BUNDLE_VERSION
        | AUTH_COMPRESSED_BUNDLE_VERSION => {
            let opened = open_named(reader, key)?;
            decrypt_named_body(reader, writer, &opened)
        }
        AEGIS_VERSION => decrypt_aegis(key, reader, writer),
        LEGACY_VERSION => decrypt_stream(key, reader, writer),
        version => Err(CryptoError::UnsupportedVersion(version)),
    }
}

pub(crate) fn sandbox_decrypt_entry(
    key: &[u8; 32],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), CryptoError> {
    let opened = open_named(reader, key)?;
    decrypt_named_body(reader, writer, &opened)
}

pub(crate) fn decrypt_named_reader(
    key: &[u8; 32],
    input: &Path,
    reader: &mut dyn Read,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PublishedFile, CryptoError> {
    let opened = open_named(reader, key)?;
    let output = place(
        input,
        options.output_dir.as_deref(),
        std::ffi::OsStr::new(&opened.name),
    )?;
    let root = options
        .output_dir
        .as_deref()
        .or_else(|| input.parent())
        .ok_or(CryptoError::BadEncryptedName)?;
    ensure_no_linked_parent(root, &output)?;
    ensure_distinct(input, &output, options.key_file.as_deref())?;
    publication::write(&output, options.overwrite, callback, |writer| {
        decrypt_named_body(reader, writer, &opened)?;
        check_progress(callback)
    })
}

enum PipeMessage {
    Data(SecretBytes),
    Done,
    Failed(String),
}

struct PipeWriter(SyncSender<PipeMessage>, Receiver<SecretBytes>);

impl Write for PipeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut buffer = self
            .1
            .try_recv()
            .unwrap_or_else(|_| SecretBytes(Vec::with_capacity(bytes.len())));
        buffer.0.clear();
        buffer.0.extend_from_slice(bytes);
        self.0
            .send(PipeMessage::Data(buffer))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "rotation stopped"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    receiver: Receiver<PipeMessage>,
    recycled: SyncSender<SecretBytes>,
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
            let old = std::mem::replace(&mut self.pending, SecretBytes(Vec::new()));
            let _ = self.recycled.try_send(old);
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

#[cfg(test)]
pub fn rotate_file_with_progress(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    rotate_file_with_deletion(old_key, new_key, input, options, callback).map(|result| result.path)
}

pub fn rotate_file_with_deletion(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<TransformOutcome, CryptoError> {
    let version = legacy_version(input)?.ok_or(CryptoError::NotEncrypted)?;
    let output = opaque_output_path(input, options.output_dir.as_deref(), false)?;
    finish_job(input, output, options, callback, |destination, source| {
        let reader = BufReader::new(source.file.try_clone()?);
        let mut source: Box<dyn Read + Send + '_> = if let Some(callback) = callback {
            Box::new(ProgressReader {
                inner: reader,
                callback,
            })
        } else {
            Box::new(reader)
        };
        let opened = if matches!(
            version,
            NAMED_VERSION
                | BUNDLE_VERSION
                | COMPRESSED_BUNDLE_VERSION
                | AUTH_BUNDLE_VERSION
                | AUTH_COMPRESSED_BUNDLE_VERSION
        ) {
            Some(open_named(&mut source, old_key)?)
        } else {
            None
        };
        let binding = opened.as_ref().and_then(|opened| opened.binding);
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
        let result = publication::write(destination, false, callback, |writer| {
            std::thread::scope(|scope| {
                let (sender, receiver) = sync_channel(2);
                let (recycled, pool) = sync_channel(4);
                let reader = PipeReader {
                    receiver,
                    recycled,
                    pending: SecretBytes(Vec::new()),
                    offset: 0,
                    done: false,
                };
                let worker = scope.spawn(move || {
                    let result = {
                        let mut sink = PipeWriter(sender.clone(), pool);
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
                let encrypted = if matches!(
                    target_version,
                    COMPRESSED_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
                ) {
                    let mut compressed =
                        flate2::read::ZlibEncoder::new(&mut reader, flate2::Compression::default());
                    encrypt_aegis_bound(
                        new_key,
                        &name,
                        &mut compressed,
                        writer,
                        target_version,
                        size,
                        binding,
                    )
                } else {
                    encrypt_aegis_bound(
                        new_key,
                        &name,
                        &mut reader,
                        writer,
                        target_version,
                        None,
                        binding,
                    )
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

pub(crate) fn rotate_named_reader(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    source: &mut (dyn Read + Send),
    writer: &mut dyn Write,
    binding: Option<BundleBinding>,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<(), CryptoError> {
    let opened = open_named(source, old_key)?;
    let name = opened.name.clone();
    let size = opened.original_size;
    let compressed = matches!(
        opened.version,
        COMPRESSED_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    );
    let binding = binding.or(opened.binding);
    let version = if binding.is_some() {
        if compressed {
            AUTH_COMPRESSED_BUNDLE_VERSION
        } else {
            AUTH_BUNDLE_VERSION
        }
    } else {
        opened.version
    };
    std::thread::scope(|scope| {
        let (sender, receiver) = sync_channel(2);
        let (recycled, pool) = sync_channel(4);
        let mut reader = PipeReader {
            receiver,
            recycled,
            pending: SecretBytes(Vec::new()),
            offset: 0,
            done: false,
        };
        let worker = scope.spawn(move || {
            let mut sink = PipeWriter(sender.clone(), pool);
            let result = decrypt_named_body(source, &mut sink, &opened);
            let _ = sender.send(match &result {
                Ok(()) => PipeMessage::Done,
                Err(err) => PipeMessage::Failed(err.to_string()),
            });
            result
        });
        let encrypted = if compressed {
            let mut encoder =
                flate2::read::ZlibEncoder::new(&mut reader, flate2::Compression::default());
            encrypt_aegis_bound(new_key, &name, &mut encoder, writer, version, size, binding)
        } else {
            encrypt_aegis_bound(new_key, &name, &mut reader, writer, version, None, binding)
        };
        drop(reader);
        worker.join().map_err(|_| CryptoError::EncryptFailed)??;
        encrypted?;
        check_progress(callback)
    })
}

pub fn decrypt_file_with_progress(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: &ProgressCallback<'_>,
) -> Result<TransformOutcome, CryptoError> {
    transform(Direction::Decrypt, key, input, options, Some(callback))
}

pub fn inspect_output_name(
    key: &[u8; 32],
    input: &Path,
) -> Result<std::ffi::OsString, CryptoError> {
    match legacy_version(input)? {
        Some(
            NAMED_VERSION
            | BUNDLE_VERSION
            | COMPRESSED_BUNDLE_VERSION
            | AUTH_BUNDLE_VERSION
            | AUTH_COMPRESSED_BUNDLE_VERSION,
        ) => {
            let mut reader = BufReader::new(File::open(input)?);
            Ok(open_named(&mut reader, key)?.name.into())
        }
        Some(LEGACY_VERSION | AEGIS_VERSION) => decrypted_file_name(file_name(input)?),
        Some(version) => Err(CryptoError::UnsupportedVersion(version)),
        None => Err(CryptoError::NotEncrypted),
    }
}

pub fn verify_file(
    key: &[u8; 32],
    input: &Path,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<String, CryptoError> {
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

pub(crate) fn verify_reader(
    key: &[u8; 32],
    input: &Path,
    reader: &mut dyn Read,
    sink: &mut dyn Write,
) -> Result<String, CryptoError> {
    // Select the format from the same stream being verified, then replay the
    // prefix to the decoder. Return a name only after the entire body passes.
    let mut prefix = [0u8; 5];
    reader.read_exact(&mut prefix).map_err(short_read)?;
    if &prefix[..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    let mut reader = io::Cursor::new(prefix).chain(reader);
    match prefix[4] {
        NAMED_VERSION
        | BUNDLE_VERSION
        | COMPRESSED_BUNDLE_VERSION
        | AUTH_BUNDLE_VERSION
        | AUTH_COMPRESSED_BUNDLE_VERSION => verify_named_reader(key, &mut reader),
        AEGIS_VERSION | LEGACY_VERSION => {
            if prefix[4] == AEGIS_VERSION {
                decrypt_aegis(key, &mut reader, sink)?;
            } else {
                decrypt_stream(key, &mut reader, sink)?;
            }
            Ok(decrypted_file_name(file_name(input)?)?
                .to_string_lossy()
                .into_owned())
        }
        version => Err(CryptoError::UnsupportedVersion(version)),
    }
}

pub(crate) fn atomic_write(destination: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    write_transformed(destination, true, |writer| {
        writer.write_all(bytes)?;
        Ok(())
    })
}

fn transform(
    direction: Direction,
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<TransformOutcome, CryptoError> {
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
            finish_job(input, output, options, callback, |destination, source| {
                let input_file = source.file.try_clone()?;
                let mut reader = BufReader::new(input_file);
                publication::write(destination, options.overwrite, callback, |writer| {
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
                finish_job(input, output, options, callback, |destination, source| {
                    let input_file = source.file.try_clone()?;
                    let mut reader = BufReader::new(input_file);
                    publication::write(destination, options.overwrite, callback, |writer| {
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
                finish_job(input, output, options, callback, |destination, source| {
                    let input_file = source.file.try_clone()?;
                    let mut reader = BufReader::new(input_file);
                    publication::write(destination, options.overwrite, callback, |writer| {
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
            Some(
                NAMED_VERSION
                | BUNDLE_VERSION
                | COMPRESSED_BUNDLE_VERSION
                | AUTH_BUNDLE_VERSION
                | AUTH_COMPRESSED_BUNDLE_VERSION,
            ) => decrypt_named(key, input, options, callback),
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
    callback: Option<&ProgressCallback<'_>>,
    write: impl FnOnce(&Path, &Source) -> Result<PublishedFile, CryptoError>,
) -> Result<TransformOutcome, CryptoError> {
    let source = Source::open(input, options.remove_original)?;
    finish_opened_job(input, output, options, source, callback, write)
}

fn finish_opened_job(
    input: &Path,
    output: PathBuf,
    options: &JobOptions,
    source: Source,
    callback: Option<&ProgressCallback<'_>>,
    write: impl FnOnce(&Path, &Source) -> Result<PublishedFile, CryptoError>,
) -> Result<TransformOutcome, CryptoError> {
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
    source.check()?;
    let published = write(&output, &source)?;
    let removal = if options.remove_original {
        deletion::remove(source, std::slice::from_ref(&published), callback)
    } else {
        Removal::not_requested(input)
    };
    Ok(TransformOutcome {
        path: output,
        removal,
    })
}

fn decrypt_named(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<TransformOutcome, CryptoError> {
    let source = Source::open(input, options.remove_original)?;
    let reader = BufReader::new(source.file.try_clone()?);
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
    finish_opened_job(
        input,
        output,
        options,
        source,
        callback,
        move |destination, _| {
            publication::write(destination, options.overwrite, callback, |writer| {
                decrypt_named_body(&mut reader, writer, &opened)?;
                check_progress(callback)
            })
        },
    )
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
    encrypt_aegis_bound(
        master,
        original_name,
        reader,
        writer,
        version,
        original_size,
        None,
    )
}

fn encrypt_aegis_bound(
    master: &[u8; 32],
    original_name: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    version: u8,
    original_size: Option<u64>,
    binding: Option<BundleBinding>,
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

    let packed = pack_name(original_name, original_size)?;
    let mut slot = Zeroizing::new(packed.to_vec());
    if binding.is_some() {
        slot.resize(NAME_SLOT + 20, 0);
    }
    if let Some(binding) = binding {
        let pos = 2 + original_name.len() + if original_size.is_some() { 8 } else { 0 };
        if pos + 20 > slot.len() {
            return Err(CryptoError::BadEncryptedName);
        }
        slot[pos..pos + 16].copy_from_slice(&binding.id);
        slot[pos + 16..pos + 20].copy_from_slice(&binding.count.to_be_bytes());
    }
    let sealed_name = seal(&file_key, &name_nonce, &header, slot.as_slice());
    slot.zeroize();

    let mut preamble = Vec::with_capacity(AEGIS_HEADER_LEN + 32 + sealed_name.len());
    preamble.extend_from_slice(&header);
    preamble.extend_from_slice(name_nonce.as_slice());
    preamble.extend_from_slice(&sealed_name);
    writer.write_all(&preamble)?;

    let mut index = 0u64;
    let mut current = SecretBytes(Vec::with_capacity(CHUNK_SIZE as usize + AEGIS_TAG_LEN));
    let mut next = SecretBytes(Vec::with_capacity(CHUNK_SIZE as usize + AEGIS_TAG_LEN));
    fill_buffer(reader, &mut current.0, CHUNK_SIZE as usize)?;
    loop {
        fill_buffer(reader, &mut next.0, CHUNK_SIZE as usize)?;
        let last = next.0.is_empty();
        let nonce = chunk_nonce(&prefix, index, last)?;
        let tag = Aegis256::<AEGIS_TAG_LEN>::new(&file_key, &nonce)
            .encrypt_in_place(&mut current.0, &preamble);
        current.0.extend_from_slice(&tag);
        writer.write_all(&current.0)?;
        index = index.checked_add(1).ok_or(CryptoError::EncryptFailed)?;
        if last {
            break;
        }
        std::mem::swap(&mut current, &mut next);
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
    binding: Option<BundleBinding>,
}

fn open_named(reader: &mut dyn Read, master: &[u8; 32]) -> Result<OpenedNamed, CryptoError> {
    let mut header = [0u8; AEGIS_HEADER_LEN];
    reader.read_exact(&mut header).map_err(short_read)?;
    if &header[0..4] != MAGIC {
        return Err(CryptoError::NotEncrypted);
    }
    if !matches!(
        header[4],
        NAMED_VERSION
            | BUNDLE_VERSION
            | COMPRESSED_BUNDLE_VERSION
            | AUTH_BUNDLE_VERSION
            | AUTH_COMPRESSED_BUNDLE_VERSION
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
    let binding_bytes = if matches!(
        header[4],
        AUTH_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    ) {
        20
    } else {
        0
    };
    let mut sealed_name = read_exact_vec(reader, NAME_FRAME_LEN + binding_bytes)?;
    let mut body_aad = Vec::with_capacity(AEGIS_HEADER_LEN + 32 + sealed_name.len());
    body_aad.extend_from_slice(&header);
    body_aad.extend_from_slice(&name_nonce);
    body_aad.extend_from_slice(&sealed_name);
    open_sealed(&file_key, &name_nonce, &header, &mut sealed_name)?;
    let (name, original_size) = unpack_name(&sealed_name, header[4])?;
    let binding = if matches!(
        header[4],
        AUTH_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    ) {
        let pos = 2 + name.len() + if original_size.is_some() { 8 } else { 0 };
        Some(BundleBinding {
            id: sealed_name[pos..pos + 16].try_into().unwrap(),
            count: u32::from_be_bytes(sealed_name[pos + 16..pos + 20].try_into().unwrap()),
        })
    } else {
        None
    };
    sealed_name.zeroize();

    Ok(OpenedNamed {
        file_key,
        prefix,
        chunk_size: chunk_size as usize,
        body_aad,
        name,
        original_size,
        version: header[4],
        binding,
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
    let expected_slot = NAME_SLOT
        + if matches!(
            version,
            AUTH_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
        ) {
            20
        } else {
            0
        };
    if slot.len() != expected_slot {
        return Err(CryptoError::AuthenticationFailed);
    }
    let len = u16::from_be_bytes([slot[0], slot[1]]) as usize;
    let compressed = matches!(
        version,
        COMPRESSED_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    );
    let binding_bytes = if matches!(
        version,
        AUTH_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    ) {
        20
    } else {
        0
    };
    let trailing = if compressed { 8 } else { 0 };
    if len > expected_slot - 2 - trailing - binding_bytes {
        return Err(CryptoError::AuthenticationFailed);
    }
    if slot[2 + len + trailing + binding_bytes..]
        .iter()
        .any(|byte| *byte != 0)
    {
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
    if matches!(
        opened.version,
        COMPRESSED_BUNDLE_VERSION | AUTH_COMPRESSED_BUNDLE_VERSION
    ) {
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
    let mut current = SecretBytes(Vec::with_capacity(frame));
    let mut next = SecretBytes(Vec::with_capacity(frame));
    fill_buffer(reader, &mut current.0, frame)?;
    if current.0.is_empty() {
        return Err(CryptoError::Truncated);
    }
    loop {
        fill_buffer(reader, &mut next.0, frame)?;
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
        std::mem::swap(&mut current, &mut next);
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

fn fill_buffer(reader: &mut dyn Read, buf: &mut Vec<u8>, max: usize) -> Result<(), CryptoError> {
    buf.as_mut_slice().zeroize();
    buf.resize(max, 0);
    let mut filled = 0;
    while filled < max {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) => {
                buf.as_mut_slice().zeroize();
                return Err(err.into());
            }
        }
    }
    buf.truncate(filled);
    Ok(())
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
    publication::write(output, overwrite, None, produce).map(|_| ())
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

    #[test]
    fn save_publishes_complete_bytes_and_cleans_up_temporary_file() {
        let dir = TempDir::new();
        let output = dir.path().join("backup-\u{00e9}-\u{937}.key");
        write_transformed(&output, false, |writer| {
            writer.write_all(b"test key backup bytes")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"test key backup bytes");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn publication_preserves_a_destination_created_after_preflight() {
        let dir = TempDir::new();
        let partial = dir.path().join("backup.partial");
        let output = dir.path().join("backup.key");
        fs::write(&partial, b"new bytes").unwrap();
        assert!(!output.exists());
        fs::write(&output, b"keep existing bytes").unwrap();

        // Call the publication primitive directly to exercise its OS-level protection.
        let handle = crate::file_guard::open_read(&partial, true).unwrap();
        let err = crate::file_guard::rename(&handle, &partial, &output, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&output).unwrap(), b"keep existing bytes");
        assert_eq!(fs::read(&partial).unwrap(), b"new bytes");
    }

    #[test]
    fn save_preserves_existing_output_and_cleans_up_temporary_file() {
        let dir = TempDir::new();
        let output = dir.path().join("backup.key");
        let err = write_transformed(&output, false, |writer| {
            writer.write_all(b"new bytes")?;
            fs::write(&output, b"keep existing bytes")?;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, CryptoError::OutputExists(_)));
        assert_eq!(fs::read(&output).unwrap(), b"keep existing bytes");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
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
    fn verification_returns_names_only_after_authentication_without_creating_plaintext() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = TempDir::new();
        let name = "private-\u{e9}-\u{937}.txt";
        let input = dir.path().join(name);
        fs::write(&input, vec![7; CHUNK_SIZE as usize * 2 + 1]).unwrap();
        let key = test_key(1);
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        fs::remove_file(&input).unwrap();
        let bytes = AtomicU64::new(0);
        assert_eq!(
            verify_file(
                &key,
                &encrypted,
                Some(&|count| {
                    bytes.fetch_add(count, Ordering::Relaxed);
                    Ok(())
                })
            )
            .unwrap(),
            name
        );
        assert_eq!(
            bytes.load(Ordering::Relaxed),
            fs::metadata(&encrypted).unwrap().len()
        );
        assert_eq!(verify_file(&key, &encrypted, None).unwrap(), name);
        assert!(verify_file(&test_key(2), &encrypted, None).is_err());
        let mut damaged = fs::read(&encrypted).unwrap();
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&encrypted, &damaged).unwrap();
        // Metadata alone still authenticates, but a failed body returns no name.
        assert_eq!(
            inspect_output_name(&key, &encrypted).unwrap(),
            std::ffi::OsString::from(name)
        );
        assert!(verify_file(&key, &encrypted, None).is_err());
        damaged.pop();
        fs::write(&encrypted, &damaged).unwrap();
        assert!(verify_file(&key, &encrypted, None).is_err());
        assert!(!input.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
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
        assert_eq!(verify_file(&key, &encrypted, None).unwrap(), "old.txt");
        let mut sandbox_reader = BufReader::new(File::open(&encrypted).unwrap());
        assert_eq!(
            sandbox_name(&key, &encrypted, &mut sandbox_reader).unwrap(),
            "old.txt"
        );
        let mut preview = Zeroizing::new(Vec::new());
        sandbox_decrypt(&key, &mut sandbox_reader, &mut *preview).unwrap();
        assert_eq!(preview.as_slice(), data);
        assert!(!input.exists());
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
        assert_eq!(input.exists(), !cfg!(windows));
        #[cfg(not(windows))]
        fs::remove_file(&input).unwrap();
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
        let result =
            encrypt_file_with_progress(&test_key(5), &input, &options(false, true), &|_| Ok(()))
                .unwrap();
        assert_eq!(
            result.removal.info.state,
            crate::deletion::DeletionState::Retained
        );
        assert!(result.removal.retry.is_some());
        assert!(result.path.is_file());
        assert!(is_opaque_name(&result.path));
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
    #[test]
    fn valid_maximum_filename_restores_and_overwrites_with_short_temporary_names() {
        let dir = TempDir::new();
        for length in [224, 255] {
            let name = format!("{}.txt", "a".repeat(length - 4));
            let input = dir.path().join(&name);
            fs::write(&input, b"new data").unwrap();
            let key = test_key(42);
            let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
            fs::write(&input, b"old data").unwrap();
            let output = decrypt_file(&key, &encrypted, &options(true, false)).unwrap();
            assert_eq!(fs::read(output).unwrap(), b"new data");
            let long_key = dir.path().join(format!("{}.key", "k".repeat(length - 4)));
            crate::key_file::write_key_file(&long_key, &key).unwrap();
            assert_eq!(*crate::key_file::read_key_file(&long_key).unwrap(), key);
        }
        assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fe-")));
    }
    #[test]
    fn a_source_changed_after_reading_is_never_deleted() {
        let dir = TempDir::new();
        let input = dir.path().join("source.txt");
        fs::write(&input, b"original bytes").unwrap();
        let read = AtomicU64::new(0);
        let attempted = std::sync::atomic::AtomicBool::new(false);
        let changed = std::sync::atomic::AtomicBool::new(false);
        let callback = |bytes: u64| -> io::Result<()> {
            let count = read.fetch_add(bytes, Ordering::Relaxed) + bytes;
            if bytes == 0 && count >= 14 && !attempted.swap(true, Ordering::Relaxed) {
                match fs::write(&input, b"modified bytes") {
                    Ok(()) => {
                        changed.store(true, Ordering::Relaxed);
                    }
                    Err(err) => return Err(err),
                }
            }
            Ok(())
        };
        let result =
            encrypt_file_with_progress(&test_key(42), &input, &options(false, true), &callback);
        assert!(result.is_err());
        assert!(input.exists());
        assert!(attempted.load(Ordering::Relaxed));
        if changed.load(Ordering::Relaxed) {
            assert_eq!(fs::read(&input).unwrap(), b"modified bytes");
        } else {
            assert_eq!(fs::read(&input).unwrap(), b"original bytes");
        }
    }

    #[test]
    fn encrypted_source_is_protected_before_reading_its_name() {
        let dir = TempDir::new();
        let input = dir.path().join("source.txt");
        let key = test_key(42);
        fs::write(&input, b"original data").unwrap();
        let encrypted = encrypt_file(&key, &input, &options(false, false)).unwrap();
        fs::write(&input, b"replacement data").unwrap();
        let replacement = encrypt_file(&key, &input, &options(false, false)).unwrap();
        let replacement_bytes = fs::read(replacement).unwrap();
        fs::remove_file(&input).unwrap();
        let attempted = std::sync::atomic::AtomicBool::new(false);
        let changed = std::sync::atomic::AtomicBool::new(false);
        let callback = |bytes: u64| -> io::Result<()> {
            if bytes > 0
                && !attempted.swap(true, Ordering::Relaxed)
                && fs::write(&encrypted, &replacement_bytes).is_ok()
            {
                changed.store(true, Ordering::Relaxed);
            }
            Ok(())
        };
        let result = decrypt_file_with_progress(&key, &encrypted, &options(false, true), &callback);
        assert!(attempted.load(Ordering::Relaxed));
        if changed.load(Ordering::Relaxed) {
            assert!(result.is_err());
            assert_eq!(fs::read(&encrypted).unwrap(), replacement_bytes);
        } else {
            assert!(result.is_ok());
            assert_eq!(encrypted.exists(), !cfg!(windows));
            assert_eq!(fs::read(&input).unwrap(), b"original data");
        }
    }
}
