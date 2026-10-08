//! Session-only receipts make deletion retry independent of encryption and key state.
#[cfg(windows)]
use crate::file_guard;
use crate::{crypto::ProgressCallback, publication::PublishedFile, source::Source};
use serde::Serialize;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::fs::File;
use std::io;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum DeletionState {
    NotRequested,
    Removed,
    Pending,
    Retained,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionInfo {
    pub state: DeletionState,
    pub source: String,
    pub reason: Option<String>,
    pub retry_id: Option<String>,
}

#[derive(Debug)]
pub struct Removal {
    pub info: DeletionInfo,
    pub retry: Option<RetryTicket>,
}
impl Removal {
    pub fn not_requested(path: &Path) -> Self {
        Self::new(path, DeletionState::NotRequested, None, None)
    }
    pub fn retained(path: &Path, reason: impl Into<String>) -> Self {
        Self::new(path, DeletionState::Retained, Some(reason.into()), None)
    }
    fn new(
        path: &Path,
        state: DeletionState,
        reason: Option<String>,
        retry: Option<RetryTicket>,
    ) -> Self {
        Self {
            info: DeletionInfo {
                state,
                source: path.display().to_string(),
                reason,
                retry_id: None,
            },
            retry,
        }
    }
}

#[derive(Debug)]
pub struct Receipt {
    pub path: PathBuf,
    #[cfg(windows)]
    identity: file_guard::Identity,
    #[cfg(windows)]
    size: u64,
    #[cfg(windows)]
    digest: [u8; 32],
}
fn check(callback: Option<&ProgressCallback<'_>>) -> io::Result<()> {
    if let Some(callback) = callback {
        callback(0)?;
    }
    Ok(())
}
#[cfg(windows)]
fn digest(file: &File, callback: Option<&ProgressCallback<'_>>) -> io::Result<[u8; 32]> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        check(callback)?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}
#[cfg(windows)]
impl Receipt {
    pub fn capture(
        file: &File,
        path: &Path,
        callback: Option<&ProgressCallback<'_>>,
    ) -> io::Result<Self> {
        let identity = file_guard::identity(file)?;
        let size = file.metadata()?.len();
        file_guard::check_path(file, path, identity, size)?;
        let digest = digest(file, callback)?;
        file_guard::check_path(file, path, identity, size)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            size,
            digest,
        })
    }
    pub fn validate(
        &self,
        source: &Source,
        callback: Option<&ProgressCallback<'_>>,
    ) -> io::Result<()> {
        source.check()?;
        file_guard::check_path(&source.file, &self.path, self.identity, self.size)?;
        if digest(&source.file, callback)? != self.digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} changed; original was preserved", self.path.display()),
            ));
        }
        source.check()
    }
}

#[derive(Clone, Debug)]
pub struct RetryTicket {
    pub source: Arc<Receipt>,
    #[cfg(windows)]
    outputs: Vec<Arc<Receipt>>,
    #[cfg(windows)]
    pub pending: bool,
}
#[cfg(windows)]
fn deletion_reason(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(32 | 33) => "Original retained because another program has it open. Close that program and retry deletion.".into(),
        Some(5) => "Original retained because deletion was denied. Check read-only attributes and permissions, then retry deletion.".into(),
        _ => format!("Original retained: {error}"),
    }
}

pub fn remove(
    source: Source,
    outputs: &[PublishedFile],
    callback: Option<&ProgressCallback<'_>>,
) -> Removal {
    let path = source.path.clone();
    if let Err(error) = check(callback) {
        return Removal::retained(&path, format!("Deletion cancelled: {error}"));
    }
    #[cfg(not(windows))]
    {
        let _ = outputs;
        Removal::retained(&path,
            "Safe automatic deletion requires Windows sharing protection; original retained on this platform.")
    }
    #[cfg(windows)]
    {
        let capture = (|| -> io::Result<_> {
            source.check()?;
            if outputs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no protected outputs; original retained",
                ));
            }
            let receipts = outputs
                .iter()
                .map(|output| output.receipt(callback))
                .collect::<io::Result<Vec<_>>>()?;
            let original = Arc::new(Receipt::capture(&source.file, &path, callback)?);
            source.check()?;
            for output in outputs {
                output.check()?;
            }
            check(callback)?;
            Ok((original, receipts))
        })();
        let (original, receipts) = match capture {
            Ok(receipts) => receipts,
            Err(error) => return Removal::retained(&path, error.to_string()),
        };
        let ticket = RetryTicket {
            source: original,
            outputs: receipts,
            pending: false,
        };
        let mut result = source.remove();
        // A reader can release its lock during encryption. Reacquire DELETE access,
        // then check both identity and bytes before acting on the reopened handle.
        for delay in [50, 100] {
            if !matches!(&result, Err(error) if matches!(error.raw_os_error(), Some(32 | 33))) {
                break;
            }
            if let Err(error) = check(callback) {
                return Removal::retained(&path, format!("Deletion cancelled: {error}"));
            }
            std::thread::sleep(Duration::from_millis(delay));
            result = (|| {
                let source = Source::open(&path, true)?;
                if source.can_delete() {
                    ticket.source.validate(&source, callback)?;
                }
                for output in outputs {
                    output.check()?;
                }
                check(callback)?;
                source.remove()
            })();
        }
        match result {
            Ok(DeletionState::Removed) => Removal::new(&path, DeletionState::Removed, None, None),
            Ok(_) => {
                let mut ticket = ticket;
                ticket.pending = true;
                Removal::new(
                    &path,
                    DeletionState::Pending,
                    Some(
                        "Deletion accepted; removal has not yet been confirmed. Close open readers and check again."
                            .into(),
                    ),
                    Some(ticket),
                )
            }
            Err(error) => Removal::new(
                &path,
                DeletionState::Retained,
                Some(deletion_reason(&error)),
                Some(ticket),
            ),
        }
    }
}

pub fn retry(ticket: RetryTicket, callback: Option<&ProgressCallback<'_>>) -> Removal {
    let path = ticket.source.path.clone();
    #[cfg(not(windows))]
    {
        let _ = callback;
        Removal::retained(
            &path,
            "Safe automatic deletion is unavailable on this platform.",
        )
    }
    #[cfg(windows)]
    {
        {
            match file_guard::namespace_present(&path) {
                Ok(false) => return Removal::new(&path, DeletionState::Removed, None, None),
                Err(error) => {
                    return Removal::new(
                        &path,
                        if ticket.pending {
                            DeletionState::Pending
                        } else {
                            DeletionState::Retained
                        },
                        Some(error.to_string()),
                        Some(ticket),
                    )
                }
                Ok(true) => (),
            }
        }
        let result = (|| -> io::Result<_> {
            check(callback)?;
            let mut protected = Vec::with_capacity(ticket.outputs.len());
            for receipt in &ticket.outputs {
                let output = Source::open(&receipt.path, false)?;
                receipt.validate(&output, callback)?;
                protected.push(output);
            }
            let source = Source::open(&path, true)?;
            ticket.source.validate(&source, callback)?;
            check(callback)?;
            source.remove()
        })();
        match result {
            Ok(DeletionState::Removed) => Removal::new(&path, DeletionState::Removed, None, None),
            Ok(_) => {
                let mut ticket = ticket;
                ticket.pending = true;
                Removal::new(
                    &path,
                    DeletionState::Pending,
                    Some("Deletion is waiting for open readers to close.".into()),
                    Some(ticket),
                )
            }
            Err(error) => {
                let state = if ticket.pending && matches!(error.raw_os_error(), Some(5 | 32 | 33)) {
                    DeletionState::Pending
                } else {
                    DeletionState::Retained
                };
                let reason = if state == DeletionState::Pending {
                    "Deletion accepted; Windows is waiting for open file handles to close.".into()
                } else {
                    deletion_reason(&error)
                };
                let retry = (error.kind() != io::ErrorKind::InvalidData).then_some(ticket);
                Removal::new(&path, state, Some(reason), retry)
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        crypto::{self, JobOptions},
        publication,
        test_support::TestDir,
    };
    use std::{fs, os::windows::fs::OpenOptionsExt};

    fn options() -> JobOptions {
        JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: None,
        }
    }
    fn locked_copy(dir: &TestDir) -> (PathBuf, PathBuf, RetryTicket) {
        let path = dir.0.join("original.txt");
        fs::write(&path, b"source bytes").unwrap();
        let reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .unwrap();
        let copied =
            crypto::encrypt_file_with_progress(&[8; 32], &path, &options(), &|_| Ok(())).unwrap();
        assert_eq!(copied.removal.info.state, DeletionState::Retained);
        assert_eq!(fs::read(&path).unwrap(), b"source bytes");
        drop(reader);
        (path, copied.path, copied.removal.retry.unwrap())
    }

    #[test]
    fn retry_removes_only_the_original_after_lock_release() {
        let dir = TestDir::new();
        let (original, output, ticket) = locked_copy(&dir);
        let removed = retry(ticket, None);
        assert_eq!(removed.info.state, DeletionState::Removed);
        assert!(removed.retry.is_none());
        assert!(!original.exists());
        assert!(output.exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn retry_keeps_saved_outputs_protected_during_validation_and_deletion() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let dir = TestDir::new();
        let (original, output, ticket) = locked_copy(&dir);
        let calls = AtomicUsize::new(0);
        let attacked = AtomicBool::new(false);
        let callback = |_| {
            // The first check precedes opening outputs. Subsequent callbacks run
            // while their protected handles remain alive through source removal.
            if calls.fetch_add(1, Ordering::Relaxed) > 0 {
                assert!(fs::write(&output, b"changed").is_err());
                assert!(fs::remove_file(&output).is_err());
                attacked.store(true, Ordering::Relaxed);
            }
            Ok(())
        };
        assert_eq!(
            retry(ticket, Some(&callback)).info.state,
            DeletionState::Removed
        );
        assert!(attacked.load(Ordering::Relaxed));
        assert!(!original.exists());
        crypto::verify_file(&[8; 32], &output, None).unwrap();
    }

    #[test]
    fn retry_rejects_changed_bytes_even_when_size_is_unchanged() {
        let dir = TestDir::new();
        let (original, _, ticket) = locked_copy(&dir);
        fs::write(&original, b"edited bytes").unwrap();
        let result = retry(ticket, None);
        assert_eq!(result.info.state, DeletionState::Retained);
        assert!(result.retry.is_none());
        assert_eq!(fs::read(original).unwrap(), b"edited bytes");
    }

    #[test]
    fn retry_rejects_a_replacement_with_identical_bytes() {
        let dir = TestDir::new();
        let (original, _, ticket) = locked_copy(&dir);
        fs::rename(&original, dir.0.join("old-original.txt")).unwrap();
        fs::write(&original, b"source bytes").unwrap();
        let result = retry(ticket, None);
        assert_eq!(result.info.state, DeletionState::Retained);
        assert!(original.exists());
        assert!(result.retry.is_none());
    }

    #[test]
    fn retry_preserves_original_if_saved_output_is_changed_or_missing() {
        for missing in [false, true] {
            let dir = TestDir::new();
            let (original, output, ticket) = locked_copy(&dir);
            if missing {
                fs::remove_file(&output).unwrap();
            } else {
                let mut bytes = fs::read(&output).unwrap();
                bytes[0] ^= 1;
                fs::write(output, bytes).unwrap();
            }
            let result = retry(ticket, None);
            assert_eq!(result.info.state, DeletionState::Retained);
            assert_eq!(fs::read(original).unwrap(), b"source bytes");
        }
    }

    #[test]
    fn initial_read_lock_is_retried_when_it_closes_before_deletion() {
        let dir = TestDir::new();
        let original = dir.0.join("original.txt");
        fs::write(&original, b"bytes").unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&original)
            .unwrap();
        let source = Source::open(&original, true).unwrap();
        assert!(!source.can_delete());
        let output = publication::write(&dir.0.join("saved"), false, None, |w| {
            w.write_all(b"bytes")?;
            Ok(())
        })
        .unwrap();
        drop(lock);
        assert_eq!(
            remove(source, &[output], None).info.state,
            DeletionState::Removed
        );
        assert!(!original.exists());
    }

    #[test]
    fn cancellation_after_publication_keeps_both_files() {
        let dir = TestDir::new();
        let original = dir.0.join("original.txt");
        fs::write(&original, b"bytes").unwrap();
        let callback = |_| {
            if fs::read_dir(&dir.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|e| {
                    e.path().extension().is_some_and(|x| x == "fenc")
                        && !e.file_name().to_string_lossy().starts_with(".fe-")
                })
            {
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            } else {
                Ok(())
            }
        };
        let result =
            crypto::encrypt_file_with_progress(&[8; 32], &original, &options(), &callback).unwrap();
        assert_eq!(result.removal.info.state, DeletionState::Retained);
        assert!(result.path.exists());
        assert!(original.exists());
    }

    #[test]
    fn read_only_source_is_retained_and_can_be_retried_after_unlocking() {
        let dir = TestDir::new();
        let original = dir.0.join("readonly.txt");
        fs::write(&original, b"bytes").unwrap();
        let mut permissions = fs::metadata(&original).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&original, permissions).unwrap();
        let result =
            crypto::encrypt_file_with_progress(&[8; 32], &original, &options(), &|_| Ok(()))
                .unwrap();
        assert_eq!(result.removal.info.state, DeletionState::Retained);
        assert!(original.exists());
        let mut permissions = fs::metadata(&original).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&original, permissions).unwrap();
        assert_eq!(
            retry(result.removal.retry.unwrap(), None).info.state,
            DeletionState::Removed
        );
    }

    #[test]
    fn pending_deletion_is_reported_until_the_last_reader_closes() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
        };
        let dir = TestDir::new();
        let original = dir.0.join("pending.txt");
        fs::write(&original, b"bytes").unwrap();
        let source = Source::open(&original, true).unwrap();
        let reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(7)
            .open(&original)
            .unwrap();
        let output = publication::write(&dir.0.join("saved"), false, None, |w| {
            w.write_all(b"bytes")?;
            Ok(())
        })
        .unwrap();
        let ticket = RetryTicket {
            source: Arc::new(Receipt::capture(&source.file, &original, None).unwrap()),
            outputs: vec![output.receipt(None).unwrap()],
            pending: true,
        };
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: use the legacy API explicitly to exercise deferred removal on modern Windows.
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    source.file.as_raw_handle(),
                    FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of_val(&info) as u32,
                )
            },
            0
        );
        drop(source);
        drop(output);
        assert!(file_guard::namespace_present(&original).unwrap());
        let pending = retry(ticket, None);
        assert_eq!(pending.info.state, DeletionState::Pending);
        drop(reader);
        assert_eq!(
            retry(pending.retry.unwrap(), None).info.state,
            DeletionState::Removed
        );
    }
    #[test]
    fn rotation_checks_cancellation_after_publication_for_files_and_zips() {
        for zip in [false, true] {
            for cancelled in [false, true] {
                let dir = TestDir::new();
                let plain = dir.0.join("plain.txt");
                fs::write(&plain, b"secret").unwrap();
                let encryption = JobOptions {
                    remove_original: false,
                    output_dir: Some(dir.0.join("encrypted")),
                    ..options()
                };
                let old = [1; 32];
                let new = [2; 32];
                let input = if zip {
                    crate::archive::encrypt_to_zip(&old, &[plain], &encryption)
                        .unwrap()
                        .path
                } else {
                    crypto::encrypt_file_with_progress(&old, &plain, &encryption, &|_| Ok(()))
                        .unwrap()
                        .path
                };
                let output_dir = dir.0.join("rotated");
                let rotation = JobOptions {
                    output_dir: Some(output_dir.clone()),
                    ..options()
                };
                let callback = |_| {
                    if cancelled
                        && fs::read_dir(&output_dir).is_ok_and(|entries| {
                            entries
                                .filter_map(Result::ok)
                                .any(|e| !e.file_name().to_string_lossy().starts_with(".fe-"))
                        })
                    {
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "cancelled after rotation publication",
                        ))
                    } else {
                        Ok(())
                    }
                };
                let result = if zip {
                    crate::archive::rotate_zip_with_deletion(
                        &old,
                        &new,
                        &input,
                        &rotation,
                        Some(&callback),
                    )
                } else {
                    crypto::rotate_file_with_deletion(
                        &old,
                        &new,
                        &input,
                        &rotation,
                        Some(&callback),
                    )
                }
                .unwrap();
                assert_eq!(
                    result.removal.info.state,
                    if cancelled {
                        DeletionState::Retained
                    } else {
                        DeletionState::Removed
                    }
                );
                assert_eq!(input.exists(), cancelled);
                assert!(result.path.exists());
                if zip {
                    let entries = crate::archive_read::entries(&result.path).unwrap();
                    assert_eq!(
                        crate::archive_read::inspect_names(&result.path, &new, &entries).unwrap(),
                        ["plain.txt"]
                    );
                } else {
                    crypto::verify_file(&new, &result.path, None).unwrap();
                }
            }
        }
    }
}

#[cfg(all(test, not(windows)))]
mod platform_tests {
    use super::*;
    use crate::{
        crypto::{self, JobOptions},
        test_support::TestDir,
    };
    use std::fs;

    #[test]
    fn a_complete_copy_retains_its_original_without_mandatory_protection() {
        let dir = TestDir::new();
        let source = dir.0.join("source.txt");
        fs::write(&source, b"bytes").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: None,
        };
        let result =
            crypto::encrypt_file_with_progress(&[8; 32], &source, &options, &|_| Ok(())).unwrap();
        assert_eq!(result.removal.info.state, DeletionState::Retained);
        assert!(result.removal.retry.is_none());
        assert_eq!(fs::read(&source).unwrap(), b"bytes");
        crypto::verify_file(&[8; 32], &result.path, None).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_source_symlink_is_rejected_without_removing_its_target() {
        let dir = TestDir::new();
        let source = dir.0.join("source.txt");
        let link = dir.0.join("link.txt");
        fs::write(&source, b"bytes").unwrap();
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert_eq!(
            Source::open(&link, true).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(fs::read(source).unwrap(), b"bytes");
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }
}
