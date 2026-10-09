//! Keep complete outputs protected until source cleanup finishes.
#[cfg(windows)]
use crate::deletion::Receipt;
use crate::{
    crypto::{CryptoError, ProgressCallback},
    file_guard,
};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::{Arc, Mutex};

#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct PublishedFile {
    pub path: PathBuf,
    file: File,
    identity: file_guard::Identity,
    size: u64,
    #[cfg(windows)]
    receipt: Mutex<Option<Arc<Receipt>>>,
}

impl PublishedFile {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn check(&self) -> io::Result<()> {
        file_guard::check_path(&self.file, &self.path, self.identity, self.size)
    }
    #[cfg(windows)]
    pub fn receipt(&self, callback: Option<&ProgressCallback<'_>>) -> io::Result<Arc<Receipt>> {
        self.check()?;
        let mut cached = self.receipt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(receipt) = &*cached {
            return Ok(receipt.clone());
        }
        let receipt = Arc::new(Receipt::capture(&self.file, &self.path, callback)?);
        self.check()?;
        *cached = Some(receipt.clone());
        Ok(receipt)
    }
}

struct Partial {
    file: Option<File>,
    path: PathBuf,
    published: bool,
}
impl Partial {
    fn discard(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_ref() {
            let mut result = file_guard::request_delete(file, &self.path);
            for delay in [50, 100] {
                if !matches!(&result, Err(error) if matches!(error.raw_os_error(), Some(32 | 33))) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(delay));
                result = file_guard::request_delete(file, &self.path);
            }
            // Keep the exact handle pinned throughout every cleanup attempt.
            drop(self.file.take());
            result?;
            file_guard::sync_parent(&self.path)?;
            if file_guard::namespace_present(&self.path)? {
                return Err(io::Error::other("temporary file deletion is pending"));
            }
        }
        Ok(())
    }
}
impl Drop for Partial {
    fn drop(&mut self) {
        if !self.published {
            if let Err(error) = self.discard() {
                // Normal error paths report cleanup explicitly; this handles unwinding.
                eprintln!(
                    "Temporary file retained at {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

pub fn write(
    output: &Path,
    overwrite: bool,
    callback: Option<&ProgressCallback<'_>>,
    produce: impl FnOnce(&mut dyn Write) -> Result<(), CryptoError>,
) -> Result<PublishedFile, CryptoError> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let path = output.with_file_name(format!(
        ".fe-partial-{}",
        crate::crypto::opaque_file_name().to_string_lossy()
    ));
    let mut partial = Partial {
        file: Some(file_guard::create(&path)?),
        path,
        published: false,
    };
    let result = (|| {
        let file = partial.file.as_ref().unwrap();
        let mut writer = BufWriter::new(file.try_clone()?);
        produce(&mut writer)?;
        writer.flush()?;
        drop(writer);
        file.sync_all()?;
        if let Some(callback) = callback {
            callback(0)?;
        }
        match fs::symlink_metadata(output) {
            Ok(_) if !overwrite => {
                return Err(CryptoError::OutputExists(output.display().to_string()))
            }
            Ok(metadata) => file_guard::regular(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        file_guard::rename(file, &partial.path, output, overwrite).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CryptoError::OutputExists(output.display().to_string())
            } else {
                error.into()
            }
        })?;
        partial.published = true;
        partial.path = output.to_path_buf();
        // Flush the final file after the atomic namespace operation, not only the temporary name.
        let details = (|| -> io::Result<_> {
            file.sync_all()?;
            file_guard::sync_parent(output)?;
            Ok((file_guard::identity(file)?, file.metadata()?.len()))
        })();
        details.map_err(|error| CryptoError::PublicationUncertain {
            output: output.display().to_string(),
            source: error,
        })
    })();
    match result {
        Ok((identity, size)) => Ok(PublishedFile {
            path: output.to_path_buf(),
            file: partial.file.take().unwrap(),
            identity,
            size,
            #[cfg(windows)]
            receipt: Mutex::new(None),
        }),
        Err(error) => {
            if !partial.published {
                if let Err(cleanup) = partial.discard() {
                    return Err(CryptoError::CleanupFailed {
                        cause: Box::new(error),
                        path: partial.path.display().to_string(),
                        source: cleanup,
                    });
                }
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    #[cfg(windows)]
    #[test]
    fn published_output_is_pinned_until_cleanup_finishes() {
        let dir = TestDir::new();
        let path = dir.0.join("restored.txt");
        let published = write(&path, false, None, |w| {
            w.write_all(b"complete")?;
            Ok(())
        })
        .unwrap();
        assert!(fs::write(&path, b"changed").is_err());
        assert!(fs::remove_file(&path).is_err());
        assert!(fs::rename(&path, dir.0.join("moved.txt")).is_err());
        published.check().unwrap();
        drop(published);
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn cancellation_after_flush_keeps_previous_output_and_cleans_partial() {
        let dir = TestDir::new();
        let path = dir.0.join("existing.txt");
        fs::write(&path, b"previous").unwrap();
        let cancelled = |_| {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled after flush",
            ))
        };
        assert!(write(&path, true, Some(&cancelled), |w| {
            w.write_all(b"new plaintext")?;
            Ok(())
        })
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn failed_overwrite_keeps_old_output_without_backups_or_partials() {
        let dir = TestDir::new();
        let path = dir.0.join("existing.txt");
        fs::write(&path, b"previous").unwrap();
        let old = crate::source::Source::open(&path, false).unwrap();
        assert!(write(&path, true, None, |w| {
            w.write_all(b"new plaintext")?;
            Ok(())
        })
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        drop(old);
    }

    #[cfg(windows)]
    #[test]
    fn failed_plaintext_cleanup_reports_the_exact_retained_path() {
        let dir = TestDir::new();
        let path = dir.0.join("restored.txt");
        let mut original_permissions = None;
        let error = write(&path, false, None, |w| {
            w.write_all(b"partial plaintext")?;
            w.flush()?;
            let partial = fs::read_dir(&dir.0)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let mut permissions = fs::metadata(&partial)?.permissions();
            original_permissions = Some(permissions.clone());
            permissions.set_readonly(true);
            fs::set_permissions(partial, permissions)?;
            Err(CryptoError::AuthenticationFailed)
        })
        .unwrap_err();
        let CryptoError::CleanupFailed { path: partial, .. } = error else {
            panic!("unexpected error: {error:?}");
        };
        let partial = PathBuf::from(partial);
        assert_eq!(partial.parent(), Some(dir.0.as_path()));
        assert_eq!(fs::read(&partial).unwrap(), b"partial plaintext");
        assert!(!path.exists());
        fs::set_permissions(&partial, original_permissions.unwrap()).unwrap();
        fs::remove_file(partial).unwrap();
    }
}
