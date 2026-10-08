//! Pin source identity and reject source links at the opened-handle boundary.
use crate::file_guard::{self, Identity};
use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

pub struct Source {
    pub file: File,
    pub path: PathBuf,
    initial: Metadata,
    identity: Identity,
    #[cfg(windows)]
    delete_error: Option<i32>,
    #[cfg(windows)]
    deletable: bool,
}

impl Source {
    pub fn open(path: &Path, deletable: bool) -> io::Result<Self> {
        let (file, can_delete, delete_error): (File, bool, Option<i32>) =
            match file_guard::open_read(path, deletable) {
                Ok(file) => (file, deletable, None),
                #[cfg(windows)]
                Err(error) if deletable && matches!(error.raw_os_error(), Some(5 | 32)) => (
                    file_guard::open_read(path, false)?,
                    false,
                    error.raw_os_error(),
                ),
                Err(error) => return Err(error),
            };
        #[cfg(not(windows))]
        let _ = (can_delete, delete_error);
        let initial = file.metadata()?;
        file_guard::regular(&initial)?;
        let identity = file_guard::identity(&file)?;
        let source = Self {
            file,
            path: path.to_path_buf(),
            initial,
            identity,
            #[cfg(windows)]
            deletable: can_delete,
            #[cfg(windows)]
            delete_error,
        };
        source.check()?;
        Ok(source)
    }

    pub fn len(&self) -> u64 {
        self.initial.len()
    }
    #[cfg(windows)]
    pub fn can_delete(&self) -> bool {
        self.deletable
    }

    pub fn check(&self) -> io::Result<()> {
        file_guard::check_path(&self.file, &self.path, self.identity, self.initial.len())?;
        let current = self.file.metadata()?;
        let unchanged = current.modified()? == self.initial.modified()?;
        #[cfg(unix)]
        let unchanged = {
            use std::os::unix::fs::MetadataExt;
            unchanged
                && current.ctime() == self.initial.ctime()
                && current.ctime_nsec() == self.initial.ctime_nsec()
        };
        if unchanged {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed; original was preserved",
            ))
        }
    }

    #[cfg(windows)]
    pub fn remove(self) -> io::Result<crate::deletion::DeletionState> {
        self.check()?;
        if !self.deletable {
            return Err(self
                .delete_error
                .map(io::Error::from_raw_os_error)
                .unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "source was not opened for deletion",
                    )
                }));
        }
        file_guard::ensure_no_named_streams(&self.file)?;
        self.check()?;
        file_guard::request_delete(&self.file, &self.path)?;
        let path = self.path.clone();
        drop(self);
        match file_guard::namespace_present(&path) {
            Ok(false) => Ok(crate::deletion::DeletionState::Removed),
            // Once deletion is accepted, a failed namespace query must not turn it
            // back into an unaccepted deletion. A later check can confirm removal.
            Ok(true) | Err(_) => Ok(crate::deletion::DeletionState::Pending),
        }
    }
}
