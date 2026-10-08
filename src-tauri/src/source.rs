//! Keep the source stable through publication and delete the file we actually opened.
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub struct Source {
    pub file: File,
    path: PathBuf,
    initial: Metadata,
    deletable: bool,
}

impl Source {
    pub fn open(path: &Path, deletable: bool) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Exclude writers and renames for the lifetime of this handle. DELETE access
            // lets removal target this handle, without reopening a potentially replaced path.
            options
                .share_mode(1)
                .access_mode(0x8000_0000 | if deletable { 0x0001_0000 } else { 0 });
        }
        let (file, can_delete) = match options.open(path) {
            Ok(file) => (file, deletable),
            #[cfg(windows)]
            Err(err) if deletable && matches!(err.raw_os_error(), Some(5 | 32)) => {
                use std::os::windows::fs::OpenOptionsExt;
                // A reader may deny DELETE access while still allowing a stable copy.
                // Keep that source and report OriginalRemains after publishing the copy.
                (options.access_mode(0x8000_0000).open(path)?, false)
            }
            Err(err) => return Err(err),
        };
        let initial = file.metadata()?;
        if !initial.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source is not a regular file",
            ));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            initial,
            deletable: can_delete,
        })
    }

    pub fn len(&self) -> u64 {
        self.initial.len()
    }

    pub fn check(&self) -> io::Result<()> {
        let current = self.file.metadata()?;
        let at_path = fs::metadata(&self.path)?;
        let unchanged = current.len() == self.initial.len()
            && current.modified()? == self.initial.modified()?
            && at_path.len() == self.initial.len()
            && at_path.modified()? == self.initial.modified()?;
        #[cfg(unix)]
        let unchanged = {
            use std::os::unix::fs::MetadataExt;
            unchanged
                && at_path.dev() == self.initial.dev()
                && at_path.ino() == self.initial.ino()
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

    pub fn remove(&self) -> io::Result<()> {
        self.check()?;
        if !self.deletable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "source could not be opened for deletion; original was preserved",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
            };
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: the live file handle was opened with DELETE access; the buffer
            // has the exact layout and length required by FileDispositionInfo.
            if unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of_val(&disposition) as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            fs::remove_file(&self.path)
        }
    }
}
