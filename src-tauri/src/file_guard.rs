//! File identity, protected publication, and namespace deletion primitives.
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub volume: u64,
    pub file: u64,
}

pub fn identity(file: &File) -> io::Result<Identity> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the live handle and correctly sized output buffer remain valid.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Identity {
            volume: info.dwVolumeSerialNumber as u64,
            file: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(Identity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file identity is unavailable",
        ))
    }
}

pub fn regular(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symbolic links and non-regular files are not supported",
        ));
    }
    Ok(())
}

pub fn configure_read(options: &mut OpenOptions, delete: bool) {
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .access_mode(0x8000_0000 | if delete { 0x0001_0000 } else { 0 });
    }
    #[cfg(not(windows))]
    let _ = delete;
}

pub fn open_read(path: &Path, delete: bool) -> io::Result<File> {
    regular(&fs::symlink_metadata(path)?)?;
    let mut options = OpenOptions::new();
    configure_read(&mut options, delete);
    let file = options.open(path)?;
    regular(&file.metadata()?)?;
    Ok(file)
}

/// The encrypted format stores the unnamed data stream only. Check the pinned
/// source handle rather than following a potentially changed pathname.
#[cfg(windows)]
pub fn ensure_no_named_streams(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetLastError, ERROR_HANDLE_EOF};
    use windows_sys::Win32::Storage::FileSystem::{
        FileStreamInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
        FILE_STREAM_INFO,
    };
    const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
    let unknown = |error: io::Error| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Windows data streams could not be checked; original retained: {error}"),
        )
    };
    // FILE_STREAM_INFO requires eight-byte alignment. Bound allocation even for
    // a provider returning unusually large stream lists.
    let mut buffer = vec![0u64; 512];
    loop {
        // SAFETY: the live handle and aligned, initialized output allocation are valid.
        let success = unsafe {
            // FileStreamInfo documents ERROR_HANDLE_EOF for an empty stream list,
            // including a successful call. Clear stale errors before querying.
            SetLastError(0);
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
            )
        };
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            return Ok(());
        }
        if success != 0 {
            break;
        }
        if matches!(error.raw_os_error(), Some(122 | 234)) && buffer.len() * 8 < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if matches!(error.raw_os_error(), Some(1 | 50 | 87)) {
            // FAT/exFAT do not have named streams. Only bypass the unsupported
            // query when the same handle's volume explicitly confirms that.
            let mut flags = 0;
            // SAFETY: optional buffers are null and flags is a valid DWORD output.
            let known = unsafe {
                GetVolumeInformationByHandleW(
                    file.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut flags,
                    std::ptr::null_mut(),
                    0,
                )
            } != 0;
            if known && flags & FILE_NAMED_STREAMS == 0 {
                return Ok(());
            }
        }
        return Err(unknown(error));
    }
    // The only permitted list is one entry named ::$DATA. Any second entry
    // or different name represents data this format does not preserve.
    let offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    // SAFETY: the allocation is aligned and larger than FILE_STREAM_INFO.
    let info = unsafe { &*buffer.as_ptr().cast::<FILE_STREAM_INFO>() };
    let length = info.StreamNameLength as usize;
    if !length.is_multiple_of(2) || length > buffer.len() * 8 - offset {
        return Err(unknown(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid stream information",
        )));
    }
    // SAFETY: the UTF-16 slice is aligned and bounds-checked above.
    let name = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
            length / 2,
        )
    };
    if info.NextEntryOffset != 0 || name != [58, 58, 36, 68, 65, 84, 65] {
        return Err(io::Error::new(io::ErrorKind::Unsupported,
            "Original retained because it contains additional Windows data streams that are not included in the saved copy."));
    }
    Ok(())
}

pub fn create(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        };
        // Request DELETE at creation so publication and cleanup use this exact handle.
        // Deny other writers and deleters while still permitting compatible readers.
        options
            .share_mode(1)
            .access_mode(0xc001_0000)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

pub fn check_path(file: &File, path: &Path, expected: Identity, size: u64) -> io::Result<()> {
    regular(&file.metadata()?)?;
    regular(&fs::symlink_metadata(path)?)?;
    // Metadata-only access is compatible with the protected read/write publication handle.
    #[cfg(windows)]
    let at_path = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        OpenOptions::new()
            .access_mode(0)
            .share_mode(7)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?
    };
    #[cfg(not(windows))]
    let at_path = File::open(path)?;
    if identity(file)? != expected
        || identity(&at_path)? != expected
        || file.metadata()?.len() != size
        || at_path.metadata()?.len() != size
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file was changed or replaced; original was preserved",
        ));
    }
    Ok(())
}

pub fn rename(file: &File, from: &Path, to: &Path, overwrite: bool) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
        };
        let _ = from;
        let parent = to
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = to
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output needs a name"))?;
        let destination = fs::canonicalize(parent)?.join(name);
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output contains a null byte",
            ));
        }
        let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let length = (offset + (name.len() + 1) * 2).max(std::mem::size_of::<FILE_RENAME_INFO>());
        let mut buffer = vec![0u64; length.div_ceil(8)];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: the u64 backing allocation is aligned for FILE_RENAME_INFO and includes
        // the full trailing UTF-16 name plus a terminator; only the initialized length is sent.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = overwrite;
            (*info).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                name.len(),
            );
            if SetFileInformationByHandle(
                file.as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                length as u32,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        if overwrite {
            fs::rename(from, to)
        } else {
            fs::hard_link(from, to)?;
            fs::remove_file(from)
        }
    }
}

/// Mark this exact opened file for removal; callers close their handles afterwards.
pub fn request_delete(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let _ = path;
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: both disposition buffers have their documented layouts and lengths.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfoEx,
                (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } != 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(1 | 50 | 87)) {
            return Err(error);
        }
        // Older Windows/filesystems may support only deferred namespace removal.
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        fs::remove_file(path)
    }
}

/// Unlike exists(), enumeration can see Windows entries that are deletion-pending.
pub fn namespace_present(path: &Path) -> io::Result<bool> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FindClose, FindFirstFileW, WIN32_FIND_DATAW,
        };
        // An exact-name directory query sees pending entries without scanning the entire
        // directory for every original in a batch. Canonicalize only the parent: the
        // pending file itself cannot be opened for canonicalization.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file needs a name"))?;
        let full = fs::canonicalize(parent)?.join(name);
        let wide: Vec<u16> = full.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: wide is null terminated and the output buffer is correctly sized.
        let handle = unsafe { FindFirstFileW(wide.as_ptr(), &mut data) };
        if handle == -1isize as _ {
            let error = io::Error::last_os_error();
            return if matches!(error.raw_os_error(), Some(2 | 3)) {
                Ok(false)
            } else {
                Err(error)
            };
        }
        // SAFETY: this is a valid search handle returned above.
        unsafe {
            FindClose(handle);
        }
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

pub fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
