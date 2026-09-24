//! A ZIP container for already encrypted files. Stored entries avoid trying to
//! compress ciphertext and keep each `.fenc` file independently decryptable.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive_read;
use crate::crypto::{self, CryptoError, JobOptions};

struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct ArchiveOutcome {
    pub path: PathBuf,
    pub delete_errors: Vec<Option<String>>,
}

type EntryCallback<'a> = dyn Fn(usize, &Path) + 'a;

/// Encrypt every input before publishing the ZIP. Originals are removed only
/// after the finished archive has been committed to its destination.
#[cfg(test)]
pub fn encrypt_to_zip(
    key: &[u8; 32],
    inputs: &[PathBuf],
    options: &JobOptions,
) -> Result<ArchiveOutcome, CryptoError> {
    encrypt_to_zip_with_progress(key, inputs, options, None, false, None, None)
}

pub fn relative_names(
    inputs: &[PathBuf],
    root_hint: Option<&Path>,
) -> Result<Vec<String>, CryptoError> {
    let mut root = root_hint.map(Path::to_path_buf).unwrap_or_else(|| {
        inputs
            .first()
            .and_then(|path| path.parent())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    if inputs.is_empty() {
        return Err(CryptoError::NotAFile("add at least one file".into()));
    }
    if root_hint.is_some() && !inputs.iter().all(|path| path.starts_with(&root)) {
        return Err(CryptoError::BadEncryptedName);
    }
    while !inputs.iter().all(|path| path.starts_with(&root)) {
        if !root.pop() {
            return Err(CryptoError::NotAFile(
                "files must share a filesystem root".into(),
            ));
        }
    }
    inputs
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| CryptoError::BadEncryptedName)?;
            let parts = relative
                .components()
                .map(|part| {
                    part.as_os_str()
                        .to_str()
                        .ok_or(CryptoError::BadEncryptedName)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parts.is_empty() {
                return Err(CryptoError::BadEncryptedName);
            }
            let name = parts.join("/");
            crypto::validate_relative_name(&name)?;
            Ok(name)
        })
        .collect()
}

pub fn encrypt_to_zip_with_progress(
    key: &[u8; 32],
    inputs: &[PathBuf],
    options: &JobOptions,
    root_hint: Option<&Path>,
    compress: bool,
    progress: Option<&crypto::ProgressCallback<'_>>,
    on_entry: Option<&EntryCallback<'_>>,
) -> Result<ArchiveOutcome, CryptoError> {
    let first = inputs
        .first()
        .ok_or_else(|| CryptoError::NotAFile("add at least one file".into()))?;
    let destination = match &options.output_dir {
        Some(dir) => dir.clone(),
        None => first
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
    };
    if destination.exists() && !destination.is_dir() {
        return Err(CryptoError::NotAFile(format!(
            "output folder is not a folder: {}",
            destination.display()
        )));
    }
    fs::create_dir_all(&destination)?;

    let archive = (0..8)
        .map(|_| {
            let mut name = PathBuf::from(crypto::opaque_file_name());
            name.set_extension("zip");
            destination.join(name)
        })
        .find(|path| !path.exists())
        .ok_or(CryptoError::EncryptFailed)?;

    for (index, input) in inputs.iter().enumerate() {
        crypto::ensure_distinct(input, &archive, options.key_file.as_deref())?;
        if inputs[..index].iter().any(|other| same_file(other, input)) {
            return Err(CryptoError::NotAFile(format!(
                "file selected more than once: {}",
                input.display()
            )));
        }
    }

    let work_dir = archive.with_extension("zip.work");
    fs::create_dir(&work_dir)?;
    let _cleanup = RemoveDir(work_dir.clone());
    let staging = JobOptions {
        overwrite: false,
        remove_original: false,
        key_file: options.key_file.clone(),
        output_dir: Some(work_dir),
    };
    let relative_names = relative_names(inputs, root_hint)?;
    let encrypted: Vec<PathBuf> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if let Some(on_entry) = on_entry {
                on_entry(index, input);
            }
            crypto::encrypt_bundle_entry_with_progress(
                key,
                input,
                &relative_names[index],
                compress,
                &staging,
                progress,
            )
        })
        .collect::<Result<_, _>>()?;
    if let Some(on_entry) = on_entry {
        on_entry(inputs.len(), &archive);
    }
    crypto::write_transformed(&archive, false, |writer| {
        write_zip(writer, &encrypted, progress).map_err(Into::into)
    })?;

    let delete_errors = inputs
        .iter()
        .map(|input| {
            if options.remove_original {
                fs::remove_file(input).err().map(|err| err.to_string())
            } else {
                None
            }
        })
        .collect();
    Ok(ArchiveOutcome {
        path: archive,
        delete_errors,
    })
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn rotate_zip_with_progress(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    progress: Option<&crypto::ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    let entries = archive_read::entries(input)?;
    let destination = options.output_dir.clone().unwrap_or_else(|| {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    fs::create_dir_all(&destination)?;
    let archive = (0..8)
        .map(|_| {
            let mut name = PathBuf::from(crypto::opaque_file_name());
            name.set_extension("zip");
            destination.join(name)
        })
        .find(|path| !path.exists())
        .ok_or(CryptoError::EncryptFailed)?;
    crypto::ensure_distinct(input, &archive, options.key_file.as_deref())?;
    let work_dir = archive.with_extension("zip.work");
    fs::create_dir(&work_dir)?;
    let _cleanup = RemoveDir(work_dir.clone());
    let new_dir = work_dir.join("new");
    fs::create_dir(&new_dir)?;
    let staging = JobOptions {
        overwrite: false,
        remove_original: false,
        key_file: options.key_file.clone(),
        output_dir: Some(new_dir),
    };
    let mut rotated = Vec::with_capacity(entries.len());
    for entry in entries {
        let old_file = work_dir.join(&entry.name);
        archive_read::extract_entry(input, &entry, &old_file, progress)?;
        rotated.push(crypto::rotate_file_with_progress(
            old_key, new_key, &old_file, &staging, progress,
        )?);
    }
    crypto::write_transformed(&archive, false, |writer| {
        write_zip(writer, &rotated, progress).map_err(Into::into)
    })?;
    if options.remove_original {
        fs::remove_file(input).map_err(|source| CryptoError::OriginalRemains {
            output: archive.display().to_string(),
            source,
        })?;
    }
    Ok(archive)
}

struct Entry {
    name: Vec<u8>,
    size: u64,
    crc: u32,
    offset: u64,
}

struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    position: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn write_zip(
    writer: &mut dyn Write,
    paths: &[PathBuf],
    progress: Option<&crypto::ProgressCallback<'_>>,
) -> io::Result<()> {
    let mut writer = CountingWriter {
        inner: writer,
        position: 0,
    };
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid ZIP entry name"))?
            .as_bytes()
            .to_vec();
        if name.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZIP entry name is too long",
            ));
        }
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        let large = size >= u32::MAX as u64;
        let offset = writer.position;
        let version: u16 = if large { 45 } else { 20 };
        let extra_len: u16 = if large { 20 } else { 0 };

        writer.write_all(&0x0403_4b50u32.to_le_bytes())?;
        writer.write_all(&version.to_le_bytes())?;
        writer.write_all(&8u16.to_le_bytes())?; // data descriptor follows the entry
        writer.write_all(&0u16.to_le_bytes())?; // stored; ciphertext is incompressible
        writer.write_all(&[0; 4])?; // DOS time and date
        writer.write_all(&0u32.to_le_bytes())?; // CRC is written in the descriptor
        for _ in 0..2 {
            writer.write_all(&(if large { u32::MAX } else { 0 }).to_le_bytes())?;
        }
        writer.write_all(&(name.len() as u16).to_le_bytes())?;
        writer.write_all(&extra_len.to_le_bytes())?;
        writer.write_all(&name)?;
        if large {
            writer.write_all(&1u16.to_le_bytes())?; // ZIP64 extended information
            writer.write_all(&16u16.to_le_bytes())?;
            writer.write_all(&size.to_le_bytes())?;
            writer.write_all(&size.to_le_bytes())?;
        }

        let mut reader = BufReader::new(file);
        let mut hasher = crc32fast::Hasher::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if let Some(progress) = progress {
                progress(0)?;
            }
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            writer.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
            copied += count as u64;
        }
        if copied != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted file changed while archiving",
            ));
        }
        let crc = hasher.finalize();
        writer.write_all(&0x0807_4b50u32.to_le_bytes())?;
        writer.write_all(&crc.to_le_bytes())?;
        if large {
            writer.write_all(&size.to_le_bytes())?;
            writer.write_all(&size.to_le_bytes())?;
        } else {
            writer.write_all(&(size as u32).to_le_bytes())?;
            writer.write_all(&(size as u32).to_le_bytes())?;
        }
        entries.push(Entry {
            name,
            size,
            crc,
            offset,
        });
    }

    let central_offset = writer.position;
    let mut zip64 = false;
    for entry in &entries {
        let large = entry.size >= u32::MAX as u64;
        let far = entry.offset >= u32::MAX as u64;
        zip64 |= large || far;
        let version: u16 = if large || far { 45 } else { 20 };
        let extra_len: u16 = if large || far {
            4 + (if large { 16 } else { 0 }) + (if far { 8 } else { 0 })
        } else {
            0
        };
        writer.write_all(&0x0201_4b50u32.to_le_bytes())?;
        writer.write_all(&version.to_le_bytes())?; // version made by
        writer.write_all(&version.to_le_bytes())?; // version needed
        writer.write_all(&8u16.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?;
        writer.write_all(&[0; 4])?;
        writer.write_all(&entry.crc.to_le_bytes())?;
        for _ in 0..2 {
            writer.write_all(&(if large { u32::MAX } else { entry.size as u32 }).to_le_bytes())?;
        }
        writer.write_all(&(entry.name.len() as u16).to_le_bytes())?;
        writer.write_all(&extra_len.to_le_bytes())?;
        writer.write_all(&0u16.to_le_bytes())?; // comment length
        writer.write_all(&0u16.to_le_bytes())?; // disk number
        writer.write_all(&0u16.to_le_bytes())?; // internal attributes
        writer.write_all(&0u32.to_le_bytes())?; // external attributes
        writer.write_all(&(if far { u32::MAX } else { entry.offset as u32 }).to_le_bytes())?;
        writer.write_all(&entry.name)?;
        if large || far {
            writer.write_all(&1u16.to_le_bytes())?;
            writer.write_all(&extra_len.saturating_sub(4).to_le_bytes())?;
            if large {
                writer.write_all(&entry.size.to_le_bytes())?;
                writer.write_all(&entry.size.to_le_bytes())?;
            }
            if far {
                writer.write_all(&entry.offset.to_le_bytes())?;
            }
        }
    }
    let central_size = writer.position - central_offset;
    zip64 |= entries.len() >= u16::MAX as usize
        || central_size >= u32::MAX as u64
        || central_offset >= u32::MAX as u64;
    if zip64 {
        let zip64_offset = writer.position;
        writer.write_all(&0x0606_4b50u32.to_le_bytes())?;
        writer.write_all(&44u64.to_le_bytes())?;
        writer.write_all(&45u16.to_le_bytes())?;
        writer.write_all(&45u16.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&(entries.len() as u64).to_le_bytes())?;
        writer.write_all(&(entries.len() as u64).to_le_bytes())?;
        writer.write_all(&central_size.to_le_bytes())?;
        writer.write_all(&central_offset.to_le_bytes())?;
        writer.write_all(&0x0706_4b50u32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&zip64_offset.to_le_bytes())?;
        writer.write_all(&1u32.to_le_bytes())?;
    }
    writer.write_all(&0x0605_4b50u32.to_le_bytes())?;
    writer.write_all(&0u16.to_le_bytes())?;
    writer.write_all(&0u16.to_le_bytes())?;
    for _ in 0..2 {
        writer.write_all(&(entries.len().min(u16::MAX as usize) as u16).to_le_bytes())?;
    }
    writer.write_all(&(central_size.min(u32::MAX as u64) as u32).to_le_bytes())?;
    writer.write_all(&(central_offset.min(u32::MAX as u64) as u32).to_le_bytes())?;
    writer.write_all(&0u16.to_le_bytes())?;
    if let Some(progress) = progress {
        progress(0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_read;
    use std::process::Command;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let mut name = PathBuf::from(crypto::opaque_file_name());
            name.set_extension("test");
            let path = std::env::temp_dir().join(name);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn zip_contains_decryptable_files_and_deletes_sources_only_after_success() {
        let dir = TestDir::new();
        let first = dir.0.join("first.txt");
        let second = dir.0.join("second.bin");
        fs::write(&first, b"private words").unwrap();
        fs::write(&second, [0, 1, 2, 255]).unwrap();
        let output_dir = dir.0.join("output");
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: Some(output_dir),
        };
        let key = [7u8; 32];

        let missing = dir.0.join("missing.txt");
        assert!(encrypt_to_zip(&key, &[first.clone(), missing], &options).is_err());
        assert!(first.exists());
        assert_eq!(
            fs::read_dir(options.output_dir.as_ref().unwrap())
                .unwrap()
                .count(),
            0
        );

        let result = encrypt_to_zip(&key, &[first.clone(), second.clone()], &options).unwrap();
        assert_eq!(result.delete_errors, vec![None, None]);
        assert!(!first.exists());
        assert!(!second.exists());
        assert_eq!(result.path.extension().unwrap(), "zip");
        assert!(fs::read(&result.path).unwrap().starts_with(b"PK\x03\x04"));

        // Python's standard ZIP reader independently checks the directory,
        // CRCs, and extractability when Python is available on the test host.
        let extracted = dir.0.join("extracted");
        let script = "import sys, zipfile; z=zipfile.ZipFile(sys.argv[1]); assert len(z.namelist()) == 2; assert all(n.endswith('.fenc') for n in z.namelist()); assert z.testzip() is None; z.extractall(sys.argv[2])";
        let check = Command::new("python")
            .arg("-c")
            .arg(script)
            .arg(&result.path)
            .arg(&extracted)
            .status();
        if let Ok(status) = check {
            assert!(status.success());
            let restored = dir.0.join("restored");
            let decrypt_options = JobOptions {
                overwrite: false,
                remove_original: false,
                key_file: None,
                output_dir: Some(restored),
            };
            for entry in fs::read_dir(extracted).unwrap() {
                crypto::decrypt_file(&key, &entry.unwrap().path(), &decrypt_options).unwrap();
            }
            assert_eq!(
                fs::read(
                    decrypt_options
                        .output_dir
                        .as_ref()
                        .unwrap()
                        .join("first.txt")
                )
                .unwrap(),
                b"private words"
            );
            assert_eq!(
                fs::read(
                    decrypt_options
                        .output_dir
                        .as_ref()
                        .unwrap()
                        .join("second.bin")
                )
                .unwrap(),
                [0, 1, 2, 255]
            );
        }
    }

    #[test]
    fn bundle_restores_nested_paths_with_and_without_compression() {
        for compress in [false, true] {
            let dir = TestDir::new();
            let root = dir.0.join("source");
            let first = root.join("north").join("same.txt");
            let second = root.join("south").join("same.txt");
            fs::create_dir_all(first.parent().unwrap()).unwrap();
            fs::create_dir_all(second.parent().unwrap()).unwrap();
            fs::write(&first, vec![b'A'; 200_000]).unwrap();
            fs::write(&second, b"south").unwrap();
            let options = JobOptions {
                overwrite: false,
                remove_original: false,
                key_file: None,
                output_dir: Some(dir.0.join("archives")),
            };
            let key = [91u8; 32];
            let archive = encrypt_to_zip_with_progress(
                &key,
                &[first, second],
                &options,
                None,
                compress,
                None,
                None,
            )
            .unwrap()
            .path;
            let entries = archive_read::entries(&archive).unwrap();
            let names = archive_read::inspect_names(&archive, &key, &entries).unwrap();
            assert_eq!(names, ["north/same.txt", "south/same.txt"]);
            let staging = dir.0.join("staging");
            fs::create_dir_all(&staging).unwrap();
            let restored = dir.0.join("restored");
            let restore_options = JobOptions {
                overwrite: false,
                remove_original: false,
                key_file: None,
                output_dir: Some(restored.clone()),
            };
            for entry in entries {
                let encrypted = staging.join(&entry.name);
                archive_read::extract_entry(&archive, &entry, &encrypted, None).unwrap();
                crypto::verify_file(&key, &encrypted, None).unwrap();
                crypto::decrypt_file(&key, &encrypted, &restore_options).unwrap();
            }
            assert_eq!(
                fs::read(restored.join("north/same.txt")).unwrap(),
                vec![b'A'; 200_000]
            );
            assert_eq!(fs::read(restored.join("south/same.txt")).unwrap(), b"south");
        }
    }

    #[test]
    fn compressed_bundle_rotates_and_retains_relative_paths() {
        let dir = TestDir::new();
        let source = dir.0.join("folder").join("child.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, vec![b'Z'; 180_000]).unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let old = [1u8; 32];
        let new = [2u8; 32];
        let archive =
            encrypt_to_zip_with_progress(&old, &[source], &options, None, true, None, None)
                .unwrap()
                .path;
        let rotated = rotate_zip_with_progress(&old, &new, &archive, &options, None).unwrap();
        let entries = archive_read::entries(&rotated).unwrap();
        let names = archive_read::inspect_names(&rotated, &new, &entries).unwrap();
        assert_eq!(names, ["child.txt"]);
        assert!(archive_read::inspect_names(&rotated, &old, &entries).is_err());
        let staged = dir.0.join(&entries[0].name);
        archive_read::extract_entry(&rotated, &entries[0], &staged, None).unwrap();
        let restore = JobOptions {
            output_dir: Some(dir.0.join("restored")),
            ..options
        };
        let plain = crypto::decrypt_file(&new, &staged, &restore).unwrap();
        assert_eq!(fs::read(plain).unwrap(), vec![b'Z'; 180_000]);
    }

    #[test]
    fn selected_folder_root_is_kept_for_a_single_nested_file() {
        let dir = TestDir::new();
        let root = dir.0.join("selected");
        let source = root.join("nested").join("only.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"only file").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let key = [8u8; 32];
        let zipped =
            encrypt_to_zip_with_progress(&key, &[source], &options, Some(&root), false, None, None)
                .unwrap()
                .path;
        let entries = archive_read::entries(&zipped).unwrap();
        assert_eq!(
            archive_read::inspect_names(&zipped, &key, &entries).unwrap(),
            ["nested/only.txt"]
        );
        let staged = dir.0.join(&entries[0].name);
        archive_read::extract_entry(&zipped, &entries[0], &staged, None).unwrap();
        let restore = JobOptions {
            output_dir: Some(dir.0.join("restored")),
            ..options
        };
        let plain = crypto::decrypt_file(&key, &staged, &restore).unwrap();
        assert_eq!(plain, dir.0.join("restored/nested/only.txt"));
        assert_eq!(fs::read(plain).unwrap(), b"only file");
    }

    #[test]
    fn zip_without_output_folder_stays_beside_first_input() {
        let dir = TestDir::new();
        let first_dir = dir.0.join("one");
        let second_dir = dir.0.join("two");
        fs::create_dir(&first_dir).unwrap();
        fs::create_dir(&second_dir).unwrap();
        let first = first_dir.join("a.txt");
        let second = second_dir.join("b.txt");
        fs::write(&first, b"a").unwrap();
        fs::write(&second, b"b").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        };
        let result = encrypt_to_zip(&[8; 32], &[first.clone(), second.clone()], &options).unwrap();
        assert_eq!(result.path.parent(), Some(first_dir.as_path()));
        assert!(first.exists());
        assert!(second.exists());
        assert_eq!(fs::read_dir(&second_dir).unwrap().count(), 1);
    }
}
