//! Streaming ZIP bundles with authenticated membership.
use crate::{
    archive_read,
    crypto::{self, BundleBinding, CryptoError, JobOptions},
    deletion::{self, Removal},
    publication,
    source::Source,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct ArchiveOutcome {
    pub path: PathBuf,
    pub removals: Vec<Removal>,
}
type EntryCallback<'a> = dyn Fn(usize, &Path) + 'a;
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

fn destination(input: &Path, options: &JobOptions) -> Result<PathBuf, CryptoError> {
    let dir = options.output_dir.clone().unwrap_or_else(|| {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    fs::create_dir_all(&dir)?;
    for _ in 0..8 {
        let mut name = PathBuf::from(crypto::opaque_file_name());
        name.set_extension("zip");
        let path = dir.join(name);
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(CryptoError::EncryptFailed)
}
fn binding(count: usize) -> BundleBinding {
    let text = crypto::opaque_file_name();
    let text = text.to_string_lossy();
    let mut id = [0; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
    }
    BundleBinding {
        id,
        count: count as u32,
    }
}
fn check(callback: Option<&crypto::ProgressCallback<'_>>) -> Result<(), CryptoError> {
    if let Some(callback) = callback {
        callback(0)?;
    }
    Ok(())
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
    if inputs.len() > 10_000 {
        return Err(CryptoError::NotAFile("select at most 10,000 files".into()));
    }
    let archive = destination(first, options)?;
    let mut seen = HashSet::with_capacity(inputs.len());
    for input in inputs {
        check(progress)?;
        crypto::ensure_distinct(input, &archive, options.key_file.as_deref())?;
        let canonical = fs::canonicalize(input)?;
        let canonical = if cfg!(windows) {
            PathBuf::from(canonical.to_string_lossy().to_lowercase())
        } else {
            canonical
        };
        if !seen.insert(canonical) {
            return Err(CryptoError::NotAFile("file selected more than once".into()));
        }
    }
    let names = relative_names(inputs, root_hint)?;
    let mut seen_names = HashSet::new();
    if names
        .iter()
        .any(|name| !seen_names.insert(name.to_lowercase()))
    {
        return Err(CryptoError::BadEncryptedName);
    }
    // Keep deletion handles open through publication; on Windows no source can be
    // modified or replaced in the interval between encrypting it and removing it.
    let mut held = Vec::new();
    let bundle = binding(inputs.len());
    let published = publication::write(&archive, false, progress, |writer| {
        let mut zip = ZipWriter::new(writer);
        for (index, input) in inputs.iter().enumerate() {
            check(progress)?;
            if let Some(on_entry) = on_entry {
                on_entry(index, input);
            }
            let source = Source::open(input, options.remove_original)?;
            let name = crypto::opaque_file_name().to_string_lossy().into_owned();
            zip.entry(&name, |sink| {
                crypto::encrypt_bundle_reader(
                    key,
                    &source,
                    &names[index],
                    compress,
                    bundle,
                    sink,
                    progress,
                )
            })?;
            if options.remove_original {
                held.push(source);
            }
        }
        if let Some(on_entry) = on_entry {
            on_entry(inputs.len(), &archive);
        }
        check(progress)?;
        for source in &held {
            source.check()?;
        }
        zip.finish(key, bundle)?;
        check(progress)
    })?;
    let removals = if options.remove_original {
        held.into_iter()
            .map(|source| deletion::remove(source, std::slice::from_ref(&published), progress))
            .collect()
    } else {
        inputs
            .iter()
            .map(|path| Removal::not_requested(path))
            .collect()
    };
    Ok(ArchiveOutcome {
        path: archive,
        removals,
    })
}

#[cfg(test)]
pub fn rotate_zip_with_progress(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    progress: Option<&crypto::ProgressCallback<'_>>,
) -> Result<PathBuf, CryptoError> {
    rotate_zip_with_deletion(old_key, new_key, input, options, progress).map(|result| result.path)
}

pub fn rotate_zip_with_deletion(
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    progress: Option<&crypto::ProgressCallback<'_>>,
) -> Result<crypto::TransformOutcome, CryptoError> {
    let source = Source::open(input, options.remove_original)?;
    let mut file = source.file.try_clone()?;
    let entries = archive_read::entries_from_reader(&mut file)?;
    let authenticated = archive_read::inspect_names_from_reader(&mut file, old_key, &entries)?.1;
    let output = destination(input, options)?;
    crypto::ensure_distinct(input, &output, options.key_file.as_deref())?;
    let bundle = binding(entries.len());
    let published = publication::write(&output, false, progress, |writer| {
        let mut zip = ZipWriter::new(writer);
        for entry in &entries {
            check(progress)?;
            let mut reader = archive_read::entry_reader(&mut file, entry, progress)?;
            let name = crypto::opaque_file_name().to_string_lossy().into_owned();
            zip.entry(&name, |sink| {
                crypto::rotate_named_reader(
                    old_key,
                    new_key,
                    &mut reader,
                    sink,
                    Some(bundle),
                    progress,
                )
            })?;
        }
        source.check()?;
        zip.finish(new_key, bundle)?;
        check(progress)
    })?;
    drop(file);
    let removal = if options.remove_original && authenticated {
        deletion::remove(source, std::slice::from_ref(&published), progress)
    } else if options.remove_original {
        Removal::retained(
            input,
            "Older ZIP retained because its complete file list is unauthenticated.",
        )
    } else {
        Removal::not_requested(input)
    };
    Ok(crypto::TransformOutcome {
        path: output,
        removal,
    })
}

pub(crate) const MANIFEST_MAGIC: &[u8; 4] = b"FEB1";
fn manifest_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut derived = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"FileEncrypt-Bundle-v1"), key)
        .expand(b"membership", derived.as_mut())
        .unwrap();
    derived
}
pub(crate) fn membership(entries: impl Iterator<Item = (String, u64, u32)>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for (name, size, crc) in entries {
        hash.update((name.len() as u32).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update(size.to_be_bytes());
        hash.update(crc.to_be_bytes());
    }
    hash.finalize().into()
}
pub(crate) fn verify_manifest(
    key: &[u8; 32],
    comment: &[u8],
    entries: &[archive_read::Entry],
) -> Result<Option<BundleBinding>, CryptoError> {
    if comment.is_empty() {
        return Ok(None);
    }
    if comment.len() != 88 || &comment[..4] != MANIFEST_MAGIC {
        return Err(CryptoError::AuthenticationFailed);
    }
    let derived = manifest_key(key);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(derived.as_slice()).unwrap();
    mac.update(&comment[..56]);
    mac.verify_slice(&comment[56..])
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let bundle = BundleBinding {
        id: comment[4..20].try_into().unwrap(),
        count: u32::from_be_bytes(comment[20..24].try_into().unwrap()),
    };
    if bundle.count as usize != entries.len()
        || comment[24..56] != membership(entries.iter().map(|e| (e.name.clone(), e.size, e.crc)))
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(Some(bundle))
}
struct Entry {
    name: String,
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
        let n = self.inner.write(bytes)?;
        self.position += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
struct EntryWriter<'a, 'b> {
    inner: &'a mut CountingWriter<'b>,
    hash: crc32fast::Hasher,
    size: u64,
}
impl Write for EntryWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.hash.update(&bytes[..n]);
        self.size += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
struct ZipWriter<'a> {
    writer: CountingWriter<'a>,
    entries: Vec<Entry>,
}
impl<'a> ZipWriter<'a> {
    fn new(inner: &'a mut dyn Write) -> Self {
        Self {
            writer: CountingWriter { inner, position: 0 },
            entries: Vec::new(),
        }
    }
    fn entry(
        &mut self,
        name: &str,
        produce: impl FnOnce(&mut dyn Write) -> Result<(), CryptoError>,
    ) -> Result<(), CryptoError> {
        let offset = self.writer.position;
        let w = &mut self.writer;
        w.write_all(&0x0403_4b50u32.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&8u16.to_le_bytes())?;
        w.write_all(&[0; 10])?;
        w.write_all(&u32::MAX.to_le_bytes())?;
        w.write_all(&u32::MAX.to_le_bytes())?;
        w.write_all(&(name.len() as u16).to_le_bytes())?;
        w.write_all(&20u16.to_le_bytes())?;
        w.write_all(name.as_bytes())?;
        w.write_all(&1u16.to_le_bytes())?;
        w.write_all(&16u16.to_le_bytes())?;
        w.write_all(&[0; 16])?;
        let mut sink = EntryWriter {
            inner: w,
            hash: crc32fast::Hasher::new(),
            size: 0,
        };
        produce(&mut sink)?;
        let size = sink.size;
        let crc = sink.hash.finalize();
        let w = &mut self.writer;
        w.write_all(&0x0807_4b50u32.to_le_bytes())?;
        w.write_all(&crc.to_le_bytes())?;
        w.write_all(&size.to_le_bytes())?;
        w.write_all(&size.to_le_bytes())?;
        self.entries.push(Entry {
            name: name.into(),
            size,
            crc,
            offset,
        });
        Ok(())
    }
    fn finish(&mut self, key: &[u8; 32], bundle: BundleBinding) -> Result<(), CryptoError> {
        let central_offset = self.writer.position;
        let w = &mut self.writer;
        for e in &self.entries {
            w.write_all(&0x0201_4b50u32.to_le_bytes())?;
            w.write_all(&45u16.to_le_bytes())?;
            w.write_all(&45u16.to_le_bytes())?;
            w.write_all(&8u16.to_le_bytes())?;
            w.write_all(&[0; 6])?;
            w.write_all(&e.crc.to_le_bytes())?;
            w.write_all(&u32::MAX.to_le_bytes())?;
            w.write_all(&u32::MAX.to_le_bytes())?;
            w.write_all(&(e.name.len() as u16).to_le_bytes())?;
            w.write_all(&28u16.to_le_bytes())?;
            w.write_all(&[0; 10])?;
            w.write_all(&u32::MAX.to_le_bytes())?;
            w.write_all(e.name.as_bytes())?;
            w.write_all(&1u16.to_le_bytes())?;
            w.write_all(&24u16.to_le_bytes())?;
            w.write_all(&e.size.to_le_bytes())?;
            w.write_all(&e.size.to_le_bytes())?;
            w.write_all(&e.offset.to_le_bytes())?;
        }
        let central_size = w.position - central_offset;
        let zip64_offset = w.position;
        w.write_all(&0x0606_4b50u32.to_le_bytes())?;
        w.write_all(&44u64.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&[0; 8])?;
        w.write_all(&(self.entries.len() as u64).to_le_bytes())?;
        w.write_all(&(self.entries.len() as u64).to_le_bytes())?;
        w.write_all(&central_size.to_le_bytes())?;
        w.write_all(&central_offset.to_le_bytes())?;
        w.write_all(&0x0706_4b50u32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&zip64_offset.to_le_bytes())?;
        w.write_all(&1u32.to_le_bytes())?;
        let mut comment = Vec::with_capacity(88);
        comment.extend_from_slice(MANIFEST_MAGIC);
        comment.extend_from_slice(&bundle.id);
        comment.extend_from_slice(&bundle.count.to_be_bytes());
        comment.extend_from_slice(&membership(
            self.entries.iter().map(|e| (e.name.clone(), e.size, e.crc)),
        ));
        let derived = manifest_key(key);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(derived.as_slice()).unwrap();
        mac.update(&comment);
        comment.extend_from_slice(&mac.finalize().into_bytes());
        w.write_all(&0x0605_4b50u32.to_le_bytes())?;
        w.write_all(&[0; 4])?;
        w.write_all(&u16::MAX.to_le_bytes())?;
        w.write_all(&u16::MAX.to_le_bytes())?;
        w.write_all(&u32::MAX.to_le_bytes())?;
        w.write_all(&u32::MAX.to_le_bytes())?;
        w.write_all(&(comment.len() as u16).to_le_bytes())?;
        w.write_all(&comment)?;
        Ok(())
    }
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
        let expected = if cfg!(windows) {
            crate::deletion::DeletionState::Removed
        } else {
            crate::deletion::DeletionState::Retained
        };
        assert!(result.removals.iter().all(|r| r.info.state == expected));
        assert_eq!(first.exists(), !cfg!(windows));
        assert_eq!(second.exists(), !cfg!(windows));
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
    fn strip_manifest(path: &Path) {
        let mut bytes = fs::read(path).unwrap();
        let eocd = bytes.len() - 110;
        assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06");
        bytes[eocd + 20..eocd + 22].copy_from_slice(&0u16.to_le_bytes());
        bytes.truncate(eocd + 22);
        fs::write(path, bytes).unwrap();
    }
    #[test]
    fn new_bundles_cannot_be_downgraded_by_removing_the_manifest() {
        let dir = TestDir::new();
        let input = dir.0.join("secret.txt");
        fs::write(&input, b"secret").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let zip = encrypt_to_zip(&[1; 32], &[input], &options).unwrap();
        strip_manifest(&zip.path);
        let entries = archive_read::entries(&zip.path).unwrap();
        assert!(archive_read::inspect_names(&zip.path, &[1; 32], &entries).is_err());
    }
    #[test]
    fn rebuilt_subset_with_the_original_manifest_fails_membership_verification() {
        let dir = TestDir::new();
        let left = dir.0.join("left.txt");
        let right = dir.0.join("right.txt");
        fs::write(&left, b"left").unwrap();
        fs::write(&right, b"right").unwrap();
        let key = [1; 32];
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let original = encrypt_to_zip(&key, &[left, right], &options).unwrap();
        let bytes = fs::read(&original.path).unwrap();
        let comment = &bytes[bytes.len() - 88..];
        let entries = archive_read::entries(&original.path).unwrap();
        let e = &entries[0];
        let ciphertext = &bytes[e.data_offset as usize..(e.data_offset + e.size) as usize];
        let rebuilt = dir.0.join("subset.zip");
        crypto::write_transformed(&rebuilt, false, |w| {
            let mut zip = ZipWriter::new(w);
            zip.entry(&e.name, |sink| {
                sink.write_all(ciphertext)?;
                Ok(())
            })?;
            zip.finish(&key, binding(1))
        })
        .unwrap();
        let mut rebuilt_bytes = fs::read(&rebuilt).unwrap();
        let at = rebuilt_bytes.len() - 88;
        rebuilt_bytes[at..].copy_from_slice(comment);
        fs::write(&rebuilt, rebuilt_bytes).unwrap();
        let subset = archive_read::entries(&rebuilt).unwrap();
        assert_eq!(subset.len(), 1);
        assert!(archive_read::inspect_names(&rebuilt, &key, &subset).is_err());
    }
    #[test]
    fn legacy_bundles_remain_readable_and_are_retained_after_rotation() {
        let dir = TestDir::new();
        let input = dir.0.join("secret.txt");
        fs::write(&input, b"legacy data").unwrap();
        let key = [1; 32];
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let encrypted = crypto::encrypt_file(&key, &input, &options).unwrap();
        let bytes = fs::read(&encrypted).unwrap();
        let legacy = dir.0.join("legacy.zip");
        crypto::write_transformed(&legacy, false, |w| {
            let mut zip = ZipWriter::new(w);
            zip.entry(encrypted.file_name().unwrap().to_str().unwrap(), |sink| {
                sink.write_all(&bytes)?;
                Ok(())
            })?;
            zip.finish(&key, binding(1))
        })
        .unwrap();
        strip_manifest(&legacy);
        let entries = archive_read::entries(&legacy).unwrap();
        assert_eq!(
            archive_read::inspect_names(&legacy, &key, &entries).unwrap(),
            ["secret.txt"]
        );
        let rotated = rotate_zip_with_progress(
            &key,
            &[2; 32],
            &legacy,
            &JobOptions {
                remove_original: true,
                ..options
            },
            None,
        )
        .unwrap();
        assert!(legacy.exists());
        let entries = archive_read::entries(&rotated).unwrap();
        assert_eq!(
            archive_read::inspect_names(&rotated, &[2; 32], &entries).unwrap(),
            ["secret.txt"]
        );
    }
    #[test]
    fn originals_cannot_change_between_entry_encryption_and_publication() {
        let dir = TestDir::new();
        let input = dir.0.join("source.txt");
        fs::write(&input, b"original").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let changed = std::sync::atomic::AtomicBool::new(false);
        let on_entry = |index: usize, _: &Path| {
            if index == 1 && fs::write(&input, b"changed after encryption").is_ok() {
                changed.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        };
        let result = encrypt_to_zip_with_progress(
            &[1; 32],
            std::slice::from_ref(&input),
            &options,
            None,
            false,
            None,
            Some(&on_entry),
        );
        if changed.load(std::sync::atomic::Ordering::Relaxed) {
            assert!(result.is_err());
            assert_eq!(fs::read(input).unwrap(), b"changed after encryption");
        } else {
            assert!(result.is_ok());
            assert_eq!(input.exists(), !cfg!(windows));
        }
    }
    #[test]
    fn cancelled_streaming_bundle_keeps_originals_and_publishes_nothing() {
        let dir = TestDir::new();
        let input = dir.0.join("source.bin");
        fs::write(&input, vec![9; 150_000]).unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let progress = |bytes: u64| -> io::Result<()> {
            if bytes > 0 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            } else {
                Ok(())
            }
        };
        assert!(encrypt_to_zip_with_progress(
            &[1; 32],
            std::slice::from_ref(&input),
            &options,
            None,
            true,
            Some(&progress),
            None
        )
        .is_err());
        assert!(input.exists());
        assert_eq!(
            fs::read_dir(options.output_dir.unwrap()).unwrap().count(),
            0
        );
    }
    #[test]
    fn bound_entries_preserve_the_legacy_relative_name_capacity() {
        let dir = TestDir::new();
        let input = dir.0.join("source.bin");
        fs::write(&input, b"data").unwrap();
        let name = format!("{}/{}.txt", "a".repeat(240), "b".repeat(257));
        assert_eq!(name.len(), 502);
        let source = Source::open(&input, false).unwrap();
        for compress in [false, true] {
            use std::io::{Seek, SeekFrom};
            source
                .file
                .try_clone()
                .unwrap()
                .seek(SeekFrom::Start(0))
                .unwrap();
            let mut bytes = Vec::new();
            let bound = binding(1);
            crypto::encrypt_bundle_reader(
                &[1; 32], &source, &name, compress, bound, &mut bytes, None,
            )
            .unwrap();
            let (restored, opened) =
                crypto::inspect_named_reader(&[1; 32], &mut std::io::Cursor::new(bytes)).unwrap();
            assert_eq!(restored, name);
            assert_eq!(opened, Some(bound));
        }
    }
    #[cfg(windows)]
    #[test]
    fn cancellation_during_original_cleanup_stops_the_remaining_deletions() {
        let dir = TestDir::new();
        let first = dir.0.join("first.txt");
        let second = dir.0.join("second.txt");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: Some(dir.0.join("out")),
        };
        let cancel_after_first = |_| {
            if !first.exists() {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "cancelled during cleanup",
                ))
            } else {
                Ok(())
            }
        };
        let result = encrypt_to_zip_with_progress(
            &[1; 32],
            &[first.clone(), second.clone()],
            &options,
            None,
            false,
            Some(&cancel_after_first),
            None,
        )
        .unwrap();
        assert_eq!(
            result.removals[0].info.state,
            crate::deletion::DeletionState::Removed
        );
        assert_eq!(
            result.removals[1].info.state,
            crate::deletion::DeletionState::Retained
        );
        assert!(!first.exists());
        assert!(second.exists());
        let entries = archive_read::entries(&result.path).unwrap();
        assert_eq!(
            archive_read::inspect_names(&result.path, &[1; 32], &entries)
                .unwrap()
                .len(),
            2
        );
    }
}
