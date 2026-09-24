//! Reads the stored, randomly named entries produced by this application's ZIP writer.
//! Refuses compressed entries and paths; no archive-controlled path is ever extracted.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{self, CryptoError, ProgressCallback};

#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub data_offset: u64,
    crc: u32,
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::NotAFile(format!("invalid FileEncrypt ZIP: {message}"))
}

fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn read_at<R: Read + Seek>(file: &mut R, offset: u64, bytes: &mut [u8]) -> Result<(), CryptoError> {
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(bytes)
        .map_err(|_| invalid("truncated archive"))
}

pub fn entries(path: &Path) -> Result<Vec<Entry>, CryptoError> {
    let mut file = File::open(path)?;
    entries_from_reader(&mut file)
}

pub fn entries_from_reader<R: Read + Seek>(mut file: &mut R) -> Result<Vec<Entry>, CryptoError> {
    let file_len = file.seek(SeekFrom::End(0))?;
    if file_len < 22 {
        return Err(invalid("missing ZIP directory"));
    }
    let tail_len = file_len.min(65_557) as usize;
    let mut tail = vec![0; tail_len];
    read_at(&mut file, file_len - tail_len as u64, &mut tail)?;
    let eocd = (0..=tail_len - 22)
        .rev()
        .find(|&i| {
            u32le(&tail, i) == 0x0605_4b50 && i + 22 + u16le(&tail, i + 20) as usize == tail_len
        })
        .ok_or_else(|| invalid("missing ZIP directory"))?;
    let eocd_offset = file_len - tail_len as u64 + eocd as u64;
    if u16le(&tail, eocd + 4) != 0 || u16le(&tail, eocd + 6) != 0 {
        return Err(invalid("multi-disk archives are unsupported"));
    }
    let mut count = u16le(&tail, eocd + 10) as u64;
    let mut central_size = u32le(&tail, eocd + 12) as u64;
    let mut central_offset = u32le(&tail, eocd + 16) as u64;
    if count == u16::MAX as u64
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
    {
        if eocd_offset < 20 {
            return Err(invalid("missing ZIP64 locator"));
        }
        let mut locator = [0; 20];
        read_at(&mut file, eocd_offset - 20, &mut locator)?;
        if u32le(&locator, 0) != 0x0706_4b50 {
            return Err(invalid("missing ZIP64 locator"));
        }
        let zip64_offset = u64le(&locator, 8);
        let mut record = [0; 56];
        read_at(&mut file, zip64_offset, &mut record)?;
        if u32le(&record, 0) != 0x0606_4b50 {
            return Err(invalid("bad ZIP64 directory"));
        }
        count = u64le(&record, 32);
        central_size = u64le(&record, 40);
        central_offset = u64le(&record, 48);
    }
    if count == 0 || count > 10_000 {
        return Err(invalid("entry count is unsupported"));
    }
    let central_end = central_offset
        .checked_add(central_size)
        .ok_or_else(|| invalid("directory overflow"))?;
    if central_end > file_len {
        return Err(invalid("directory exceeds archive"));
    }
    let mut cursor = central_offset;
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if cursor.checked_add(46).is_none_or(|end| end > central_end) {
            return Err(invalid("truncated entry directory"));
        }
        let mut header = [0; 46];
        read_at(&mut file, cursor, &mut header)?;
        if u32le(&header, 0) != 0x0201_4b50 {
            return Err(invalid("bad entry directory"));
        }
        let flags = u16le(&header, 8);
        if flags & !0x0808 != 0 || u16le(&header, 10) != 0 {
            return Err(invalid(
                "only uncompressed, unencrypted ZIP entries are supported",
            ));
        }
        let name_len = u16le(&header, 28) as usize;
        let extra_len = u16le(&header, 30) as usize;
        let comment_len = u16le(&header, 32) as usize;
        let next = cursor
            .checked_add(46 + name_len as u64 + extra_len as u64 + comment_len as u64)
            .ok_or_else(|| invalid("entry directory overflow"))?;
        if next > central_end || name_len != 37 {
            return Err(invalid("unexpected entry name"));
        }
        let mut variable = vec![0; name_len + extra_len];
        read_at(&mut file, cursor + 46, &mut variable)?;
        let name = std::str::from_utf8(&variable[..name_len])
            .map_err(|_| invalid("entry name is not text"))?;
        if !name.ends_with(".fenc") || !name[..32].bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("entry is not a FileEncrypt file"));
        }
        let mut size = u32le(&header, 24) as u64;
        let compressed = u32le(&header, 20) as u64;
        let mut local_offset = u32le(&header, 42) as u64;
        if size == u32::MAX as u64
            || compressed == u32::MAX as u64
            || local_offset == u32::MAX as u64
        {
            let mut pos = name_len;
            let mut found = false;
            while pos + 4 <= variable.len() {
                let kind = u16le(&variable, pos);
                let len = u16le(&variable, pos + 2) as usize;
                pos += 4;
                if pos + len > variable.len() {
                    return Err(invalid("bad ZIP64 extra field"));
                }
                if kind == 1 {
                    let mut part = pos;
                    if size == u32::MAX as u64 {
                        if part + 8 > pos + len {
                            return Err(invalid("missing ZIP64 size"));
                        }
                        size = u64le(&variable, part);
                        part += 8;
                    }
                    if compressed == u32::MAX as u64 {
                        if part + 8 > pos + len {
                            return Err(invalid("missing ZIP64 compressed size"));
                        }
                        if u64le(&variable, part) != size {
                            return Err(invalid("compressed entry"));
                        }
                        part += 8;
                    }
                    if local_offset == u32::MAX as u64 {
                        if part + 8 > pos + len {
                            return Err(invalid("missing ZIP64 offset"));
                        }
                        local_offset = u64le(&variable, part);
                    }
                    found = true;
                    break;
                }
                pos += len;
            }
            if !found {
                return Err(invalid("missing ZIP64 extra field"));
            }
        } else if compressed != size {
            return Err(invalid("compressed entry"));
        }
        let mut local = [0; 30];
        read_at(&mut file, local_offset, &mut local)?;
        if u32le(&local, 0) != 0x0403_4b50 || u16le(&local, 8) != 0 {
            return Err(invalid("bad local entry"));
        }
        let local_name_len = u16le(&local, 26) as usize;
        let local_extra_len = u16le(&local, 28) as usize;
        if local_name_len != name_len {
            return Err(invalid("entry names disagree"));
        }
        let data_offset = local_offset
            .checked_add(30 + local_name_len as u64 + local_extra_len as u64)
            .ok_or_else(|| invalid("entry offset overflow"))?;
        if data_offset
            .checked_add(size)
            .is_none_or(|end| end > central_offset)
        {
            return Err(invalid("entry exceeds data section"));
        }
        let mut local_name = vec![0; local_name_len];
        read_at(&mut file, local_offset + 30, &mut local_name)?;
        if local_name != variable[..name_len] {
            return Err(invalid("entry names disagree"));
        }
        result.push(Entry {
            name: name.to_owned(),
            size,
            data_offset,
            crc: u32le(&header, 16),
        });
        cursor = next;
    }
    if cursor != central_end {
        return Err(invalid("unexpected directory data"));
    }
    Ok(result)
}

pub fn inspect_names(
    path: &Path,
    key: &[u8; 32],
    entries: &[Entry],
) -> Result<Vec<String>, CryptoError> {
    let mut file = File::open(path)?;
    entries
        .iter()
        .map(|entry| {
            file.seek(SeekFrom::Start(entry.data_offset))?;
            let mut limited = (&mut file).take(entry.size);
            crypto::named_file_name_from_reader(key, &mut limited)
        })
        .collect()
}

pub fn extract_entry(
    archive: &Path,
    entry: &Entry,
    destination: &Path,
    callback: Option<&ProgressCallback<'_>>,
) -> Result<(), CryptoError> {
    let mut source = File::open(archive)?;
    source.seek(SeekFrom::Start(entry.data_offset))?;
    let mut limited = source.take(entry.size);
    let mut target = File::create(destination)?;
    let mut hasher = crc32fast::Hasher::new();
    let mut copied = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        if let Some(callback) = callback {
            callback(0)?;
        }
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        target.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        copied += count as u64;
        if let Some(callback) = callback {
            callback(count as u64)?;
        }
    }
    target.sync_all()?;
    if copied != entry.size || hasher.finalize() != entry.crc {
        let _ = fs::remove_file(destination);
        return Err(invalid("entry checksum or length changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive;
    use crate::crypto::JobOptions;

    #[test]
    fn fuzz_seed_parses_and_truncations_do_not_panic() {
        let seed = include_bytes!("../../fuzz/corpus/zip_reader/one-entry.zip");
        assert_eq!(
            entries_from_reader(&mut std::io::Cursor::new(seed))
                .unwrap()
                .len(),
            1
        );
        for len in 0..seed.len() {
            let _ = entries_from_reader(&mut std::io::Cursor::new(&seed[..len]));
        }
    }

    #[test]
    fn app_zip_can_be_inspected_extracted_and_decrypted() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-read-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("secret.txt");
        fs::write(&source, b"zip round trip").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(root.clone()),
        };
        let key = [29u8; 32];
        let zipped = archive::encrypt_to_zip(&key, &[source], &options).unwrap();
        let found = entries(&zipped.path).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            inspect_names(&zipped.path, &key, &found).unwrap(),
            ["secret.txt"]
        );
        let staged = root.join(&found[0].name);
        extract_entry(&zipped.path, &found[0], &staged, None).unwrap();
        crypto::verify_file(&key, &staged, None).unwrap();
        let output_dir = root.join("restored");
        let restored = crypto::decrypt_file(
            &key,
            &staged,
            &JobOptions {
                output_dir: Some(output_dir),
                ..options
            },
        )
        .unwrap();
        assert_eq!(fs::read(restored).unwrap(), b"zip round trip");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unexpected_entry_name() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-badzip-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("a.txt");
        fs::write(&source, b"a").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(root.clone()),
        };
        let zipped = archive::encrypt_to_zip(&[3; 32], &[source], &options).unwrap();
        let mut bytes = fs::read(&zipped.path).unwrap();
        let central = bytes
            .windows(4)
            .position(|part| part == b"PK\x01\x02")
            .unwrap();
        bytes[central + 46] = b'/';
        fs::write(&zipped.path, bytes).unwrap();
        assert!(entries(&zipped.path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_changed_entry_and_removes_staging_file() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-tamperedzip-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("a.txt");
        fs::write(&source, b"important data").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(root.clone()),
        };
        let zipped = archive::encrypt_to_zip(&[3; 32], &[source], &options).unwrap();
        let found = entries(&zipped.path).unwrap();
        let mut bytes = fs::read(&zipped.path).unwrap();
        let last = (found[0].data_offset + found[0].size - 1) as usize;
        bytes[last] ^= 1;
        fs::write(&zipped.path, bytes).unwrap();
        let staged = root.join(&found[0].name);
        assert!(extract_entry(&zipped.path, &found[0], &staged, None).is_err());
        assert!(!staged.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
