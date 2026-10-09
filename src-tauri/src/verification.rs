//! Background authentication without outputs, deletion, or retained plaintext.
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use serde::Serialize;
use tauri::Manager;

use crate::commands::{lock, AppState};
use crate::{archive_read, crypto, source::Source};

#[derive(Default)]
pub struct VerificationState {
    pub(crate) work: Mutex<()>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    input: String,
    state: &'static str,
    message: String,
    entry_count: usize,
    complete: bool,
}

fn check(state: &AppState, revision: u64) -> io::Result<()> {
    if state.key_revision.load(Ordering::Acquire) != revision
        || state.running.load(Ordering::Acquire)
    {
        return Err(io::Error::new(
            // read_exact retries Interrupted; propagate the pause so foreground
            // jobs can acquire the work lock and release protected file handles.
            io::ErrorKind::WouldBlock,
            "Verification paused.",
        ));
    }
    Ok(())
}

struct CheckedReader<'a> {
    file: &'a mut File,
    state: &'a AppState,
    revision: u64,
}
impl Read for CheckedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        check(self.state, self.revision)?;
        self.file.read(bytes)
    }
}
impl Seek for CheckedReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        check(self.state, self.revision)?;
        self.file.seek(position)
    }
}

fn authenticate(
    state: &AppState,
    key: &[u8; 32],
    revision: u64,
    path: &Path,
) -> Result<(usize, bool), crypto::CryptoError> {
    check(state, revision)?;
    let mut source = Source::open(path, false)?;
    let mut reader = BufReader::new(CheckedReader {
        file: &mut source.file,
        state,
        revision,
    });
    let result = if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
    {
        let entries = archive_read::entries_from_reader(&mut reader)?;
        if entries.is_empty() {
            return Err(crypto::CryptoError::NotAFile(
                "The ZIP contains no encrypted files to verify.".into(),
            ));
        }
        let (_, complete) = archive_read::inspect_names_from_reader(&mut reader, key, &entries)?;
        for entry in &entries {
            check(state, revision)?;
            let mut member = archive_read::entry_reader(&mut reader, entry, None)?;
            crypto::verify_named_reader(key, &mut member)?;
        }
        (entries.len(), complete)
    } else {
        crypto::verify_reader(key, path, &mut reader, &mut io::sink())?;
        (1, true)
    };
    drop(reader);
    source.check()?;
    check(state, revision)?;
    Ok(result)
}

fn verify(state: &AppState, revision: u64, paths: Vec<String>) -> Vec<VerificationResult> {
    let key = {
        let _change = lock(&state.key_change);
        if check(state, revision).is_ok() {
            lock(&state.key).clone()
        } else {
            None
        }
    };
    paths.into_iter().map(|input| {
        let result = key.as_ref().map(|key| authenticate(state, key, revision, Path::new(&input)));
        let (status, message, entry_count, complete) = match result {
            Some(Ok((count, complete))) => ("verified", if complete {
                if count == 1 { "Authenticated with the loaded key.".into() }
                else { format!("All {count} files and the ZIP file list authenticated with the loaded key.") }
            } else { format!("All {count} entries authenticated. This older ZIP's complete file list cannot be authenticated.") }, count, complete),
            _ if key.is_none() || check(state, revision).is_err() => ("pending", "Waiting to verify with the loaded key.".into(), 0, false),
            Some(Err(error)) => ("failed", error.to_string(), 0, false),
            None => unreachable!(),
        };
        VerificationResult { input, state: status, message, entry_count, complete }
    }).collect()
}

#[tauri::command]
pub async fn verify_selected_files(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    key_revision: u64,
    paths: Vec<String>,
) -> Result<Vec<VerificationResult>, String> {
    if window.label() != "main" || paths.is_empty() || paths.len() > 32 {
        return Err("Verify between 1 and 32 selected files from the main window.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let verifier = app.state::<VerificationState>();
        let _work = lock(&verifier.work);
        verify(&app.state::<AppState>(), key_revision, paths)
    })
    .await
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive, crypto::JobOptions, test_support::TestDir};
    use std::fs;
    use zeroize::Zeroizing;

    fn loaded() -> AppState {
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new([42; 32]));
        state.key_revision.store(1, Ordering::Release);
        state
    }

    fn options() -> JobOptions {
        JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        }
    }

    #[test]
    fn automatic_verification_authenticates_each_file_without_creating_outputs() {
        let dir = TestDir::new();
        let input = dir.0.join("private.txt");
        fs::write(&input, b"private contents").unwrap();
        let encrypted = crypto::encrypt_file(&[42; 32], &input, &options()).unwrap();
        let wrong_key = crypto::encrypt_file(&[43; 32], &input, &options()).unwrap();
        let before = fs::read_dir(&dir.0).unwrap().count();
        let results = verify(
            &loaded(),
            1,
            vec![
                encrypted.display().to_string(),
                wrong_key.display().to_string(),
            ],
        );
        assert_eq!(results[0].state, "verified");
        assert_eq!(results[0].entry_count, 1);
        assert_eq!(results[1].state, "failed");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), before);
        assert_eq!(fs::read(&input).unwrap(), b"private contents");
    }

    #[test]
    fn a_zip_gets_a_checkmark_only_when_every_entry_authenticates() {
        let dir = TestDir::new();
        let inputs: Vec<_> = ["one.txt", "two.txt"]
            .into_iter()
            .map(|name| {
                let input = dir.0.join(name);
                fs::write(&input, name.as_bytes()).unwrap();
                input
            })
            .collect();
        let zip = archive::encrypt_to_zip_with_progress(
            &[42; 32],
            &inputs,
            &options(),
            Some(&dir.0),
            true,
            None,
            None,
        )
        .unwrap();
        let before = fs::read_dir(&dir.0).unwrap().count();
        let state = loaded();
        let result = verify(&state, 1, vec![zip.path.display().to_string()]).remove(0);
        assert_eq!(result.state, "verified");
        assert_eq!(result.entry_count, 2);
        assert!(result.complete);
        let entries = archive_read::entries(&zip.path).unwrap();
        let last = &entries[1];
        let mut bytes = fs::read(&zip.path).unwrap();
        bytes[(last.data_offset + last.size - 1) as usize] ^= 1;
        fs::write(&zip.path, bytes).unwrap();
        assert_eq!(
            verify(&state, 1, vec![zip.path.display().to_string()])[0].state,
            "failed"
        );
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), before);
    }

    #[test]
    fn key_changes_and_foreground_jobs_pause_the_background_checker() {
        let dir = TestDir::new();
        let input = dir.0.join("private.txt");
        fs::write(&input, b"private contents").unwrap();
        let encrypted = crypto::encrypt_file(&[42; 32], &input, &options()).unwrap();
        let state = loaded();
        state.running.store(true, Ordering::Release);
        assert_eq!(
            verify(&state, 1, vec![encrypted.display().to_string()])[0].state,
            "pending"
        );
        state.running.store(false, Ordering::Release);
        state.key_revision.store(2, Ordering::Release);
        assert_eq!(
            verify(&state, 1, vec![encrypted.display().to_string()])[0].state,
            "pending"
        );
        let mut file = File::open(encrypted).unwrap();
        let mut reader = CheckedReader {
            file: &mut file,
            state: &state,
            revision: 2,
        };
        assert_eq!(reader.read(&mut [0; 4]).unwrap(), 4);
        state.running.store(true, Ordering::Release);
        assert_eq!(
            reader.read_exact(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
