//! Remember the Files list independently of keys and decrypted sandbox data.
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::commands::{lock, AppState};

const MAX_FILES: usize = 10_000;
const MAX_SAVED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub struct SelectionStore {
    revision: Mutex<u64>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct FileSelection {
    paths: Vec<String>,
    #[serde(default)]
    roots: HashMap<String, String>,
}

impl FileSelection {
    fn normalize(mut self) -> Result<Self, String> {
        if self.paths.len() > MAX_FILES {
            return Err("FileEncrypt can remember up to 10,000 selected files.".into());
        }
        let mut seen = HashSet::new();
        self.paths
            .retain(|path| !path.is_empty() && seen.insert(path.clone()));
        self.roots
            .retain(|path, root| seen.contains(path) && !root.is_empty());
        Ok(self)
    }
}

fn selection_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir.join("selected-files.json"))
}

fn read_selection(path: &Path) -> Result<FileSelection, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileSelection::default());
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SAVED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_SAVED_BYTES {
        return Err("The remembered file selection is too large to restore.".into());
    }
    serde_json::from_slice::<FileSelection>(&bytes)
        .map_err(|error| error.to_string())?
        .normalize()
}

fn write_selection(
    store: &SelectionStore,
    path: &Path,
    revision: u64,
    selection: FileSelection,
) -> Result<(), String> {
    let selection = selection.normalize()?;
    let bytes = serde_json::to_vec(&selection).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_SAVED_BYTES {
        return Err("The file selection is too large to remember.".into());
    }
    let mut latest = lock(&store.revision);
    if revision <= *latest {
        return Ok(());
    }
    // Async IPC calls can arrive out of order. Never let an older selection
    // undo a newer Remove or Clear list, even if its write fails.
    *latest = revision;
    crate::crypto::atomic_write(path, &bytes).map_err(|error| error.to_string())
}

fn restore_selection(state: &AppState, path: &Path) -> Result<Option<FileSelection>, String> {
    if lock(&state.key).is_none() || lock(&state.key_path).is_none() {
        return Ok(None);
    }
    read_selection(path).map(Some)
}

#[tauri::command]
pub async fn remember_selected_files(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    revision: u64,
    selection: FileSelection,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Update the file selection from the main window.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        write_selection(
            &app.state::<SelectionStore>(),
            &selection_path(&app)?,
            revision,
            selection,
        )
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn restore_selected_files(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Option<FileSelection>, String> {
    if window.label() != "main" {
        return Err("Restore the file selection in the main window.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        restore_selection(&state, &selection_path(&app)?)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use zeroize::Zeroizing;

    fn selection() -> FileSelection {
        FileSelection {
            paths: vec![
                "E:/encrypted/notes.fenc".into(),
                "E:/encrypted/photos.zip".into(),
            ],
            roots: HashMap::from([("E:/encrypted/notes.fenc".into(), "E:/encrypted".into())]),
        }
    }

    #[test]
    fn selection_round_trips_across_launches_after_loading_a_saved_key() {
        let dir = TestDir::new();
        let path = dir.0.join("selected-files.json");
        write_selection(&SelectionStore::default(), &path, 1, selection()).unwrap();
        let reopened = AppState::default();
        assert!(restore_selection(&reopened, &path).unwrap().is_none());
        *lock(&reopened.key) = Some(Zeroizing::new([42; 32]));
        assert!(
            restore_selection(&reopened, &path).unwrap().is_none(),
            "session keys do not restore a saved selection"
        );
        *lock(&reopened.key_path) = Some(dir.0.join("saved.key"));
        let restored = restore_selection(&reopened, &path).unwrap().unwrap();
        assert_eq!(restored.paths, selection().paths);
        assert_eq!(restored.roots, selection().roots);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn newer_removals_and_clear_cannot_be_undone_by_delayed_saves() {
        let dir = TestDir::new();
        let path = dir.0.join("selected-files.json");
        let store = SelectionStore::default();
        write_selection(&store, &path, 1, selection()).unwrap();
        let mut removed = selection();
        removed.paths.remove(0);
        write_selection(&store, &path, 3, removed).unwrap();
        write_selection(&store, &path, 2, selection()).unwrap();
        let restored = read_selection(&path).unwrap();
        assert_eq!(restored.paths, vec!["E:/encrypted/photos.zip"]);
        assert!(restored.roots.is_empty());
        write_selection(&store, &path, 5, FileSelection::default()).unwrap();
        write_selection(&store, &path, 4, selection()).unwrap();
        assert!(read_selection(&path).unwrap().paths.is_empty());
        // The next app launch starts a fresh revision sequence.
        write_selection(&SelectionStore::default(), &path, 1, selection()).unwrap();
        assert_eq!(read_selection(&path).unwrap().paths, selection().paths);
    }

    #[test]
    fn missing_lists_and_older_path_only_lists_restore_without_errors() {
        let dir = TestDir::new();
        let path = dir.0.join("selected-files.json");
        assert!(read_selection(&path).unwrap().paths.is_empty());
        fs::write(
            &path,
            br#"{"paths":["E:/notes.fenc","E:/notes.fenc","","E:/photos.zip"]}"#,
        )
        .unwrap();
        let restored = read_selection(&path).unwrap();
        assert_eq!(restored.paths, vec!["E:/notes.fenc", "E:/photos.zip"]);
        assert!(restored.roots.is_empty());
    }

    #[test]
    fn oversized_or_corrupt_lists_do_not_replace_a_saved_selection() {
        let dir = TestDir::new();
        let path = dir.0.join("selected-files.json");
        let store = SelectionStore::default();
        write_selection(&store, &path, 1, selection()).unwrap();
        let oversized = FileSelection {
            paths: vec!["E:/file.fenc".into(); MAX_FILES + 1],
            roots: HashMap::new(),
        };
        assert!(write_selection(&store, &path, 2, oversized).is_err());
        assert_eq!(read_selection(&path).unwrap().paths, selection().paths);
        fs::write(&path, b"{interrupted").unwrap();
        assert!(read_selection(&path).is_err());
    }
}
