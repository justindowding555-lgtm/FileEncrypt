use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError, JobOptions};
use crate::key_file;

pub struct AppState {
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    key_path: Mutex<Option<PathBuf>>,
    output_dir: Mutex<Option<PathBuf>>,
    message: Mutex<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            key: Mutex::new(None),
            key_path: Mutex::new(None),
            output_dir: Mutex::new(None),
            message: Mutex::new(String::new()),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    key_loaded: bool,
    key_path: Option<String>,
    output_dir: Option<String>,
    fingerprint: Option<String>,
    message: String,
}

#[derive(Serialize)]
pub struct FileOutcome {
    input: String,
    output: Option<String>,
    ok: bool,
    message: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Settings {
    #[serde(default)]
    key_path: Option<PathBuf>,
    #[serde(default)]
    output_dir: Option<PathBuf>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub fn restore_saved_key(app: &tauri::AppHandle, state: &AppState) {
    let Some(settings) = read_settings(app) else {
        return;
    };
    *lock(&state.output_dir) = settings.output_dir;
    let Some(path) = settings.key_path else {
        return;
    };
    *lock(&state.key_path) = Some(path.clone());
    match key_file::read_key_file(&path) {
        Ok(key) => {
            *lock(&state.key) = Some(key);
            set_message(state, "Key loaded from the saved location.");
        }
        Err(err) => set_message(state, format!("Could not load the saved key: {err}")),
    }
}

#[tauri::command]
pub fn get_status(state: tauri::State<'_, AppState>) -> AppStatus {
    status(&state)
}

#[tauri::command]
pub async fn pick_input_files(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(files) = dialog.set_title("Choose files").blocking_pick_files() else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::with_capacity(files.len());
    for file in files {
        paths.push(
            file.into_path()
                .map_err(|err| err.to_string())?
                .display()
                .to_string(),
        );
    }
    Ok(paths)
}

#[tauri::command]
pub async fn pick_save_path(app: tauri::AppHandle) -> Result<Option<String>, String> {
    Ok(pick_save(&app)?.map(|path| path.display().to_string()))
}

#[tauri::command]
pub fn set_output_dir(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<AppStatus, String> {
    let dir = output_directory(&path)?;
    store_output_dir(&app, &state, dir);
    Ok(status(&state))
}

#[tauri::command]
pub async fn pick_output_dir(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, String> {
    let Some(path) = pick_folder(&app)? else {
        return Ok(None);
    };
    store_output_dir(&app, &state, Some(path.clone()));
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
pub async fn generate_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<AppStatus, String> {
    let Some(path) = resolve_save_path(&app, &path)? else {
        set_message(&state, "Key file was not created.");
        return Ok(status(&state));
    };
    if path.is_dir() {
        return Err("Choose a file path for the key, not a folder.".into());
    }
    if path.exists() && !confirm_replace(&app, &path) {
        set_message(&state, "Existing key file was left unchanged.");
        return Ok(status(&state));
    }
    let key = key_file::generate_key();
    key_file::write_key_file(&path, &key).map_err(|err| err.to_string())?;
    let extra = remember_key(&app, &state, path, key);
    set_message(&state, format!("New key generated and saved.{extra}"));
    Ok(status(&state))
}

#[tauri::command]
pub async fn save_typed_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    mut key_text: String,
) -> Result<AppStatus, String> {
    let parsed = key_file::parse_key_material(&key_text);
    key_text.zeroize();
    let key = parsed.map_err(|err| err.to_string())?;
    let Some(path) = resolve_save_path(&app, &path)? else {
        set_message(&state, "Key file was not written.");
        return Ok(status(&state));
    };
    if path.is_dir() {
        return Err("Choose a file path for the key, not a folder.".into());
    }
    if path.exists() && !confirm_replace(&app, &path) {
        set_message(&state, "Existing key file was left unchanged.");
        return Ok(status(&state));
    }
    key_file::write_key_file(&path, &key).map_err(|err| err.to_string())?;
    let extra = remember_key(&app, &state, path, key);
    set_message(&state, format!("Key written to the file.{extra}"));
    Ok(status(&state))
}

#[tauri::command]
pub async fn load_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
) -> Result<AppStatus, String> {
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("Enter a key file path, or use Browse and load.".into());
    }
    finish_load(&app, &state, PathBuf::from(path))
}

#[tauri::command]
pub async fn browse_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<AppStatus, String> {
    let Some(path) = pick_open(&app)? else {
        set_message(&state, "No key file was opened.");
        return Ok(status(&state));
    };
    finish_load(&app, &state, path)
}

#[tauri::command]
pub fn unload_key(state: tauri::State<'_, AppState>) -> AppStatus {
    *lock(&state.key) = None;
    set_message(
        &state,
        "Key unloaded from memory. The key file was not deleted.",
    );
    status(&state)
}

#[tauri::command]
pub fn encrypt_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
    output_dir: String,
    overwrite: bool,
    remove_original: bool,
) -> Result<Vec<FileOutcome>, String> {
    process(&app, &state, paths, &output_dir, overwrite, remove_original, true)
}

#[tauri::command]
pub fn decrypt_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    paths: Vec<String>,
    output_dir: String,
    overwrite: bool,
    remove_original: bool,
) -> Result<Vec<FileOutcome>, String> {
    process(
        &app,
        &state,
        paths,
        &output_dir,
        overwrite,
        remove_original,
        false,
    )
}

fn finish_load(
    app: &tauri::AppHandle,
    state: &AppState,
    path: PathBuf,
) -> Result<AppStatus, String> {
    let key = key_file::read_key_file(&path).map_err(|err| err.to_string())?;
    let extra = remember_key(app, state, path, key);
    set_message(state, format!("Key loaded.{extra}"));
    Ok(status(state))
}

fn process(
    app: &tauri::AppHandle,
    state: &AppState,
    paths: Vec<String>,
    output_dir: &str,
    overwrite: bool,
    remove_original: bool,
    encrypt: bool,
) -> Result<Vec<FileOutcome>, String> {
    if paths.is_empty() {
        return Err("Add at least one file.".into());
    }
    let Some(key) = lock(&state.key).clone() else {
        return Err("Load or create an encryption key first.".into());
    };
    let output_dir = output_directory(output_dir)?;
    store_output_dir(app, state, output_dir.clone());
    let options = JobOptions {
        overwrite,
        remove_original,
        key_file: lock(&state.key_path).clone(),
        output_dir,
    };
    Ok(paths
        .into_iter()
        .map(|path| one_file(&key, path, &options, encrypt))
        .collect())
}

fn one_file(key: &[u8; 32], path: String, options: &JobOptions, encrypt: bool) -> FileOutcome {
    let input = PathBuf::from(&path);
    let result = if encrypt {
        crypto::encrypt_file(key, &input, options)
    } else {
        crypto::decrypt_file(key, &input, options)
    };
    match result {
        Ok(output) => FileOutcome {
            input: path,
            output: Some(output.display().to_string()),
            ok: true,
            message: if encrypt {
                "Encrypted".into()
            } else {
                "Decrypted".into()
            },
        },
        Err(CryptoError::OriginalRemains { output, source }) => FileOutcome {
            input: path,
            output: Some(output),
            ok: false,
            message: format!(
                "The new file was written, but the original could not be deleted: {source}"
            ),
        },
        Err(err) => FileOutcome {
            input: path,
            output: None,
            ok: false,
            message: err.to_string(),
        },
    }
}

fn status(state: &AppState) -> AppStatus {
    let (key_loaded, fingerprint) = {
        let key = lock(&state.key);
        (
            key.is_some(),
            key.as_ref().map(|value| key_file::fingerprint(value.as_slice())),
        )
    };
    let key_path = lock(&state.key_path)
        .as_ref()
        .map(|path| path.display().to_string());
    let output_dir = lock(&state.output_dir)
        .as_ref()
        .map(|path| path.display().to_string());
    let message = lock(&state.message).clone();
    AppStatus {
        key_loaded,
        key_path,
        output_dir,
        fingerprint,
        message,
    }
}

fn output_directory(path: &str) -> Result<Option<PathBuf>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    let dir = PathBuf::from(path);
    if dir.exists() && !dir.is_dir() {
        return Err(format!("{} is a file. Choose a folder.", dir.display()));
    }
    Ok(Some(dir))
}

fn store_output_dir(app: &tauri::AppHandle, state: &AppState, output_dir: Option<PathBuf>) {
    *lock(&state.output_dir) = output_dir;
    let _ = write_settings(app, state);
}

fn set_message(state: &AppState, message: impl Into<String>) {
    *lock(&state.message) = message.into();
}

fn remember_key(
    app: &tauri::AppHandle,
    state: &AppState,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
) -> String {
    *lock(&state.key) = Some(key);
    *lock(&state.key_path) = Some(path.clone());
    match write_settings(app, state) {
        Ok(()) => String::new(),
        Err(err) => format!(" The path could not be remembered for next launch: {err}"),
    }
}

fn resolve_save_path(app: &tauri::AppHandle, path: &str) -> Result<Option<PathBuf>, String> {
    let path = path.trim();
    if path.is_empty() {
        pick_save(app)
    } else {
        Ok(Some(PathBuf::from(path)))
    }
}

fn pick_folder(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog
        .set_title("Choose output folder")
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    picked.into_path().map(Some).map_err(|err| err.to_string())
}

fn pick_save(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog
        .set_title("Save encryption key")
        .set_file_name("fileencrypt.key")
        .add_filter("Key file", &["key"])
        .add_filter("All files", &["*"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    picked.into_path().map(Some).map_err(|err| err.to_string())
}

fn pick_open(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog
        .set_title("Open encryption key")
        .add_filter("Key file", &["key"])
        .add_filter("All files", &["*"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    picked.into_path().map(Some).map_err(|err| err.to_string())
}

fn confirm_replace(app: &tauri::AppHandle, path: &Path) -> bool {
    app.dialog()
        .message(format!(
            "Replace the existing key file?\n\n{}\n\nFiles already encrypted with the key in that file will not open with the new key.",
            path.display()
        ))
        .title("Replace key file")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show()
}

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|err| err.to_string())?;
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir.join("settings.json"))
}

fn write_settings(app: &tauri::AppHandle, state: &AppState) -> Result<(), String> {
    let settings = Settings {
        key_path: lock(&state.key_path).clone(),
        output_dir: lock(&state.output_dir).clone(),
    };
    let json = serde_json::to_string_pretty(&settings).map_err(|err| err.to_string())?;
    fs::write(settings_path(app)?, json).map_err(|err| err.to_string())
}

fn read_settings(app: &tauri::AppHandle) -> Option<Settings> {
    let path = settings_path(app).ok()?;
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}
