use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use zeroize::{Zeroize, Zeroizing};

use crate::archive;
use crate::archive_read;
use crate::crypto::{self, CryptoError, JobOptions};
use crate::key_file;

pub struct AppState {
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    key_path: Mutex<Option<PathBuf>>,
    output_dir: Mutex<Option<PathBuf>>,
    message: Mutex<String>,
    running: AtomicBool,
    cancelled: AtomicBool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            key: Mutex::new(None),
            key_path: Mutex::new(None),
            output_dir: Mutex::new(None),
            message: Mutex::new(String::new()),
            running: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
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

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRequest {
    paths: Vec<String>,
    output_dir: String,
    overwrite: bool,
    remove_original: bool,
    zip: bool,
    operation: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewItem {
    input: String,
    output: String,
    bytes: u64,
    issue: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobPreview {
    items: Vec<PreviewItem>,
    warnings: Vec<String>,
    can_run: bool,
    total_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobProgress {
    processed_bytes: u64,
    total_bytes: u64,
    current_file: String,
    file_index: usize,
    file_count: usize,
    stage: String,
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
pub async fn pick_input_folder(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog
        .set_title("Choose a folder of files")
        .blocking_pick_folder()
    else {
        return Ok(Vec::new());
    };
    let folder = picked.into_path().map_err(|err| err.to_string())?;
    expand_paths(vec![folder.display().to_string()])
}

#[tauri::command]
pub fn expand_dropped_paths(paths: Vec<String>) -> Result<Vec<String>, String> {
    expand_paths(paths)
}

fn expand_paths(paths: Vec<String>) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut pending = paths.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    while let Some(path) = pending.pop() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            if found.len() >= 10_000 {
                return Err("Select fewer than 10,000 files at once.".into());
            }
            found.push(path.display().to_string());
        } else if metadata.is_dir() {
            let mut children = fs::read_dir(&path)
                .map_err(|err| format!("{}: {err}", path.display()))?
                .map(|entry| entry.map(|item| item.path()).map_err(|err| err.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            children.sort();
            pending.extend(children.into_iter().rev());
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
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
    mut passphrase: Option<String>,
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
    let written = if let Some(value) = passphrase.as_deref().filter(|value| !value.is_empty()) {
        key_file::write_protected_key_file(&path, &key, value)
    } else {
        key_file::write_key_file(&path, &key)
    };
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    written.map_err(|err| err.to_string())?;
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
    mut passphrase: Option<String>,
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
    let written = if let Some(value) = passphrase.as_deref().filter(|value| !value.is_empty()) {
        key_file::write_protected_key_file(&path, &key, value)
    } else {
        key_file::write_key_file(&path, &key)
    };
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    written.map_err(|err| err.to_string())?;
    let extra = remember_key(&app, &state, path, key);
    set_message(&state, format!("Key written to the file.{extra}"));
    Ok(status(&state))
}

#[tauri::command]
pub async fn load_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    mut passphrase: Option<String>,
) -> Result<AppStatus, String> {
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("Enter a key file path, or use Browse and load.".into());
    }
    let result = finish_load(&app, &state, PathBuf::from(path), passphrase.as_deref());
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    result
}

#[tauri::command]
pub async fn browse_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut passphrase: Option<String>,
) -> Result<AppStatus, String> {
    let Some(path) = pick_open(&app)? else {
        set_message(&state, "No key file was opened.");
        return Ok(status(&state));
    };
    let result = finish_load(&app, &state, path, passphrase.as_deref());
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    result
}

#[tauri::command]
pub async fn backup_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut passphrase: Option<String>,
) -> Result<AppStatus, String> {
    let source = lock(&state.key_path)
        .clone()
        .ok_or("Load a saved key first.")?;
    let current = lock(&state.key).clone().ok_or("Load a key first.")?;
    let source_key = key_file::read_key_file_with_passphrase(&source, passphrase.as_deref())
        .map_err(|err| err.to_string());
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    if source_key?.as_slice() != current.as_slice() {
        return Err(
            "The key file changed since it was loaded. Load it again before backing it up.".into(),
        );
    }
    let Some(destination) = pick_save(&app)? else {
        return Ok(status(&state));
    };
    if source.canonicalize().ok() == destination.canonicalize().ok() && source.exists() {
        return Err("Choose a different location for the backup.".into());
    }
    if destination.exists() {
        return Err("Choose a new path for the backup so an existing key is not replaced.".into());
    }
    if fs::metadata(&source).map_err(|err| err.to_string())?.len() > 4096 {
        return Err("The selected key file is too large.".into());
    }
    let bytes = fs::read(&source).map_err(|err| err.to_string())?;
    crypto::write_transformed(&destination, false, |writer| {
        writer.write_all(&bytes).map_err(CryptoError::from)
    })
    .map_err(|err| err.to_string())?;
    let copied = fs::read(&destination).map_err(|err| err.to_string())?;
    if copied != bytes {
        return Err("Backup verification failed.".into());
    }
    // The copy is byte-for-byte identical. A separate restore check tests its passphrase.
    set_message(
        &state,
        format!(
            "Key backup written and checked at {}. Use Check backup to test opening it.",
            destination.display()
        ),
    );
    drop(current);
    Ok(status(&state))
}

#[tauri::command]
pub async fn check_key_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut passphrase: Option<String>,
) -> Result<AppStatus, String> {
    let current = lock(&state.key).clone().ok_or("Load a key first.")?;
    let Some(path) = pick_open(&app)? else {
        return Ok(status(&state));
    };
    let opened = key_file::read_key_file_with_passphrase(&path, passphrase.as_deref())
        .map_err(|err| err.to_string());
    if let Some(value) = passphrase.as_mut() {
        value.zeroize();
    }
    let opened = opened?;
    if opened.as_slice() != current.as_slice() {
        return Err("This backup contains a different key.".into());
    }
    set_message(
        &state,
        format!(
            "Backup checked: {} opens with the current key.",
            path.display()
        ),
    );
    Ok(status(&state))
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
pub async fn preview_job(app: tauri::AppHandle, request: JobRequest) -> Result<JobPreview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        plan_job(&state, &request)
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
pub async fn run_job(
    app: tauri::AppHandle,
    request: JobRequest,
) -> Result<Vec<FileOutcome>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        if state
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Err("A job is already running.".into());
        }
        struct Running<'a>(&'a AppState);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.running.store(false, Ordering::Release);
            }
        }
        let _guard = Running(&state);
        state.cancelled.store(false, Ordering::Release);
        let preview = plan_job(&state, &request)?;
        if !preview.can_run {
            return Err("Resolve the issues shown in the preview before starting.".into());
        }
        execute_job(&app, &state, request, preview)
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
pub fn cancel_job(state: tauri::State<'_, AppState>) -> bool {
    if !state.running.load(Ordering::Acquire) {
        return false;
    }
    state.cancelled.store(true, Ordering::Release);
    true
}

fn planned_output(input: &Path, dir: Option<&Path>, name: &std::ffi::OsStr) -> PathBuf {
    match dir {
        Some(dir) => dir.join(name),
        None => input.with_file_name(name),
    }
}

fn comparison_path(path: &Path) -> PathBuf {
    let absolute = fs::canonicalize(path)
        .or_else(|_| {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            fs::canonicalize(parent).map(|value| value.join(path.file_name().unwrap_or_default()))
        })
        .unwrap_or_else(|_| path.to_path_buf());
    if cfg!(windows) {
        PathBuf::from(absolute.to_string_lossy().to_lowercase())
    } else {
        absolute
    }
}

fn plan_job(state: &AppState, request: &JobRequest) -> Result<JobPreview, String> {
    if !matches!(request.operation.as_str(), "encrypt" | "decrypt" | "verify") {
        return Err("Unknown operation.".into());
    }
    if request.paths.is_empty() {
        return Err("Add at least one file.".into());
    }
    if request.paths.len() > 10_000 {
        return Err("Select fewer than 10,000 files at once.".into());
    }
    let key = lock(&state.key)
        .clone()
        .ok_or("Load or create an encryption key first.")?;
    let dir = output_directory(&request.output_dir)?;
    let zip_destination = dir.clone().unwrap_or_else(|| {
        Path::new(&request.paths[0])
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    let key_path = lock(&state.key_path).clone();
    let mut items = Vec::new();
    let mut seen_inputs = HashSet::new();
    let all_inputs = request
        .paths
        .iter()
        .map(|path| comparison_path(Path::new(path)))
        .collect::<HashSet<_>>();
    let mut seen_outputs = HashSet::new();
    let mut total_bytes = 0u64;
    let mut warnings = Vec::new();
    if request.remove_original && request.operation != "verify" {
        warnings.push("Originals will be removed after each successful output. This is ordinary deletion, not secure erasure.".into());
    }
    if request.remove_original && request.operation == "verify" {
        warnings.push("Verify does not delete originals.".into());
    }
    for path in &request.paths {
        let input = PathBuf::from(path);
        let meta = fs::metadata(&input).map_err(|err| format!("{}: {err}", input.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a file.", input.display()));
        }
        let duplicate = !seen_inputs.insert(comparison_path(&input));
        let is_zip = input
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));
        if is_zip && request.operation != "encrypt" {
            let entries = archive_read::entries(&input).map_err(|err| err.to_string())?;
            let names = archive_read::inspect_names(&input, &key, &entries)
                .map_err(|err| err.to_string())?;
            for (entry, name) in entries.iter().zip(names) {
                let output = if request.operation == "verify" {
                    None
                } else {
                    Some(planned_output(
                        &input,
                        dir.as_deref(),
                        std::ffi::OsStr::new(&name),
                    ))
                };
                let issue = preview_issue(
                    &input,
                    output.as_deref(),
                    key_path.as_deref(),
                    request.overwrite,
                    duplicate,
                    &all_inputs,
                    &mut seen_outputs,
                );
                total_bytes = total_bytes.saturating_add(entry.size.saturating_mul(2));
                items.push(PreviewItem {
                    input: format!("{} / {}", input.display(), entry.name),
                    output: output
                        .map_or_else(|| "Verify only".into(), |value| value.display().to_string()),
                    bytes: entry.size,
                    issue,
                });
            }
        } else {
            let output = match request.operation.as_str() {
                "verify" => {
                    crypto::inspect_output_name(&key, &input).map_err(|err| err.to_string())?;
                    None
                }
                "encrypt" if request.zip => None,
                "encrypt" => Some(planned_output(
                    &input,
                    dir.as_deref(),
                    std::ffi::OsStr::new("<random>.fenc"),
                )),
                _ => Some(planned_output(
                    &input,
                    dir.as_deref(),
                    &crypto::inspect_output_name(&key, &input).map_err(|err| err.to_string())?,
                )),
            };
            let issue = preview_issue(
                &input,
                if request.operation == "encrypt" {
                    None
                } else {
                    output.as_deref()
                },
                key_path.as_deref(),
                request.overwrite,
                duplicate,
                &all_inputs,
                &mut seen_outputs,
            );
            total_bytes = total_bytes.saturating_add(meta.len());
            let output_text = if request.operation == "verify" {
                "Verify only".into()
            } else if request.zip && request.operation == "encrypt" {
                zip_destination.join("<random>.zip").display().to_string()
            } else {
                output.unwrap().display().to_string()
            };
            items.push(PreviewItem {
                input: path.clone(),
                output: output_text,
                bytes: meta.len(),
                issue,
            });
        }
    }
    if request.overwrite && request.operation == "decrypt" {
        warnings.push("Existing output files shown in the preview will be replaced.".into());
    }
    Ok(JobPreview {
        can_run: items.iter().all(|item| item.issue.is_none()),
        items,
        warnings,
        total_bytes,
    })
}

fn preview_issue(
    input: &Path,
    output: Option<&Path>,
    key_path: Option<&Path>,
    overwrite: bool,
    duplicate: bool,
    all_inputs: &HashSet<PathBuf>,
    seen_outputs: &mut HashSet<PathBuf>,
) -> Option<String> {
    if duplicate {
        return Some("This input was selected more than once.".into());
    }
    if key_path.is_some_and(|key| comparison_path(key) == comparison_path(input)) {
        return Some("This is the key file.".into());
    }
    let Some(output) = output else {
        return None;
    };
    if !seen_outputs.insert(comparison_path(output)) {
        return Some("Another selected file has the same output path.".into());
    }
    if all_inputs.contains(&comparison_path(output))
        || key_path.is_some_and(|key| comparison_path(key) == comparison_path(output))
    {
        return Some("Output conflicts with an input or key file.".into());
    }
    if output.exists() && !overwrite {
        return Some("Output already exists. Choose a folder or enable replacement.".into());
    }
    None
}

struct RemoveTemp(PathBuf);
impl Drop for RemoveTemp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn execute_job(
    app: &tauri::AppHandle,
    state: &AppState,
    request: JobRequest,
    preview: JobPreview,
) -> Result<Vec<FileOutcome>, String> {
    let key = lock(&state.key).clone().ok_or("Load a key first.")?;
    let output_dir = output_directory(&request.output_dir)?;
    store_output_dir(app, state, output_dir.clone());
    let options = JobOptions {
        overwrite: request.overwrite,
        remove_original: request.remove_original,
        key_file: lock(&state.key_path).clone(),
        output_dir,
    };
    let processed = AtomicU64::new(0);
    let current = Mutex::new((0usize, String::new(), String::new()));
    let last_emit = Mutex::new(Instant::now() - Duration::from_secs(1));
    let report = |force: bool| {
        let (index, file, stage) = lock(&current).clone();
        let mut last = lock(&last_emit);
        if force || last.elapsed() >= Duration::from_millis(80) {
            let _ = app.emit(
                "job-progress",
                JobProgress {
                    processed_bytes: processed.load(Ordering::Relaxed),
                    total_bytes: preview.total_bytes,
                    current_file: file,
                    file_index: index + 1,
                    file_count: preview.items.len(),
                    stage,
                },
            );
            *last = Instant::now();
        }
    };
    let progress = |bytes: u64| -> io::Result<()> {
        if state.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
        }
        processed.fetch_add(bytes, Ordering::Relaxed);
        report(false);
        Ok(())
    };
    let mut outcomes = Vec::new();
    let mut preview_index = 0usize;
    if request.operation == "encrypt" && request.zip {
        let paths = request.paths.iter().map(PathBuf::from).collect::<Vec<_>>();
        let on_entry = |index: usize, path: &Path| {
            let packaging = index >= paths.len();
            *lock(&current) = (
                index.min(paths.len() - 1),
                path.display().to_string(),
                if packaging {
                    "Packaging ZIP"
                } else {
                    "Encrypting"
                }
                .into(),
            );
            report(true);
        };
        let result = archive::encrypt_to_zip_with_progress(
            &key,
            &paths,
            &options,
            Some(&progress),
            Some(&on_entry),
        );
        let result = result.map_err(|err| err.to_string())?;
        for (input, error) in request.paths.into_iter().zip(result.delete_errors) {
            outcomes.push(FileOutcome {
                input,
                output: Some(result.path.display().to_string()),
                ok: error.is_none(),
                message: error.map_or_else(
                    || "Encrypted into ZIP".into(),
                    |err| format!("ZIP written, but original remains: {err}"),
                ),
            });
        }
        report(true);
        return Ok(outcomes);
    }
    for path in request.paths {
        if state.cancelled.load(Ordering::Acquire) {
            break;
        }
        let input = PathBuf::from(&path);
        let is_zip = input
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));
        if is_zip && request.operation != "encrypt" {
            let entries = archive_read::entries(&input).map_err(|err| err.to_string())?;
            let mut all_ok = true;
            for entry in entries {
                if state.cancelled.load(Ordering::Acquire) {
                    all_ok = false;
                    break;
                }
                *lock(&current) = (
                    preview_index,
                    format!("{} / {}", path, entry.name),
                    "Reading ZIP entry".into(),
                );
                report(true);
                let temp_dir = std::env::temp_dir().join(format!(
                    "fileencrypt-{}",
                    crypto::opaque_file_name().to_string_lossy()
                ));
                fs::create_dir(&temp_dir).map_err(|err| err.to_string())?;
                let _cleanup = RemoveTemp(temp_dir.clone());
                let temp = temp_dir.join(&entry.name);
                let result = archive_read::extract_entry(&input, &entry, &temp, Some(&progress))
                    .and_then(|()| {
                        lock(&current).2 = if request.operation == "verify" {
                            "Verifying".into()
                        } else {
                            "Decrypting".into()
                        };
                        report(true);
                        if request.operation == "verify" {
                            crypto::verify_file(&key, &temp, Some(&progress))?;
                            Ok(None)
                        } else {
                            let mut entry_options = options.clone();
                            entry_options.remove_original = false;
                            if entry_options.output_dir.is_none() {
                                entry_options.output_dir = input.parent().map(Path::to_path_buf);
                            }
                            crypto::decrypt_file_with_progress(
                                &key,
                                &temp,
                                &entry_options,
                                &progress,
                            )
                            .map(Some)
                        }
                    });
                let ok = result.is_ok();
                if !ok {
                    all_ok = false;
                }
                outcomes.push(FileOutcome {
                    input: format!("{} / {}", path, entry.name),
                    output: result
                        .as_ref()
                        .ok()
                        .and_then(|value| value.as_ref().map(|path| path.display().to_string())),
                    ok,
                    message: match result {
                        Ok(_) if request.operation == "verify" => "Verified".into(),
                        Ok(_) => "Decrypted from ZIP".into(),
                        Err(err) => err.to_string(),
                    },
                });
                preview_index += 1;
                if state.cancelled.load(Ordering::Acquire) {
                    all_ok = false;
                    break;
                }
            }
            if all_ok && request.remove_original && request.operation == "decrypt" {
                if let Err(err) = fs::remove_file(&input) {
                    outcomes.push(FileOutcome {
                        input: path,
                        output: None,
                        ok: false,
                        message: format!("Decrypted entries, but ZIP remains: {err}"),
                    });
                }
            }
        } else {
            *lock(&current) = (
                preview_index,
                path.clone(),
                match request.operation.as_str() {
                    "encrypt" => "Encrypting",
                    "decrypt" => "Decrypting",
                    _ => "Verifying",
                }
                .into(),
            );
            report(true);
            let result = match request.operation.as_str() {
                "encrypt" => {
                    crypto::encrypt_file_with_progress(&key, &input, &options, &progress).map(Some)
                }
                "decrypt" => {
                    crypto::decrypt_file_with_progress(&key, &input, &options, &progress).map(Some)
                }
                _ => crypto::verify_file(&key, &input, Some(&progress)).map(|()| None),
            };
            outcomes.push(match result {
                Ok(output) => FileOutcome {
                    input: path,
                    output: output.map(|value| value.display().to_string()),
                    ok: true,
                    message: match request.operation.as_str() {
                        "encrypt" => "Encrypted",
                        "decrypt" => "Decrypted",
                        _ => "Verified",
                    }
                    .into(),
                },
                Err(CryptoError::OriginalRemains { output, source }) => FileOutcome {
                    input: path,
                    output: Some(output),
                    ok: false,
                    message: format!("The output was written, but the original remains: {source}"),
                },
                Err(err) => FileOutcome {
                    input: path,
                    output: None,
                    ok: false,
                    message: err.to_string(),
                },
            });
            preview_index += 1;
        }
    }
    if state.cancelled.load(Ordering::Acquire) {
        for item in preview.items.iter().skip(preview_index) {
            outcomes.push(FileOutcome {
                input: item.input.clone(),
                output: None,
                ok: false,
                message: "Not processed: job cancelled".into(),
            });
        }
    }
    report(true);
    Ok(outcomes)
}

fn finish_load(
    app: &tauri::AppHandle,
    state: &AppState,
    path: PathBuf,
    passphrase: Option<&str>,
) -> Result<AppStatus, String> {
    let key = key_file::read_key_file_with_passphrase(&path, passphrase)
        .map_err(|err| err.to_string())?;
    let extra = remember_key(app, state, path, key);
    set_message(state, format!("Key loaded.{extra}"));
    Ok(status(state))
}

fn status(state: &AppState) -> AppStatus {
    let (key_loaded, fingerprint) = {
        let key = lock(&state.key);
        (
            key.is_some(),
            key.as_ref()
                .map(|value| key_file::fingerprint(value.as_slice())),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_blocks_two_decryptions_with_the_same_output() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-plan-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        let left = root.join("left");
        let right = root.join("right");
        let destination = root.join("out");
        fs::create_dir_all(&left).unwrap();
        fs::create_dir_all(&right).unwrap();
        let one = left.join("same.txt");
        let two = right.join("same.txt");
        fs::write(&one, b"one").unwrap();
        fs::write(&two, b"two").unwrap();
        let key = [7u8; 32];
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        };
        let one = crypto::encrypt_file(&key, &one, &options).unwrap();
        let two = crypto::encrypt_file(&key, &two, &options).unwrap();
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new(key));
        let request = JobRequest {
            paths: vec![one.display().to_string(), two.display().to_string()],
            output_dir: destination.display().to_string(),
            overwrite: true,
            remove_original: false,
            zip: false,
            operation: "decrypt".into(),
        };
        let preview = plan_job(&state, &request).unwrap();
        assert!(!preview.can_run);
        assert!(preview.items.iter().any(|item| item
            .issue
            .as_deref()
            .is_some_and(|issue| issue.contains("same output path"))));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expanding_folder_collects_nested_files() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-folder-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("one.txt"), b"one").unwrap();
        fs::write(root.join("nested").join("two.txt"), b"two").unwrap();
        let files = expand_paths(vec![root.display().to_string()]).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|name| name.ends_with("one.txt")));
        assert!(files.iter().any(|name| name.ends_with("two.txt")));
        fs::remove_dir_all(root).unwrap();
    }
}
