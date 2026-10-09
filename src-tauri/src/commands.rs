use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_updater::UpdaterExt;
use zeroize::{Zeroize, Zeroizing};

use crate::archive;
use crate::archive_read;
use crate::crypto::{self, CryptoError, JobOptions};
use crate::key_file;
use crate::source::Source;
use crate::{
    deletion::{self, DeletionInfo, DeletionState, Removal, RetryTicket},
    file_guard,
};

pub struct AppState {
    pub(crate) key_change: Mutex<()>,
    pub(crate) key_revision: AtomicU64,
    pub(crate) key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    pub(crate) key_path: Mutex<Option<PathBuf>>,
    pub(crate) key_file_hash: Mutex<Option<[u8; 32]>>,
    pub(crate) emergency_locked: AtomicBool,
    pub(crate) emergency_delete_held: AtomicBool,
    pub(crate) emergency: Mutex<crate::emergency::Controls>,
    pub(crate) protection: Mutex<crate::key_protection::Session>,
    pub(crate) sandbox: Mutex<crate::sandbox::Registry>,
    output_dir: Mutex<Option<PathBuf>>,
    message: Mutex<String>,
    startup_key_unavailable: AtomicBool,
    pub(crate) running: AtomicBool,
    cancelled: AtomicBool,
    deletions: Mutex<DeletionRegistry>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            key_change: Mutex::new(()),
            key_revision: AtomicU64::new(0),
            key: Mutex::new(None),
            key_path: Mutex::new(None),
            key_file_hash: Mutex::new(None),
            emergency_locked: AtomicBool::new(false),
            emergency_delete_held: AtomicBool::new(false),
            emergency: Mutex::new(crate::emergency::Controls::default()),
            protection: Mutex::new(crate::key_protection::Session::default()),
            sandbox: Mutex::new(crate::sandbox::Registry::default()),
            output_dir: Mutex::new(None),
            message: Mutex::new(String::new()),
            startup_key_unavailable: AtomicBool::new(false),
            running: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            deletions: Mutex::new(DeletionRegistry::default()),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    access_setup_required: bool,
    access_setup_is_upgrade: bool,
    access_setup_key_path: Option<String>,
    access_setup_requires_current_reference: bool,
    emergency_locked: bool,
    emergency_deletion_armed: bool,
    emergency_deletion_path: Option<String>,
    emergency_deletion_message: Option<String>,
    emergency_shortcuts_native: bool,
    key_revision: u64,
    key_loaded: bool,
    key_path: Option<String>,
    sandbox_available: bool,
    output_dir: Option<String>,
    fingerprint: Option<String>,
    message: String,
    startup_key_unavailable: bool,
    updates_configured: bool,
}

#[derive(Serialize)]
pub struct FileOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<DeletionInfo>,
    input: String,
    output: Option<String>,
    #[serde(rename = "originalName", skip_serializing_if = "Option::is_none")]
    original_name: Option<String>,
    ok: bool,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationReport {
    results: Vec<FileOutcome>,
    status: AppStatus,
    new_key_path: String,
    notice: Option<String>,
}

const UPDATE_URL: &str =
    "https://github.com/justindowding555-lgtm/FileEncrypt/releases/latest/download/latest.json";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    version: String,
    notes: Option<String>,
}

fn updater_key() -> Result<&'static str, String> {
    option_env!("FILEENCRYPT_UPDATER_PUBKEY")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Signed updates are not configured in this build.".into())
}

#[tauri::command]
pub async fn check_for_updates(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    let key = updater_key()?;
    let endpoint = UPDATE_URL
        .parse()
        .map_err(|err| format!("Invalid update URL: {err}"))?;
    let updater = app
        .updater_builder()
        .pubkey(key)
        .endpoints(vec![endpoint])
        .map_err(|err| err.to_string())?
        .build()
        .map_err(|err| err.to_string())?;
    updater
        .check()
        .await
        .map_err(|err| err.to_string())?
        .map(|update| {
            Ok(UpdateInfo {
                version: update.version,
                notes: update.body,
            })
        })
        .transpose()
}

#[tauri::command]
pub async fn install_update(app: tauri::AppHandle) -> Result<String, String> {
    if app.state::<AppState>().running.load(Ordering::Acquire) {
        return Err("Finish the current file job before installing an update.".into());
    }
    let key = updater_key()?;
    let endpoint = UPDATE_URL
        .parse()
        .map_err(|err| format!("Invalid update URL: {err}"))?;
    let updater = app
        .updater_builder()
        .pubkey(key)
        .endpoints(vec![endpoint])
        .map_err(|err| err.to_string())?
        .build()
        .map_err(|err| err.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|err| err.to_string())?
        .ok_or("No newer signed update is available.")?;
    let version = update.version.clone();
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|err| err.to_string())?;
    Ok(format!(
        "Installed version {version}. Restart FileEncrypt to use it."
    ))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRequest {
    paths: Vec<String>,
    #[serde(default)]
    folder_roots: HashMap<String, String>,
    output_dir: String,
    overwrite: bool,
    remove_original: bool,
    zip: bool,
    #[serde(default)]
    compress: bool,
    operation: String,
}

#[derive(Serialize)]
pub struct SelectedPaths {
    paths: Vec<String>,
    roots: HashMap<String, String>,
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

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

const MAX_DELETION_RECEIPTS: usize = 10_000;
const PENDING_DELETION_BATCH_SIZE: usize = 100;

#[derive(Default)]
struct DeletionRegistry {
    current: HashMap<String, Arc<RetryTicket>>,
    confirmed: HashMap<String, DeletionInfo>,
    staged: Option<HashMap<String, Arc<RetryTicket>>>,
}

impl DeletionRegistry {
    fn clear(&mut self) {
        self.current.clear();
        self.confirmed.clear();
        self.staged = None;
    }
}

/// Keep the displayed results usable if a new job fails. Only replace their
/// receipts when a completed report is ready to replace those results in the UI.
struct DeletionBatch<'a> {
    state: &'a AppState,
    committed: bool,
}
impl<'a> DeletionBatch<'a> {
    fn new(state: &'a AppState) -> Self {
        let mut registry = lock(&state.deletions);
        debug_assert!(registry.staged.is_none());
        registry.staged = Some(HashMap::new());
        Self {
            state,
            committed: false,
        }
    }
    fn commit(mut self) {
        let mut registry = lock(&self.state.deletions);
        registry.current = registry.staged.take().unwrap_or_default();
        registry.confirmed.clear();
        self.committed = true;
    }
}
impl Drop for DeletionBatch<'_> {
    fn drop(&mut self) {
        if !self.committed {
            lock(&self.state.deletions).staged = None;
        }
    }
}

fn register_removal(state: &AppState, mut removal: Removal) -> DeletionInfo {
    if let Some(ticket) = removal.retry {
        let mut registry = lock(&state.deletions);
        let tickets = match &mut *registry {
            DeletionRegistry {
                staged: Some(tickets),
                ..
            } => tickets,
            DeletionRegistry { current, .. } => current,
        };
        if tickets.len() < MAX_DELETION_RECEIPTS {
            let token = crypto::opaque_file_name().to_string_lossy().into_owned();
            tickets.insert(token.clone(), Arc::new(ticket));
            removal.info.retry_id = Some(token);
        } else {
            let reason = removal.info.reason.get_or_insert_with(String::new);
            if !reason.is_empty() {
                reason.push(' ');
            }
            reason.push_str("Deletion retry is unavailable because this report reached the 10,000-receipt limit.");
        }
    }
    removal.info
}

fn transformed_outcome(
    state: &AppState,
    input: String,
    result: crypto::TransformOutcome,
    message: &str,
) -> FileOutcome {
    let info = register_removal(state, result.removal);
    FileOutcome {
        input,
        output: Some(result.path.display().to_string()),
        original_name: None,
        ok: true,
        message: message.into(),
        deletion: (info.state != DeletionState::NotRequested).then_some(info),
    }
}

fn failed_outcome(input: String, error: CryptoError) -> FileOutcome {
    let output = match &error {
        CryptoError::PublicationUncertain { output, .. } => Some(output.clone()),
        _ => None,
    };
    FileOutcome {
        input,
        output,
        original_name: None,
        ok: false,
        message: error.to_string(),
        deletion: None,
    }
}

#[tauri::command]
pub async fn retry_deletion(
    app: tauri::AppHandle,
    retry_id: String,
) -> Result<DeletionInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        if state.running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return Err("Finish the current job before retrying deletion.".into());
        }
        struct Running<'a>(&'a AppState);
        impl Drop for Running<'_> {
            fn drop(&mut self) { self.0.running.store(false, Ordering::Release); }
        }
        let _running = Running(&state);
        state.cancelled.store(false, Ordering::Release);
        let verifier = app.state::<crate::verification::VerificationState>();
        let _verification = lock(&verifier.work);
        let ticket = {
            let mut registry = lock(&state.deletions);
            if let Some(info) = registry.confirmed.get(&retry_id).cloned() {
                return Ok(info);
            }
            registry.current.remove(&retry_id)
        }
            .ok_or("This deletion receipt is no longer available. Receipts last until new results replace them or the app closes.")?;
        let callback = |_| -> io::Result<()> {
            if state.cancelled.load(Ordering::Acquire) || state.emergency_locked.load(Ordering::Acquire) {
                Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"))
            } else { Ok(()) }
        };
        Ok(register_removal(&state, deletion::retry(Arc::unwrap_or_clone(ticket), Some(&callback))))
    }).await.map_err(|error| error.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDeletionUpdate {
    retry_id: String,
    deletion: Option<DeletionInfo>,
}

fn pending_deletion_updates(state: &AppState, retry_ids: &[String]) -> Vec<PendingDeletionUpdate> {
    // Snapshot shared receipts so filesystem queries never hold the registry
    // mutex or occupy the file-job slot. IDs stay stable across status polls.
    let tickets = {
        let registry = lock(&state.deletions);
        let mut seen = HashSet::new();
        retry_ids
            .iter()
            .filter(|id| seen.insert(*id))
            .map(|id| {
                (
                    id.clone(),
                    registry.current.get(id).cloned(),
                    registry.confirmed.get(id).cloned(),
                )
            })
            .collect::<Vec<_>>()
    };
    let mut updates = Vec::with_capacity(tickets.len());
    for (retry_id, ticket, confirmed) in tickets {
        let deletion = confirmed.or_else(|| ticket.as_deref().and_then(deletion::check_pending));
        let mut registry = lock(&state.deletions);
        // A new report or an explicit retry may have retired this receipt while
        // the query was in flight. Never resurrect it in the current registry.
        let current = ticket.as_ref().is_some_and(|ticket| {
            registry
                .current
                .get(&retry_id)
                .is_some_and(|entry| Arc::ptr_eq(entry, ticket))
        });
        let deletion = if current {
            // Cache confirmation until the next report. If an IPC response is
            // lost, the next check must still be able to recover this outcome.
            registry
                .confirmed
                .get(&retry_id)
                .cloned()
                .or(deletion)
                .map(|mut info| {
                    if info.state == DeletionState::Removed {
                        registry.confirmed.insert(retry_id.clone(), info.clone());
                    } else {
                        info.retry_id = Some(retry_id.clone());
                    }
                    info
                })
        } else {
            None
        };
        updates.push(PendingDeletionUpdate { retry_id, deletion });
    }
    updates
}

#[tauri::command]
pub async fn check_pending_deletions(
    app: tauri::AppHandle,
    retry_ids: Vec<String>,
) -> Result<Vec<PendingDeletionUpdate>, String> {
    if retry_ids.len() > PENDING_DELETION_BATCH_SIZE {
        return Err("Check at most 100 pending deletions at a time.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        pending_deletion_updates(app.state::<AppState>().inner(), &retry_ids)
    })
    .await
    .map_err(|error| error.to_string())
}

pub fn restore_saved_key(app: &tauri::AppHandle, state: &AppState) {
    let Some(settings) = read_settings(app) else {
        return;
    };
    restore_saved_settings(state, settings);
}

fn restore_saved_settings(state: &AppState, settings: Settings) {
    *lock(&state.output_dir) = settings.output_dir;
    let Some(path) = settings.key_path else {
        return;
    };
    restore_saved_key_from_path(state, &path);
}

pub(crate) fn restore_saved_key_from_path(state: &AppState, path: &Path) {
    let _key_change = lock(&state.key_change);
    crate::key_protection::cancel(state);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    *lock(&state.key_path) = Some(path.to_path_buf());
    *lock(&state.key) = None;
    *lock(&state.key_file_hash) = None;
    if crate::emergency::ensure_unlocked(state).is_err() {
        state.startup_key_unavailable.store(true, Ordering::Release);
        set_message(state, crate::emergency::UNAVAILABLE);
        return;
    }
    match key_file::read_key_snapshot(path).and_then(|bytes| {
        crate::key_protection::observe_key_file(state, &bytes);
        let key = key_file::parse_key_snapshot(path, &bytes, None)?;
        use sha2::Digest;
        Ok((key, sha2::Sha256::digest(bytes.as_slice()).into()))
    }) {
        Ok((key, hash)) => {
            *lock(&state.key) = Some(key);
            *lock(&state.key_file_hash) = Some(hash);
            set_message(state, "Key loaded from the saved location.");
        }
        Err(err) => {
            // Protected or damaged keys keep their actual loading error.
            if key_file_unavailable(&err) {
                state.startup_key_unavailable.store(true, Ordering::Release);
                set_message(
                    state,
                    "Your saved key file is unavailable. Reconnect its drive; FileEncrypt will check for it automatically. Use Browse and load if its location changed.",
                );
                return;
            }
            if crate::key_protection::setup_required(state) && crate::key_protection::needs_current_reference(state) {
                set_message(state, "Update emergency access setup with your existing password to restore automatic key loading.");
            } else {
                set_message(state, format!("Could not load the saved key: {err}"));
            }
        }
    }
}

/// Watch saved file keys in both directions. Session-only and explicitly
/// unloaded keys are excluded; a delayed read cannot replace a newer key.
pub(crate) fn refresh_key_file(state: &AppState) -> bool {
    let deletion_changed = crate::emergency::check_deletion(state);
    let check = {
        let _key_change = lock(&state.key_change);
        if crate::emergency::ensure_unlocked(state).is_err() {
            return deletion_changed;
        }
        let loaded = lock(&state.key).is_some();
        if !loaded
            && (!state.startup_key_unavailable.load(Ordering::Acquire)
                || state.running.load(Ordering::Acquire))
        {
            return deletion_changed;
        }
        let Some(path) = lock(&state.key_path).clone() else {
            return deletion_changed;
        };
        KeyFileCheck {
            revision: state.key_revision.load(Ordering::Acquire),
            path,
            loaded,
            expected_hash: *lock(&state.key_file_hash),
        }
    };
    // Read outside the state lock: an unavailable removable or network drive
    // must not block manual key changes or app shutdown.
    let snapshot = key_file::read_key_snapshot(&check.path);
    finish_key_file_check(state, check, snapshot) || deletion_changed
}

struct KeyFileCheck {
    revision: u64,
    path: PathBuf,
    loaded: bool,
    expected_hash: Option<[u8; 32]>,
}

fn key_file_unavailable(error: &CryptoError) -> bool {
    matches!(error, CryptoError::Io(_))
        || matches!(error, CryptoError::InvalidKeyFile(message) if message.starts_with("key file not found: "))
}

fn finish_key_file_check(
    state: &AppState,
    check: KeyFileCheck,
    snapshot: Result<Zeroizing<Vec<u8>>, CryptoError>,
) -> bool {
    let _key_change = lock(&state.key_change);
    if state.key_revision.load(Ordering::Acquire) != check.revision
        || crate::emergency::ensure_unlocked(state).is_err()
        || (!check.loaded && state.running.load(Ordering::Acquire))
    {
        return false;
    }
    let bytes = match snapshot {
        Ok(bytes) => bytes,
        Err(error) => {
            let unavailable = key_file_unavailable(&error);
            if !check.loaded && unavailable {
                return false;
            }
            deactivate_file_key(
                state,
                unavailable,
                if unavailable {
                    "Key disconnected and unloaded. Reconnect its drive; FileEncrypt will check for the saved key automatically.".into()
                } else {
                    format!("The saved key file cannot be loaded. Open Key options to load it again. {error}")
                },
            );
            return true;
        }
    };
    use sha2::Digest;
    let hash: [u8; 32] = sha2::Sha256::digest(bytes.as_slice()).into();
    if check.expected_hash.is_some_and(|expected| expected != hash) {
        deactivate_file_key(state, false, "The key file changed since it was loaded. Open Key options and load the saved key again.".into());
        return true;
    }
    if check.loaded {
        return false;
    }
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    match key_file::parse_key_snapshot(&check.path, &bytes, None) {
        Ok(key) => {
            *lock(&state.key) = Some(key);
            *lock(&state.key_file_hash) = Some(hash);
            set_message(state, "Key reconnected and loaded from the saved location.");
        }
        Err(error) => {
            // A readable protected or damaged file is no longer disconnected.
            // Keep its actual loading error and do not retain a passphrase.
            *lock(&state.key_file_hash) = None;
            set_message(
                state,
                format!("Key file reconnected. Open Key options to load it. {error}"),
            );
        }
    }
    true
}

// Caller holds key_change. Keep only the non-secret file digest on disconnect
// so reconnecting a different file at the same path cannot silently switch keys.
pub(crate) fn deactivate_file_key(state: &AppState, disconnected: bool, message: String) {
    crate::key_protection::cancel(state);
    crate::sandbox::revoke(state);
    *lock(&state.key) = None;
    if !disconnected {
        lock(&state.emergency).disarm();
        *lock(&state.key_file_hash) = None;
    }
    if state.running.load(Ordering::Acquire) {
        state.cancelled.store(true, Ordering::Release);
    }
    state
        .startup_key_unavailable
        .store(disconnected, Ordering::Release);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    set_message(state, message);
}

pub(crate) fn start_key_monitor(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        let armed = lock(&app.state::<AppState>().emergency)
            .armed_path()
            .is_some();
        std::thread::sleep(if armed {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(1)
        });
        if app.get_webview_window("main").is_none() {
            break;
        }
        let state = app.state::<AppState>();
        if refresh_key_file(&state) {
            crate::sandbox::close_invalid_previews(&app);
            let _ = app.emit("key-status-changed", status(&state));
        }
    });
}

#[tauri::command]
pub fn get_status(state: tauri::State<'_, AppState>) -> AppStatus {
    status(&state)
}

#[tauri::command]
pub async fn recheck_key_file(app: tauri::AppHandle) -> Result<AppStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let changed = refresh_key_file(&state);
        let current = status(&state);
        if changed {
            crate::sandbox::close_invalid_previews(&app);
            let _ = app.emit("key-status-changed", &current);
        }
        current
    })
    .await
    .map_err(|error| error.to_string())
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
    for path in &paths {
        file_guard::regular(&fs::symlink_metadata(path).map_err(|error| error.to_string())?)
            .map_err(|error| format!("{path}: {error}"))?;
    }
    Ok(paths)
}

#[tauri::command]
pub async fn pick_input_folder(app: tauri::AppHandle) -> Result<SelectedPaths, String> {
    let mut dialog = app.dialog().file();
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.set_parent(&window);
    }
    let Some(picked) = dialog
        .set_title("Choose a folder of files")
        .blocking_pick_folder()
    else {
        return Ok(SelectedPaths {
            paths: Vec::new(),
            roots: HashMap::new(),
        });
    };
    let folder = picked.into_path().map_err(|err| err.to_string())?;
    expand_paths_with_roots(vec![folder.display().to_string()])
}

#[tauri::command]
pub fn expand_dropped_paths(paths: Vec<String>) -> Result<SelectedPaths, String> {
    expand_paths_with_roots(paths)
}

fn expand_paths_with_roots(paths: Vec<String>) -> Result<SelectedPaths, String> {
    let mut selection = SelectedPaths {
        paths: Vec::new(),
        roots: HashMap::new(),
    };
    for path in paths {
        let root = PathBuf::from(&path);
        let folder = fs::symlink_metadata(&root)
            .map_err(|err| err.to_string())?
            .is_dir();
        let expanded = expand_paths(vec![path.clone()])?;
        if folder {
            for child in &expanded {
                selection.roots.insert(child.clone(), path.clone());
            }
        }
        selection.paths.extend(expanded);
    }
    selection.paths.sort();
    selection.paths.dedup();
    if selection.paths.len() > 10_000 {
        return Err("Select fewer than 10,000 files at once.".into());
    }
    Ok(selection)
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
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    crate::emergency::ensure_unlocked(&state)?;
    let passphrase = passphrase.map(Zeroizing::new);
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
    written.map_err(|err| err.to_string())?;
    let hash =
        key_file::checked_file_hash(&path, &key, passphrase.as_deref().map(String::as_str)).ok();
    let extra = remember_key(&app, &state, path, key, hash)?;
    set_message(&state, format!("New key generated and saved.{extra}"));
    Ok(status(&state))
}

#[tauri::command]
pub async fn save_typed_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    mut key_text: String,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    crate::emergency::ensure_unlocked(&state)?;
    let passphrase = passphrase.map(Zeroizing::new);
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
    written.map_err(|err| err.to_string())?;
    let hash =
        key_file::checked_file_hash(&path, &key, passphrase.as_deref().map(String::as_str)).ok();
    let extra = remember_key(&app, &state, path, key, hash)?;
    set_message(&state, format!("Key written to the file.{extra}"));
    Ok(status(&state))
}

#[tauri::command]
pub fn use_typed_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    key_text: String,
) -> Result<AppStatus, String> {
    let key_text = Zeroizing::new(key_text);
    if state.running.load(Ordering::Acquire) {
        return Err("Finish the current file job before changing keys.".into());
    }
    let parsed = key_file::parse_key_material(&key_text);
    drop(key_text);
    let key = parsed.map_err(|err| err.to_string())?;
    activate_session_key(&state, key, &settings_path(&app)?)?;
    Ok(status(&state))
}

fn activate_session_key(
    state: &AppState,
    key: Zeroizing<[u8; 32]>,
    settings_path: &Path,
) -> Result<(), String> {
    let _key_change = lock(&state.key_change);
    crate::emergency::ensure_unlocked(state)?;
    crate::key_protection::cancel(state);
    // Remember only preferences and clear the old file path before activating
    // this key, so a later launch cannot silently restore a previous file key.
    let settings = Settings {
        key_path: None,
        output_dir: lock(&state.output_dir).clone(),
    };
    write_settings_file(settings_path, &settings)?;
    lock(&state.emergency).disarm();
    crate::sandbox::revoke(state);
    *lock(&state.key) = Some(key);
    *lock(&state.key_path) = None;
    *lock(&state.key_file_hash) = None;
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    set_message(
        state,
        "Key loaded for this session only. It will be cleared when you close the app.",
    );
    Ok(())
}

#[tauri::command]
pub async fn load_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    path: String,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    crate::emergency::ensure_unlocked(&state)?;
    let passphrase = passphrase.map(Zeroizing::new);
    let path = path.trim().to_string();
    if path.is_empty() {
        return Err("Enter a key file path, or use Browse and load.".into());
    }
    finish_load(
        &app,
        &state,
        PathBuf::from(path),
        passphrase.as_deref().map(String::as_str),
    )
}

#[tauri::command]
pub async fn browse_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    let passphrase = passphrase.map(Zeroizing::new);
    let Some(path) = pick_key_for_load(&state, || pick_open(&app))? else {
        set_message(&state, "No key file was opened.");
        return Ok(status(&state));
    };
    finish_load(
        &app,
        &state,
        path,
        passphrase.as_deref().map(String::as_str),
    )
}

fn pick_key_for_load(
    state: &AppState,
    picker: impl FnOnce() -> Result<Option<PathBuf>, String>,
) -> Result<Option<PathBuf>, String> {
    // A locked app still behaves like an ordinary file picker. Reject the
    // selection before reading any bytes or changing the remembered key path.
    let picked = picker()?;
    if picked.is_some() {
        crate::emergency::ensure_unlocked(state)?;
    }
    Ok(picked)
}

#[tauri::command]
pub async fn backup_key(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    crate::emergency::ensure_unlocked(&state)?;
    let passphrase = passphrase.map(Zeroizing::new);
    let source = lock(&state.key_path)
        .clone()
        .ok_or("Load a saved key first.")?;
    let current = lock(&state.key).clone().ok_or("Load a key first.")?;
    let bytes = key_file::read_key_snapshot(&source).map_err(|err| err.to_string())?;
    let source_key =
        key_file::parse_key_snapshot(&source, &bytes, passphrase.as_deref().map(String::as_str))
            .map_err(|err| err.to_string());
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
    write_checked_backup(
        &destination,
        &bytes,
        &current,
        passphrase.as_deref().map(String::as_str),
    )?;
    // The published copy has been reopened, parsed, and checked against the loaded key.
    set_message(
        &state,
        format!(
            "Key backup written, reopened, and checked at {}.",
            destination.display()
        ),
    );
    drop(current);
    Ok(status(&state))
}

fn write_checked_backup(
    destination: &Path,
    bytes: &[u8],
    current: &[u8; 32],
    passphrase: Option<&str>,
) -> Result<(), String> {
    let snapshot_key = key_file::parse_key_snapshot(destination, bytes, passphrase)
        .map_err(|err| err.to_string())?;
    if snapshot_key.as_slice() != current {
        return Err("Backup snapshot contains a different key.".into());
    }
    crypto::write_transformed(destination, false, |writer| {
        writer.write_all(bytes)?;
        Ok(())
    })
    .map_err(|err| err.to_string())?;
    let copied = key_file::read_key_snapshot(destination).map_err(|err| err.to_string())?;
    let reopened = key_file::parse_key_snapshot(destination, &copied, passphrase)
        .map_err(|err| err.to_string())?;
    if copied.as_slice() != bytes || reopened.as_slice() != current {
        return Err("Backup verification failed.".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn check_key_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    crate::emergency::ensure_unlocked(&state)?;
    let passphrase = passphrase.map(Zeroizing::new);
    let current = lock(&state.key).clone().ok_or("Load a key first.")?;
    let Some(path) = pick_open(&app)? else {
        return Ok(status(&state));
    };
    let opened =
        key_file::read_key_file_with_passphrase(&path, passphrase.as_deref().map(String::as_str))
            .map_err(|err| err.to_string())?;
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
    unload_key_from_memory(&state);
    status(&state)
}

fn unload_key_from_memory(state: &AppState) {
    let _key_change = lock(&state.key_change);
    crate::key_protection::cancel(state);
    lock(&state.emergency).disarm();
    crate::sandbox::revoke(state);
    *lock(&state.key) = None;
    *lock(&state.key_file_hash) = None;
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    set_message(state, "Key unloaded from memory.");
}

pub fn clear_key_on_close(state: &AppState) {
    let _key_change = lock(&state.key_change);
    crate::key_protection::cancel(state);
    lock(&state.emergency).disarm();
    crate::sandbox::revoke(state);
    state.cancelled.store(true, Ordering::Release);
    lock(&state.deletions).clear();
    // Dropping Zeroizing overwrites the stored key bytes before releasing them.
    *lock(&state.key) = None;
    *lock(&state.key_file_hash) = None;
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
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
        let verifier = app.state::<crate::verification::VerificationState>();
        let _verification = lock(&verifier.work);
        let preview = plan_job(&state, &request)?;
        if !preview.can_run {
            return Err("Resolve the issues shown in the preview before starting.".into());
        }
        let batch = DeletionBatch::new(&state);
        let results = execute_job(&app, &state, request, preview)?;
        batch.commit();
        Ok(results)
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

#[tauri::command]
pub async fn rotate_key(
    app: tauri::AppHandle,
    paths: Vec<String>,
    output_dir: String,
    remove_original: bool,
    passphrase: Option<String>,
) -> Result<Option<RotationReport>, String> {
    let passphrase = passphrase.map(Zeroizing::new);
    if paths.is_empty() || paths.len() > 10_000 {
        return Err("Select between 1 and 10,000 encrypted files or FileEncrypt ZIPs.".into());
    }
    let Some(new_path) = pick_save(&app)? else {
        return Ok(None);
    };
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
        let _running = Running(&state);
        state.cancelled.store(false, Ordering::Release);
        let verifier = app.state::<crate::verification::VerificationState>();
        let _verification = lock(&verifier.work);
        crate::emergency::ensure_unlocked(&state)?;
        let old_key = lock(&state.key)
            .clone()
            .ok_or("Load the current key first.")?;
        let old_path = lock(&state.key_path).clone();
        if new_path.exists()
            || old_path
                .as_ref()
                .is_some_and(|path| comparison_path(&new_path) == comparison_path(path))
            || paths
                .iter()
                .any(|path| comparison_path(Path::new(path)) == comparison_path(&new_path))
        {
            return Err(
                "Choose a new key-file path that does not exist or overlap an input.".into(),
            );
        }
        let dir = output_directory(&output_dir)?;
        if dir
            .as_ref()
            .is_some_and(|dir| comparison_path(dir) == comparison_path(&new_path))
        {
            return Err("The key-file path cannot be the output folder.".into());
        }
        let mut seen = HashSet::new();
        let mut total = 0u64;
        for path in &paths {
            check_rotation(&state, None).map_err(|err| err.to_string())?;
            let input = Path::new(path);
            if !seen.insert(comparison_path(input)) {
                return Err("The same input was selected more than once.".into());
            }
            file_guard::regular(&fs::symlink_metadata(input).map_err(|error| error.to_string())?)
                .map_err(|error| format!("{}: {error}", input.display()))?;
            let meta = fs::metadata(input).map_err(|err| err.to_string())?;
            if !meta.is_file() {
                return Err(format!("Not a file: {}", input.display()));
            }
            if input
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
            {
                let entries = archive_read::entries(input).map_err(|err| err.to_string())?;
                archive_read::inspect_names(input, &old_key, &entries)
                    .map_err(|err| err.to_string())?;
                total = entries
                    .iter()
                    .fold(total, |sum, entry| sum.saturating_add(entry.size));
            } else {
                crypto::inspect_output_name(&old_key, input).map_err(|err| err.to_string())?;
                total = total.saturating_add(meta.len());
            }
        }
        let new_key = key_file::generate_key();
        let key_progress = |_| check_rotation(&state, None);
        let saved_key = key_file::create_rotation_key(
            &new_path,
            &new_key,
            passphrase.as_deref().map(String::as_str),
            Some(&key_progress),
        )
        .map_err(|err| err.to_string())?;
        let options = JobOptions {
            overwrite: false,
            remove_original,
            key_file: old_path,
            output_dir: dir,
        };
        let processed = AtomicU64::new(0);
        let last_emit = Mutex::new(Instant::now() - Duration::from_secs(1));
        let mut results = Vec::with_capacity(paths.len());
        let batch = DeletionBatch::new(&state);
        for (index, path) in paths.into_iter().enumerate() {
            if state.cancelled.load(Ordering::Acquire)
                || state.emergency_locked.load(Ordering::Acquire)
            {
                break;
            }
            let input = PathBuf::from(&path);
            *lock(&last_emit) = Instant::now() - Duration::from_secs(1);
            let progress = |bytes: u64| -> io::Result<()> {
                check_rotation(&state, Some(&saved_key))?;
                let done = processed
                    .fetch_add(bytes, Ordering::Relaxed)
                    .saturating_add(bytes);
                let mut last = lock(&last_emit);
                if last.elapsed() >= Duration::from_millis(80) {
                    let _ = app.emit(
                        "job-progress",
                        JobProgress {
                            processed_bytes: done,
                            total_bytes: total,
                            current_file: path.clone(),
                            file_index: index + 1,
                            file_count: seen.len(),
                            stage: "Rotating key".into(),
                        },
                    );
                    *last = Instant::now();
                }
                Ok(())
            };
            let rotated = if input
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
            {
                archive::rotate_zip_with_deletion(
                    &old_key,
                    &new_key,
                    &input,
                    &options,
                    Some(&progress),
                )
            } else {
                crypto::rotate_file_with_deletion(
                    &old_key,
                    &new_key,
                    &input,
                    &options,
                    Some(&progress),
                )
            };
            let _ = app.emit(
                "job-progress",
                JobProgress {
                    processed_bytes: processed.load(Ordering::Relaxed),
                    total_bytes: total,
                    current_file: path.clone(),
                    file_index: index + 1,
                    file_count: seen.len(),
                    stage: "Rotating key".into(),
                },
            );
            results.push(match rotated {
                Ok(result) => transformed_outcome(&state, path, result, "Rotated to new key"),
                Err(error) => failed_outcome(path, error),
            });
        }
        let report = finish_rotation(&state, batch, results, seen.len(), &new_path, || {
            let hash = saved_key.checked_hash().map_err(|err| err.to_string())?;
            remember_key(&app, &state, new_path.clone(), new_key, Some(hash))
        });
        Ok(Some(report))
    })
    .await
    .map_err(|err| err.to_string())?
}

fn check_rotation(state: &AppState, saved_key: Option<&key_file::RotationKey>) -> io::Result<()> {
    if state.cancelled.load(Ordering::Acquire) || state.emergency_locked.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "job cancelled"));
    }
    if let Some(saved_key) = saved_key {
        saved_key.check()?;
    }
    Ok(())
}

fn finish_rotation(
    state: &AppState,
    batch: DeletionBatch<'_>,
    results: Vec<FileOutcome>,
    selected_count: usize,
    new_path: &Path,
    activate: impl FnOnce() -> Result<String, String>,
) -> RotationReport {
    // Completed outputs and cleanup receipts survive a failed final activation.
    batch.commit();
    let success = results.len() == selected_count && results.iter().all(|item| item.ok);
    let (message, notice) = if success {
        match activate() {
            Ok(extra) => (format!("Selected files rotated. New key: {}. Keep the old key for any files you did not select.{extra}", new_path.display()), false),
            Err(error) => (format!("Files were rotated, but the new key could not be activated: {error}. New key file: {}. Keep it for the successful outputs, and keep the old key for any files you did not select.", new_path.display()), true),
        }
    } else {
        (format!("Rotation was incomplete. New key file: {}. Keep it for any successful outputs, and keep the old key for retained inputs and files you did not select.", new_path.display()), true)
    };
    set_message(state, &message);
    RotationReport {
        results,
        status: status(state),
        new_key_path: new_path.display().to_string(),
        notice: notice.then_some(message),
    }
}

fn planned_output(input: &Path, dir: Option<&Path>, name: &std::ffi::OsStr) -> PathBuf {
    match dir {
        Some(dir) => dir.join(name),
        None => input.parent().unwrap_or_else(|| Path::new(".")).join(name),
    }
}

fn comparison_path(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    // Resolve the nearest existing ancestor so nested, not-yet-created outputs
    // use the same volume/path representation as their parent outputs.
    let absolute = absolute
        .ancestors()
        .find_map(|ancestor| {
            fs::canonicalize(ancestor)
                .ok()
                .map(|parent| parent.join(absolute.strip_prefix(ancestor).unwrap()))
        })
        .unwrap_or(absolute);
    if cfg!(windows) {
        PathBuf::from(absolute.to_string_lossy().to_lowercase())
    } else {
        absolute
    }
}

fn bundle_root(request: &JobRequest) -> Option<PathBuf> {
    let first = request.folder_roots.get(request.paths.first()?)?;
    request
        .paths
        .iter()
        .all(|path| request.folder_roots.get(path) == Some(first))
        .then(|| PathBuf::from(first))
}

fn plan_job(state: &AppState, request: &JobRequest) -> Result<JobPreview, String> {
    crate::emergency::ensure_unlocked(state)?;
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
    if request.operation == "encrypt" && request.zip {
        let paths = request.paths.iter().map(PathBuf::from).collect::<Vec<_>>();
        let names = archive::relative_names(&paths, bundle_root(request).as_deref())
            .map_err(|err| err.to_string())?;
        let mut seen = HashSet::new();
        if names.iter().any(|name| !seen.insert(name.to_lowercase())) {
            return Err("Two selected files would restore to the same bundle path.".into());
        }
    }
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
    let mut seen_outputs = PlannedOutputs::default();
    let mut total_bytes = 0u64;
    let mut warnings = Vec::new();
    if request.remove_original && request.operation != "verify" {
        warnings.push(if cfg!(windows) {
            "Originals are removed after saved outputs are flushed and protected. Locked originals may be retained or pending; check the results. This is ordinary deletion, not secure erasure."
        } else {
            "Originals will be retained on this platform because mandatory file protection is unavailable."
        }.into());
    }
    if request.remove_original && request.operation == "verify" {
        warnings.push("Verify does not delete originals.".into());
    }
    for path in &request.paths {
        let input = PathBuf::from(path);
        let meta =
            fs::symlink_metadata(&input).map_err(|err| format!("{}: {err}", input.display()))?;
        file_guard::regular(&meta).map_err(|err| format!("{}: {err}", input.display()))?;
        let duplicate = !seen_inputs.insert(comparison_path(&input));
        let is_zip = input
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));
        if is_zip && request.operation != "encrypt" {
            let entries = archive_read::entries(&input).map_err(|err| err.to_string())?;
            let mut source = fs::File::open(&input).map_err(|err| err.to_string())?;
            let (names, authenticated) =
                archive_read::inspect_names_from_reader(&mut source, &key, &entries)
                    .map_err(|err| err.to_string())?;
            if !authenticated {
                warnings.push(format!("{}: older bundle; individual files authenticate, but bundle completeness cannot be checked. The source ZIP will be retained.",input.display()));
            }
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
                total_bytes = total_bytes.saturating_add(entry.size);
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

#[derive(Default)]
struct PlannedOutputs {
    files: HashSet<PathBuf>,
    directories: HashSet<PathBuf>,
}

impl PlannedOutputs {
    fn insert(&mut self, path: &Path) -> Option<&'static str> {
        let issue = if self.files.contains(path) {
            Some("Another selected file has the same output path.")
        } else if self.directories.contains(path)
            || path
                .ancestors()
                .skip(1)
                .any(|parent| self.files.contains(parent))
        {
            Some("Selected outputs conflict: a file is also needed as a folder.")
        } else {
            None
        };
        self.files.insert(path.to_path_buf());
        self.directories
            .extend(path.ancestors().skip(1).map(Path::to_path_buf));
        issue
    }
}

fn preview_issue(
    input: &Path,
    output: Option<&Path>,
    key_path: Option<&Path>,
    overwrite: bool,
    duplicate: bool,
    all_inputs: &HashSet<PathBuf>,
    seen_outputs: &mut PlannedOutputs,
) -> Option<String> {
    if duplicate {
        return Some("This input was selected more than once.".into());
    }
    if key_path.is_some_and(|key| comparison_path(key) == comparison_path(input)) {
        return Some("This is the key file.".into());
    }
    let output = output?;
    let normalized = comparison_path(output);
    if let Some(issue) = seen_outputs.insert(&normalized) {
        return Some(issue.into());
    }
    if normalized.ancestors().any(|path| all_inputs.contains(path))
        || key_path.is_some_and(|key| normalized.starts_with(comparison_path(key)))
    {
        return Some("Output conflicts with an input or key file.".into());
    }
    for parent in output
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        match fs::metadata(parent) {
            Ok(metadata) if !metadata.is_dir() => {
                return Some("An output parent path is not a folder.".into())
            }
            Err(err) if err.kind() != io::ErrorKind::NotFound => {
                return Some(format!("Cannot inspect output folder: {err}"))
            }
            _ => {}
        }
    }
    match fs::symlink_metadata(output) {
        Ok(_) if !overwrite => {
            return Some("Output already exists. Choose a folder or enable replacement.".into())
        }
        Ok(metadata) if !metadata.is_file() => {
            return Some("Existing output is not a regular file.".into())
        }
        Err(err) if err.kind() != io::ErrorKind::NotFound => {
            return Some(format!("Cannot inspect output: {err}"))
        }
        _ => {}
    }
    None
}

fn zip_outcomes(
    key: &[u8; 32],
    input: &Path,
    options: &JobOptions,
    verify: bool,
    progress: &crypto::ProgressCallback<'_>,
    on_entry: &dyn Fn(usize, &archive_read::Entry),
    state: &AppState,
) -> Vec<FileOutcome> {
    let setup = (|| -> Result<_, CryptoError> {
        let source = Source::open(input, options.remove_original && !verify)?;
        let mut file = source.file.try_clone()?;
        let entries = archive_read::entries_from_reader(&mut file)?;
        let authenticated = archive_read::inspect_names_from_reader(&mut file, key, &entries)?.1;
        Ok((source, file, entries, authenticated))
    })();
    let (source, mut file, entries, authenticated) = match setup {
        Ok(value) => value,
        Err(err) => {
            return vec![FileOutcome {
                deletion: None,
                input: input.display().to_string(),
                output: None,
                original_name: None,
                ok: false,
                message: err.to_string(),
            }]
        }
    };
    let mut outcomes = Vec::with_capacity(entries.len());
    let mut all_ok = true;
    let mut protected = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let result = if state.cancelled.load(Ordering::Acquire)
            || state.emergency_locked.load(Ordering::Acquire)
        {
            Err(CryptoError::Io(io::Error::new(
                io::ErrorKind::Interrupted,
                "Not processed: job cancelled",
            )))
        } else {
            on_entry(index, entry);
            let mut entry_options = options.clone();
            entry_options.remove_original = false;
            if entry_options.output_dir.is_none() {
                entry_options.output_dir = input.parent().map(Path::to_path_buf);
            }
            archive_read::entry_reader(&mut file, entry, Some(progress)).and_then(|mut reader| {
                if verify {
                    crypto::verify_named_reader(key, &mut reader).map(|name| (None, Some(name)))
                } else {
                    crypto::decrypt_named_reader(
                        key,
                        input,
                        &mut reader,
                        &entry_options,
                        Some(progress),
                    )
                    .map(|published| (Some(published), None))
                }
            })
        };
        let ok = result.is_ok();
        all_ok &= ok;
        let output = match &result {
            Ok((Some(published), _)) => Some(published.path.display().to_string()),
            Err(CryptoError::PublicationUncertain { output, .. }) => Some(output.clone()),
            _ => None,
        };
        let original_name = match &result {
            Ok((_, name)) => name.clone(),
            Err(_) => None,
        };
        let message = match &result {
            Ok(_) if !authenticated => format!(
                "{}; older ZIP retained because its complete file list is unauthenticated",
                if verify {
                    "Verified entry"
                } else {
                    "Decrypted entry"
                }
            ),
            Ok(_) => {
                if verify {
                    "Verified".into()
                } else {
                    "Decrypted from ZIP".into()
                }
            }
            Err(err) => err.to_string(),
        };
        if let Ok((Some(published), _)) = result {
            protected.push(published);
        }
        outcomes.push(FileOutcome {
            deletion: None,
            input: format!("{} / {}", input.display(), entry.name),
            output,
            original_name,
            ok,
            message,
        });
    }
    drop(file);
    if !verify && options.remove_original {
        let removal = if !all_ok {
            Removal::retained(
                input,
                "ZIP retained because not every entry was restored successfully.",
            )
        } else if !authenticated {
            Removal::retained(
                input,
                "Older ZIP retained because its complete file list is unauthenticated.",
            )
        } else {
            deletion::remove(source, &protected, Some(progress))
        };
        if let Some(first) = outcomes.first_mut() {
            first.deletion = Some(register_removal(state, removal));
        }
    }
    outcomes
}

fn execute_job(
    app: &tauri::AppHandle,
    state: &AppState,
    request: JobRequest,
    preview: JobPreview,
) -> Result<Vec<FileOutcome>, String> {
    crate::emergency::ensure_unlocked(state)?;
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
        let mut last = lock(&last_emit);
        if force || last.elapsed() >= Duration::from_millis(80) {
            let (index, file, stage) = lock(&current).clone();
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
        if state.cancelled.load(Ordering::Acquire) || state.emergency_locked.load(Ordering::Acquire)
        {
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
            bundle_root(&request).as_deref(),
            request.compress,
            Some(&progress),
            Some(&on_entry),
        );
        let result = result.map_err(|err| err.to_string())?;
        for (input, removal) in request.paths.into_iter().zip(result.removals) {
            outcomes.push(transformed_outcome(
                state,
                input,
                crypto::TransformOutcome {
                    path: result.path.clone(),
                    removal,
                },
                "Encrypted into ZIP",
            ));
        }
        report(true);
        return Ok(outcomes);
    }
    for path in request.paths {
        if state.cancelled.load(Ordering::Acquire) || state.emergency_locked.load(Ordering::Acquire)
        {
            break;
        }
        let input = PathBuf::from(&path);
        let is_zip = input
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));
        if is_zip && request.operation != "encrypt" {
            let expected = preview
                .items
                .iter()
                .skip(preview_index)
                .take_while(|item| item.input.starts_with(&format!("{} / ", input.display())))
                .count()
                .max(1);
            let on_entry = |index: usize, entry: &archive_read::Entry| {
                *lock(&current) = (
                    preview_index + index,
                    format!("{} / {}", path, entry.name),
                    if request.operation == "verify" {
                        "Verifying".into()
                    } else {
                        "Decrypting".into()
                    },
                );
                report(true);
            };
            outcomes.extend(zip_outcomes(
                &key,
                &input,
                &options,
                request.operation == "verify",
                &progress,
                &on_entry,
                state,
            ));
            preview_index += expected;
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
                "encrypt" => crypto::encrypt_file_with_progress(&key, &input, &options, &progress)
                    .map(|result| (Some(result), None)),
                "decrypt" => crypto::decrypt_file_with_progress(&key, &input, &options, &progress)
                    .map(|result| (Some(result), None)),
                _ => crypto::verify_file(&key, &input, Some(&progress))
                    .map(|name| (None, Some(name))),
            };
            outcomes.push(match result {
                Ok((Some(result), _)) => transformed_outcome(
                    state,
                    path,
                    result,
                    if request.operation == "encrypt" {
                        "Encrypted"
                    } else {
                        "Decrypted"
                    },
                ),
                Ok((None, original_name)) => FileOutcome {
                    input: path,
                    output: None,
                    original_name,
                    ok: true,
                    message: "Verified".into(),
                    deletion: None,
                },
                Err(error) => failed_outcome(path, error),
            });
            preview_index += 1;
        }
    }
    if state.cancelled.load(Ordering::Acquire) || state.emergency_locked.load(Ordering::Acquire) {
        for item in preview.items.iter().skip(preview_index) {
            outcomes.push(FileOutcome {
                deletion: None,
                input: item.input.clone(),
                output: None,
                original_name: None,
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
    crate::emergency::ensure_unlocked(state)?;
    let bytes = key_file::read_key_snapshot(&path).map_err(|err| err.to_string())?;
    let key =
        key_file::parse_key_snapshot(&path, &bytes, passphrase).map_err(|err| err.to_string())?;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(bytes.as_slice()).into();
    let extra = remember_key(app, state, path, key, Some(hash))?;
    set_message(state, format!("Key loaded.{extra}"));
    Ok(status(state))
}

pub(crate) fn status(state: &AppState) -> AppStatus {
    let _key_change = lock(&state.key_change);
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
    let emergency_locked = state.emergency_locked.load(Ordering::Acquire);
    let message = if emergency_locked {
        crate::emergency::UNAVAILABLE.into()
    } else {
        lock(&state.message).clone()
    };
    let emergency = lock(&state.emergency);
    let emergency_deletion_path = emergency.armed_path();
    AppStatus {
        access_setup_required: crate::key_protection::setup_required(state),
        access_setup_is_upgrade: crate::key_protection::setup_is_upgrade(state),
        access_setup_requires_current_reference: crate::key_protection::needs_current_reference(state),
        access_setup_key_path: key_path.clone().or_else(|| crate::key_protection::default_key_path(state).map(|path| path.display().to_string())),
        emergency_locked,
        emergency_deletion_armed: emergency_deletion_path.is_some(),
        emergency_deletion_path,
        emergency_deletion_message: emergency.report.clone(),
        emergency_shortcuts_native: cfg!(windows),
        key_revision: state.key_revision.load(Ordering::Acquire),
        key_loaded,
        key_path,
        sandbox_available: key_loaded && lock(&state.key_file_hash).is_some(),
        output_dir,
        fingerprint,
        message,
        startup_key_unavailable: emergency_locked
            || state.startup_key_unavailable.load(Ordering::Acquire),
        updates_configured: updater_key().is_ok(),
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
    file_hash: Option<[u8; 32]>,
) -> Result<String, String> {
    let _key_change = lock(&state.key_change);
    crate::emergency::ensure_unlocked(state)?;
    crate::key_protection::cancel(state);
    lock(&state.emergency).disarm();
    crate::sandbox::revoke(state);
    *lock(&state.key) = Some(key);
    *lock(&state.key_path) = Some(path.clone());
    *lock(&state.key_file_hash) = file_hash;
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    let sandbox_note = if file_hash.is_none() {
        " Reload the key file to enable sandbox viewing."
    } else {
        ""
    };
    Ok(match write_settings(app, state) {
        Ok(()) => sandbox_note.into(),
        Err(err) => {
            format!(" The path could not be remembered for next launch: {err}{sandbox_note}")
        }
    })
}

// Caller holds key_change and has successfully removed the persistent lock.
pub(crate) fn finish_emergency_unlock(state: &AppState) {
    state
        .startup_key_unavailable
        .store(false, Ordering::Release);
    state.key_revision.fetch_add(1, Ordering::AcqRel);
    set_message(
        state,
        if lock(&state.key).is_some() {
            "Key loaded."
        } else {
            "Choose a key to get started."
        },
    );
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

pub(crate) fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|err| err.to_string())?;
    fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    Ok(dir.join("settings.json"))
}

fn write_settings(app: &tauri::AppHandle, state: &AppState) -> Result<(), String> {
    write_settings_to_path(state, &settings_path(app)?)
}

// Caller may hold key_change while committing first-launch protection.
pub(crate) fn write_settings_to_path(state: &AppState, path: &Path) -> Result<(), String> {
    let settings = Settings {
        key_path: lock(&state.key_path).clone(),
        output_dir: lock(&state.output_dir).clone(),
    };
    write_settings_file(path, &settings)
}

fn write_settings_file(path: &Path, settings: &Settings) -> Result<(), String> {
    let json = serde_json::to_string_pretty(settings).map_err(|err| err.to_string())?;
    crypto::atomic_write(path, json.as_bytes()).map_err(|err| err.to_string())
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
    fn completed_rotation_survives_emergency_lock_during_activation() {
        let state = AppState::default();
        let deletion = Removal::retained(Path::new("input.fenc"), "locked original").info;
        lock(&state.deletions)
            .confirmed
            .insert("previous".into(), deletion.clone());
        let batch = DeletionBatch::new(&state);
        #[cfg(windows)]
        let dir = crate::test_support::TestDir::new();
        #[cfg(windows)]
        let deletion = register_removal(&state, crate::test_support::retained_removal(&dir));
        let retry_id = deletion.retry_id.clone();
        let report = finish_rotation(
            &state,
            batch,
            vec![FileOutcome {
                deletion: Some(deletion),
                input: "input.fenc".into(),
                output: Some("rotated.fenc".into()),
                original_name: None,
                ok: true,
                message: "Rotated".into(),
            }],
            1,
            Path::new("new.key"),
            || {
                state.emergency_locked.store(true, Ordering::Release);
                crate::emergency::ensure_unlocked(&state)?;
                Ok(String::new())
            },
        );
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].ok);
        assert!(report.results[0].deletion.is_some());
        assert!(report.status.emergency_locked);
        assert_eq!(report.new_key_path, "new.key");
        assert!(report.notice.as_deref().unwrap().contains("new.key"));
        assert!(lock(&state.deletions).staged.is_none());
        assert!(lock(&state.deletions).confirmed.is_empty());
        if let Some(id) = retry_id {
            assert!(lock(&state.deletions).current.contains_key(&id));
        }
        assert!(lock(&state.key).is_none());
    }

    #[test]
    fn partial_rotation_does_not_activate_the_new_key() {
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new([4; 32]));
        let report = finish_rotation(
            &state,
            DeletionBatch::new(&state),
            vec![],
            2,
            Path::new("new.key"),
            || panic!("partial rotation must retain the old key"),
        );
        assert!(report.notice.unwrap().contains("incomplete"));
        assert_eq!(lock(&state.key).as_ref().unwrap().as_slice(), &[4; 32]);
    }

    #[test]
    fn rotation_checks_the_recovery_key_before_publishing_or_deleting() {
        let dir = crate::test_support::TestDir::new();
        let input = dir.0.join("input.txt");
        fs::write(&input, b"keep this recoverable").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("encrypted")),
        };
        let old_key = [4; 32];
        let encrypted = crypto::encrypt_file(&old_key, &input, &options).unwrap();
        let new_key = [5; 32];
        let key_path = dir.0.join("new.key");
        let saved_key = key_file::create_rotation_key(&key_path, &new_key, None, None).unwrap();
        let state = AppState::default();
        let attempted = AtomicBool::new(false);
        let progress = |bytes| {
            if bytes > 0 && !attempted.swap(true, Ordering::AcqRel) {
                #[cfg(windows)]
                {
                    assert!(fs::remove_file(&key_path).is_err());
                    assert!(fs::write(&key_path, b"replacement").is_err());
                }
                #[cfg(not(windows))]
                fs::remove_file(&key_path)?;
            }
            check_rotation(&state, Some(&saved_key))
        };
        let rotation = JobOptions {
            remove_original: true,
            output_dir: Some(dir.0.join("rotated")),
            ..options
        };
        let result = crypto::rotate_file_with_deletion(
            &old_key,
            &new_key,
            &encrypted,
            &rotation,
            Some(&progress),
        );
        assert!(attempted.load(Ordering::Acquire));
        #[cfg(windows)]
        {
            let result = result.unwrap();
            assert_eq!(result.removal.info.state, DeletionState::Removed);
            assert!(!encrypted.exists());
            assert!(crypto::inspect_output_name(&new_key, &result.path).is_ok());
            assert!(saved_key.checked_hash().is_ok());
        }
        #[cfg(not(windows))]
        {
            assert!(result.is_err());
            assert!(encrypted.exists());
        }
    }

    #[test]
    fn preview_blocks_output_file_and_folder_conflicts_in_either_order() {
        let dir = crate::test_support::TestDir::new();
        let input = dir.0.join("input.fenc");
        let outputs = [
            dir.0.join("restored/report.txt"),
            dir.0.join("restored/report.txt/notes.txt"),
        ];
        for order in [[0, 1], [1, 0]] {
            let mut seen = PlannedOutputs::default();
            assert!(preview_issue(
                &input,
                Some(&outputs[order[0]]),
                None,
                false,
                false,
                &HashSet::new(),
                &mut seen
            )
            .is_none());
            let issue = preview_issue(
                &input,
                Some(&outputs[order[1]]),
                None,
                false,
                false,
                &HashSet::new(),
                &mut seen,
            )
            .unwrap();
            assert!(issue.contains("also needed as a folder"));
        }
        fs::create_dir_all(dir.0.join("restored")).unwrap();
        fs::write(&outputs[0], b"existing file").unwrap();
        let issue = preview_issue(
            &input,
            Some(&outputs[1]),
            None,
            false,
            false,
            &HashSet::new(),
            &mut PlannedOutputs::default(),
        )
        .unwrap();
        assert!(issue.contains("not a folder"));
    }

    #[test]
    fn preview_rejects_conflicting_paths_from_separate_valid_bundles() {
        let dir = crate::test_support::TestDir::new();
        let key = [4; 32];
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("encrypted")),
        };
        let mut bundles = Vec::new();
        for (folder, relative) in [("one", "report.txt"), ("two", "report.txt/notes.txt")] {
            let root = dir.0.join(folder);
            let input = root.join(relative);
            fs::create_dir_all(input.parent().unwrap()).unwrap();
            fs::write(&input, b"bundle contents").unwrap();
            let bundle = archive::encrypt_to_zip_with_progress(
                &key,
                &[input],
                &options,
                Some(&root),
                false,
                None,
                None,
            )
            .unwrap();
            bundles.push(bundle.path.display().to_string());
        }
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new(key));
        for paths in [bundles.clone(), bundles.into_iter().rev().collect()] {
            let request = JobRequest {
                paths,
                folder_roots: HashMap::new(),
                output_dir: dir.0.join("restored").display().to_string(),
                overwrite: false,
                remove_original: true,
                zip: false,
                compress: false,
                operation: "decrypt".into(),
            };
            let preview = plan_job(&state, &request).unwrap();
            assert!(!preview.can_run);
            assert!(preview.items.iter().any(|item| item
                .issue
                .as_deref()
                .is_some_and(|issue| issue.contains("also needed as a folder"))));
            assert!(!dir.0.join("restored").exists());
            assert!(request.paths.iter().all(|path| Path::new(path).exists()));
        }
    }

    #[test]
    fn emergency_browse_opens_the_picker_but_rejects_selection_without_changing_keys() {
        let state = AppState::default();
        let saved = PathBuf::from("saved.key");
        *lock(&state.key_path) = Some(saved.clone());
        state.emergency_locked.store(true, Ordering::Release);
        let mut picker_opened = false;
        let result = pick_key_for_load(&state, || {
            picker_opened = true;
            Ok(Some(PathBuf::from(
                "a-different-key-that-does-not-exist.key",
            )))
        });
        assert!(picker_opened);
        assert_eq!(result.unwrap_err(), crate::emergency::UNAVAILABLE);
        assert_eq!(*lock(&state.key_path), Some(saved));
        assert!(lock(&state.key).is_none());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(pick_key_for_load(&state, || Ok(None)).unwrap().is_none());
        assert!(state.emergency_locked.load(Ordering::Acquire));
    }

    #[test]
    fn emergency_lock_rejects_typed_activation_and_delayed_key_snapshots() {
        let dir = crate::test_support::TestDir::new();
        let state = AppState::default();
        let path = dir.0.join("saved.key");
        key_file::write_key_file(&path, &[42; 32]).unwrap();
        restore_saved_key_from_path(&state, &path);
        let check = KeyFileCheck {
            revision: state.key_revision.load(Ordering::Acquire),
            path: path.clone(),
            loaded: false,
            expected_hash: *lock(&state.key_file_hash),
        };
        let snapshot = key_file::read_key_snapshot(&path);
        state.emergency_locked.store(true, Ordering::Release);
        deactivate_file_key(&state, true, crate::emergency::UNAVAILABLE.into());
        assert!(!finish_key_file_check(&state, check, snapshot));
        assert!(lock(&state.key).is_none());
        let settings_path = dir.0.join("settings.json");
        assert_eq!(
            activate_session_key(&state, Zeroizing::new([9; 32]), &settings_path).unwrap_err(),
            crate::emergency::UNAVAILABLE
        );
        assert!(!settings_path.exists());
        assert!(lock(&state.key).is_none());
    }

    #[test]
    fn session_key_is_not_saved_or_restored_and_supports_file_jobs() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-session-key-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let old_path = root.join("previous.key");
        let settings_path = root.join("settings.json");
        let output_dir = root.join("outputs");
        let old_key = [3; 32];
        key_file::write_key_file(&old_path, &old_key).unwrap();
        let original_key_file = fs::read(&old_path).unwrap();
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new(old_key));
        *lock(&state.key_path) = Some(old_path.clone());
        *lock(&state.output_dir) = Some(output_dir.clone());
        state.startup_key_unavailable.store(true, Ordering::Release);
        write_settings_file(
            &settings_path,
            &Settings {
                key_path: Some(old_path.clone()),
                output_dir: Some(output_dir.clone()),
            },
        )
        .unwrap();

        let key = [7; 32];
        activate_session_key(&state, Zeroizing::new(key), &settings_path).unwrap();
        let current = status(&state);
        assert!(current.key_loaded);
        assert!(current.key_path.is_none());
        assert!(!current.startup_key_unavailable);
        assert!(!refresh_key_file(&state));
        assert_eq!(current.fingerprint, Some(key_file::fingerprint(&key)));
        assert_eq!(fs::read(&old_path).unwrap(), original_key_file);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);

        let settings: Settings =
            serde_json::from_slice(&fs::read(&settings_path).unwrap()).unwrap();
        assert!(settings.key_path.is_none());
        assert_eq!(settings.output_dir, Some(output_dir.clone()));
        let reopened = AppState::default();
        restore_saved_settings(&reopened, settings);
        assert!(!status(&reopened).key_loaded);
        assert!(status(&reopened).key_path.is_none());
        assert!(!status(&reopened).startup_key_unavailable);
        assert_eq!(*lock(&reopened.output_dir), Some(output_dir));

        let input = root.join("payload.txt");
        fs::write(&input, b"session-only payload").unwrap();
        let mut request = JobRequest {
            paths: vec![input.display().to_string()],
            folder_roots: HashMap::new(),
            output_dir: String::new(),
            overwrite: false,
            remove_original: false,
            zip: false,
            compress: false,
            operation: "encrypt".into(),
        };
        assert!(plan_job(&state, &request).unwrap().can_run);
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: lock(&state.key_path).clone(),
            output_dir: None,
        };
        let active_key = lock(&state.key).clone().unwrap();
        let encrypted = crypto::encrypt_file(&active_key, &input, &options).unwrap();
        request.paths = vec![encrypted.display().to_string()];
        request.operation = "verify".into();
        assert!(plan_job(&state, &request).unwrap().can_run);
        crypto::verify_file(&active_key, &encrypted, None).unwrap();
        fs::remove_file(&input).unwrap();
        request.operation = "decrypt".into();
        assert!(plan_job(&state, &request).unwrap().can_run);
        let restored = crypto::decrypt_file(&active_key, &encrypted, &options).unwrap();
        assert_eq!(fs::read(restored).unwrap(), b"session-only payload");
        drop(active_key);

        clear_key_on_close(&state);
        assert!(!status(&state).key_loaded);
        assert!(status(&state).fingerprint.is_none());
        assert!(state.cancelled.load(Ordering::Acquire));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_session_preferences_write_preserves_the_loaded_key() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-session-key-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let blocked = root.join("settings.json");
        fs::create_dir(&blocked).unwrap();
        let state = AppState::default();
        let old_key = [3; 32];
        let old_path = root.join("previous.key");
        *lock(&state.key) = Some(Zeroizing::new(old_key));
        *lock(&state.key_path) = Some(old_path.clone());

        assert!(activate_session_key(&state, Zeroizing::new([7; 32]), &blocked).is_err());
        assert_eq!(
            status(&state).fingerprint,
            Some(key_file::fingerprint(&old_key))
        );
        assert_eq!(*lock(&state.key_path), Some(old_path));
        assert!(blocked.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_saved_key_warns_and_can_be_loaded_after_reconnecting() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-startup-key-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        let path = root.join("usb.key");
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new([9; 32]));

        restore_saved_key_from_path(&state, &path);
        let current = status(&state);
        assert!(!current.key_loaded);
        assert!(current.fingerprint.is_none());
        assert_eq!(current.key_path.as_deref(), path.to_str());
        assert!(current.startup_key_unavailable);
        assert!(current.message.contains("saved key file is unavailable"));
        let payload = serde_json::to_value(&current).unwrap();
        assert_eq!(payload["startupKeyUnavailable"], true);
        assert_eq!(payload["keyRevision"], current.key_revision);
        assert!(!refresh_key_file(&state));

        fs::create_dir(&root).unwrap();
        let key = [7; 32];
        key_file::write_key_file(&path, &key).unwrap();
        assert!(refresh_key_file(&state));
        let current = status(&state);
        assert!(current.key_loaded);
        assert!(current.sandbox_available);
        assert!(!current.startup_key_unavailable);
        assert_eq!(current.fingerprint, Some(key_file::fingerprint(&key)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removed_key_unloads_cancels_and_reloads_only_after_the_job_stops() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-key-monitor-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("usb.key");
        let key = [7; 32];
        key_file::write_key_file(&path, &key).unwrap();
        let bytes = fs::read(&path).unwrap();
        let state = AppState::default();
        restore_saved_key_from_path(&state, &path);
        let hash = *lock(&state.key_file_hash);
        let revision = status(&state).key_revision;
        state.running.store(true, Ordering::Release);

        fs::remove_file(&path).unwrap();
        assert!(refresh_key_file(&state));
        let current = status(&state);
        assert!(!current.key_loaded);
        assert!(!current.sandbox_available);
        assert!(current.fingerprint.is_none());
        assert!(current.startup_key_unavailable);
        assert_eq!(current.key_path.as_deref(), path.to_str());
        assert!(current.key_revision > revision);
        assert_eq!(*lock(&state.key_file_hash), hash);
        assert!(state.cancelled.load(Ordering::Acquire));
        assert!(!refresh_key_file(&state));

        fs::write(&path, bytes).unwrap();
        assert!(!refresh_key_file(&state));
        state.running.store(false, Ordering::Release);
        assert!(refresh_key_file(&state));
        let current = status(&state);
        assert!(current.key_loaded);
        assert!(current.sandbox_available);
        assert!(!current.startup_key_unavailable);
        assert_eq!(current.fingerprint, Some(key_file::fingerprint(&key)));
        assert!(!refresh_key_file(&state));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn changed_key_file_never_silently_switches_the_loaded_key() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-key-monitor-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("usb.key");
        let state = AppState::default();
        for disconnect_first in [false, true] {
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            key_file::write_key_file(&path, &[7; 32]).unwrap();
            restore_saved_key_from_path(&state, &path);
            fs::remove_file(&path).unwrap();
            if disconnect_first {
                assert!(refresh_key_file(&state));
                assert!(status(&state).startup_key_unavailable);
            }
            key_file::write_key_file(&path, &[8; 32]).unwrap();
            assert!(refresh_key_file(&state));
            let current = status(&state);
            assert!(!current.key_loaded);
            assert!(!current.startup_key_unavailable);
            assert!(current.message.contains("key file changed"));
            assert!(!refresh_key_file(&state));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protected_key_reconnection_clears_disconnect_and_keeps_the_passphrase_error() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-key-monitor-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("usb.key");
        let state = AppState::default();
        restore_saved_key_from_path(&state, &path);
        assert!(status(&state).startup_key_unavailable);
        // The protected header requests a passphrase before sealed bytes are decoded.
        fs::write(
            &path,
            "FileEncrypt-Key-v2\npbkdf2-sha256:600000\nunused\nunused\nunused\n",
        )
        .unwrap();
        assert!(refresh_key_file(&state));
        let current = status(&state);
        assert!(!current.startup_key_unavailable);
        assert!(!current.key_loaded);
        assert!(current.message.contains("needs its passphrase"));
        assert!(!refresh_key_file(&state));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delayed_file_reads_cannot_reverse_an_explicit_unload() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-key-monitor-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("usb.key");
        key_file::write_key_file(&path, &[7; 32]).unwrap();
        let state = AppState::default();
        restore_saved_key_from_path(&state, &path);
        let check = KeyFileCheck {
            revision: state.key_revision.load(Ordering::Acquire),
            path: path.clone(),
            loaded: true,
            expected_hash: *lock(&state.key_file_hash),
        };
        unload_key_from_memory(&state);
        assert!(!finish_key_file_check(
            &state,
            check,
            Err(io::Error::from(io::ErrorKind::NotFound).into())
        ));
        assert!(!status(&state).startup_key_unavailable);
        assert_eq!(status(&state).message, "Key unloaded from memory.");
        assert!(!refresh_key_file(&state));

        restore_saved_key_from_path(&state, &path);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(refresh_key_file(&state));
        let check = KeyFileCheck {
            revision: state.key_revision.load(Ordering::Acquire),
            path: path.clone(),
            loaded: false,
            expected_hash: *lock(&state.key_file_hash),
        };
        fs::write(&path, bytes).unwrap();
        let snapshot = key_file::read_key_snapshot(&path);
        unload_key_from_memory(&state);
        assert!(!finish_key_file_check(&state, check, snapshot));
        assert!(!status(&state).key_loaded);
        assert!(!status(&state).startup_key_unavailable);
        assert!(!refresh_key_file(&state));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_protected_or_invalid_key_does_not_show_disconnected_warning() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-startup-key-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("protected.key");
        // A v2 header reaches the passphrase check before decoding the sealed key.
        fs::write(
            &path,
            "FileEncrypt-Key-v2\npbkdf2-sha256:600000\nunused\nunused\nunused\n",
        )
        .unwrap();
        let state = AppState::default();
        restore_saved_key_from_path(&state, &path);
        assert!(!status(&state).startup_key_unavailable);
        assert!(!status(&state).key_loaded);
        assert!(status(&state).message.contains("needs its passphrase"));

        fs::write(&path, "not a key file").unwrap();
        restore_saved_key_from_path(&state, &path);
        assert!(!status(&state).startup_key_unavailable);
        assert!(!status(&state).key_loaded);
        assert!(status(&state)
            .message
            .contains("Could not load the saved key"));
        fs::remove_dir_all(root).unwrap();
    }

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
            folder_roots: HashMap::new(),
            output_dir: destination.display().to_string(),
            overwrite: true,
            remove_original: false,
            zip: false,
            compress: false,
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
    fn preview_blocks_replacing_a_directory() {
        let root = std::env::temp_dir().join(format!(
            "fileencrypt-plan-test-{}",
            crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&root).unwrap();
        let input = root.join("input.fenc");
        let output = root.join("restored.txt");
        fs::write(&input, b"input").unwrap();
        fs::create_dir(&output).unwrap();

        let issue = preview_issue(
            &input,
            Some(&output),
            None,
            true,
            false,
            &HashSet::from([comparison_path(&input)]),
            &mut PlannedOutputs::default(),
        );
        assert_eq!(
            issue.as_deref(),
            Some("Existing output is not a regular file.")
        );
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
        let selection = expand_paths_with_roots(vec![root.display().to_string()]).unwrap();
        assert_eq!(selection.paths, files);
        assert!(selection
            .roots
            .values()
            .all(|path| path == &root.display().to_string()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn backup_writes_the_validated_snapshot_even_when_the_source_changes() {
        let root = std::env::temp_dir().join(crypto::opaque_file_name());
        fs::create_dir(&root).unwrap();
        let input = root.join("source.key");
        let backup = root.join("backup.key");
        let old = [1; 32];
        let new = [2; 32];
        key_file::write_key_file(&input, &old).unwrap();
        let snapshot = key_file::read_key_snapshot(&input).unwrap();
        key_file::write_key_file(&input, &new).unwrap();
        write_checked_backup(&backup, &snapshot, &old, None).unwrap();
        assert_eq!(*key_file::read_key_file(&backup).unwrap(), old);
        assert!(write_checked_backup(&root.join("wrong.key"), &snapshot, &new, None).is_err());
        assert!(!root.join("wrong.key").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_late_zip_setup_error_is_an_outcome_and_preserves_completed_results() {
        let key = [1; 32];
        let mut results = vec![FileOutcome {
            deletion: None,
            input: "first.fenc".into(),
            output: Some("first.txt".into()),
            original_name: None,
            ok: true,
            message: "Decrypted".into(),
        }];
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        };
        let missing = std::env::temp_dir().join(crypto::opaque_file_name());
        results.extend(zip_outcomes(
            &key,
            &missing,
            &options,
            false,
            &|_| Ok(()),
            &|_, _| {},
            &AppState::default(),
        ));
        assert_eq!(results.len(), 2);
        assert!(results[0].ok);
        assert!(!results[1].ok);
        assert!(results[1].output.is_none());
    }
    #[test]
    fn zip_jobs_stream_verify_restore_delete_and_preserve_sources_on_failure() {
        let root = std::env::temp_dir().join(crypto::opaque_file_name());
        fs::create_dir(&root).unwrap();
        let a = root.join("a.txt");
        let b = root.join("b.txt");
        fs::write(&a, b"first file").unwrap();
        fs::write(&b, vec![7; 150_000]).unwrap();
        let key = [4; 32];
        let encryption = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(root.join("archives")),
        };
        for compress in [false, true] {
            let archive = archive::encrypt_to_zip_with_progress(
                &key,
                &[a.clone(), b.clone()],
                &encryption,
                None,
                compress,
                None,
                None,
            )
            .unwrap()
            .path;
            let restore = JobOptions {
                remove_original: true,
                output_dir: Some(root.join("restored")),
                ..encryption.clone()
            };
            let verified = zip_outcomes(
                &key,
                &archive,
                &restore,
                true,
                &|_| Ok(()),
                &|_, _| {},
                &AppState::default(),
            );
            assert_eq!(verified.len(), 2);
            assert!(verified.iter().all(|r| r.ok));
            assert_eq!(verified[0].original_name.as_deref(), Some("a.txt"));
            assert_eq!(verified[1].original_name.as_deref(), Some("b.txt"));
            assert!(verified
                .iter()
                .all(|r| r.output.is_none() && r.deletion.is_none()));
            assert_eq!(
                serde_json::to_value(&verified[0]).unwrap()["originalName"],
                "a.txt"
            );
            assert!(archive.exists());
            assert!(!root.join("restored").exists());
            let damaged = root.join("damaged.zip");
            let mut bytes = fs::read(&archive).unwrap();
            let entries = archive_read::entries(&archive).unwrap();
            bytes[(entries[0].data_offset + entries[0].size - 1) as usize] ^= 1;
            fs::write(&damaged, bytes).unwrap();
            let failed = zip_outcomes(
                &key,
                &damaged,
                &restore,
                false,
                &|_| Ok(()),
                &|_, _| {},
                &AppState::default(),
            );
            assert!(!failed[0].ok);
            assert!(failed[1].ok);
            assert!(damaged.exists());
            assert!(!root.join("restored/a.txt").exists());
            fs::remove_file(root.join("restored/b.txt")).unwrap();
            let restored = zip_outcomes(
                &key,
                &archive,
                &restore,
                false,
                &|_| Ok(()),
                &|_, _| {},
                &AppState::default(),
            );
            assert!(restored.iter().all(|r| r.ok));
            assert_eq!(archive.exists(), !cfg!(windows));
            assert_eq!(
                fs::read(root.join("restored/a.txt")).unwrap(),
                b"first file"
            );
            assert_eq!(
                fs::read(root.join("restored/b.txt")).unwrap(),
                vec![7; 150_000]
            );
            assert!(!fs::read_dir(root.join("restored")).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fe-")));
            fs::remove_dir_all(root.join("restored")).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn all_restored_zip_outputs_stay_protected_until_source_deletion() {
        let dir = crate::test_support::TestDir::new();
        let first = dir.0.join("first.txt");
        let second = dir.0.join("second.txt");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let options = JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: Some(dir.0.join("encrypted")),
        };
        let key = [4; 32];
        let archive = archive::encrypt_to_zip(&key, &[first, second], &options)
            .unwrap()
            .path;
        let restore = JobOptions {
            remove_original: true,
            output_dir: Some(dir.0.join("restored")),
            ..options
        };
        let first_output = dir.0.join("restored/first.txt");
        let attacked = AtomicBool::new(false);
        let on_entry = |index, _: &archive_read::Entry| {
            if index == 1 {
                assert!(first_output.exists());
                assert!(fs::write(&first_output, b"changed").is_err());
                assert!(fs::remove_file(&first_output).is_err());
                attacked.store(true, Ordering::Relaxed);
            }
        };
        let results = zip_outcomes(
            &key,
            &archive,
            &restore,
            false,
            &|_| Ok(()),
            &on_entry,
            &AppState::default(),
        );
        assert!(attacked.load(Ordering::Relaxed));
        assert!(results.iter().all(|r| r.ok));
        assert_eq!(
            results[0].deletion.as_ref().unwrap().state,
            DeletionState::Removed
        );
        assert!(!archive.exists());
        assert_eq!(fs::read(first_output).unwrap(), b"first");
        assert_eq!(
            fs::read(dir.0.join("restored/second.txt")).unwrap(),
            b"second"
        );
    }
    #[cfg(windows)]
    #[test]
    fn extra_streams_are_preserved_during_bundle_creation_restoration_and_rotation() {
        use crate::deletion::DeletionState;
        let dir = crate::test_support::TestDir::new();
        let first = dir.0.join("first.txt");
        let second = dir.0.join("second.txt");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let extra = crate::test_support::add_stream(&second, "extra", b"keep source stream");
        let options = JobOptions {
            overwrite: false,
            remove_original: true,
            key_file: None,
            output_dir: Some(dir.0.join("encrypted")),
        };
        let key = [4; 32];
        let bundle =
            archive::encrypt_to_zip(&key, &[first.clone(), second.clone()], &options).unwrap();
        assert_eq!(bundle.removals[0].info.state, DeletionState::Removed);
        assert_eq!(bundle.removals[1].info.state, DeletionState::Retained);
        assert!(bundle.removals[1].retry.is_none());
        assert!(!first.exists());
        assert_eq!(fs::read(second).unwrap(), b"second");
        assert_eq!(fs::read(extra).unwrap(), b"keep source stream");

        let zip_bytes = fs::read(&bundle.path).unwrap();
        let zip_extra = crate::test_support::add_stream(&bundle.path, "extra", b"keep ZIP stream");
        let rotation = JobOptions {
            output_dir: Some(dir.0.join("rotated")),
            ..options.clone()
        };
        let rotated =
            archive::rotate_zip_with_deletion(&key, &[5; 32], &bundle.path, &rotation, None)
                .unwrap();
        assert_eq!(rotated.removal.info.state, DeletionState::Retained);
        assert!(rotated.removal.retry.is_none());
        let entries = archive_read::entries(&rotated.path).unwrap();
        assert_eq!(
            archive_read::inspect_names(&rotated.path, &[5; 32], &entries).unwrap(),
            ["first.txt", "second.txt"]
        );

        let restore = JobOptions {
            output_dir: Some(dir.0.join("restored")),
            ..options
        };
        let results = zip_outcomes(
            &key,
            &bundle.path,
            &restore,
            false,
            &|_| Ok(()),
            &|_, _| {},
            &AppState::default(),
        );
        assert!(results.iter().all(|result| result.ok));
        let deletion = results[0].deletion.as_ref().unwrap();
        assert_eq!(deletion.state, DeletionState::Retained);
        assert!(deletion.retry_id.is_none());
        assert_eq!(fs::read(&bundle.path).unwrap(), zip_bytes);
        assert_eq!(fs::read(zip_extra).unwrap(), b"keep ZIP stream");
        assert_eq!(
            fs::read(dir.0.join("restored/first.txt")).unwrap(),
            b"first"
        );
        assert_eq!(
            fs::read(dir.0.join("restored/second.txt")).unwrap(),
            b"second"
        );
    }

    #[cfg(windows)]
    #[test]
    fn new_reports_have_retry_capacity_even_when_the_previous_report_is_full() {
        let dir = crate::test_support::TestDir::new();
        let fixture = crate::test_support::retained_removal(&dir);
        let make_removal = || Removal {
            info: fixture.info.clone(),
            retry: fixture.retry.clone(),
        };
        let state = AppState::default();
        let old_batch = DeletionBatch::new(&state);
        for _ in 0..MAX_DELETION_RECEIPTS {
            assert!(register_removal(&state, make_removal()).retry_id.is_some());
        }
        let overflow = register_removal(&state, make_removal());
        assert!(overflow.retry_id.is_none());
        assert!(overflow.reason.unwrap().contains("10,000-receipt limit"));
        old_batch.commit();
        assert_eq!(lock(&state.deletions).current.len(), MAX_DELETION_RECEIPTS);
        let new_batch = DeletionBatch::new(&state);
        let latest = register_removal(&state, make_removal()).retry_id.unwrap();
        assert_eq!(lock(&state.deletions).current.len(), MAX_DELETION_RECEIPTS);
        new_batch.commit();
        assert_eq!(lock(&state.deletions).current.len(), 1);
        assert!(lock(&state.deletions).current.contains_key(&latest));
        // A subsequent report without retryable originals retires the previous receipt.
        DeletionBatch::new(&state).commit();
        assert!(lock(&state.deletions).current.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn a_failed_report_preserves_retries_for_the_still_displayed_results() {
        let dir = crate::test_support::TestDir::new();
        let fixture = crate::test_support::retained_removal(&dir);
        let make_removal = || Removal {
            info: fixture.info.clone(),
            retry: fixture.retry.clone(),
        };
        let state = AppState::default();
        let original = register_removal(&state, make_removal()).retry_id.unwrap();
        {
            let _failed_batch = DeletionBatch::new(&state);
            assert!(register_removal(&state, make_removal()).retry_id.is_some());
        }
        let registry = lock(&state.deletions);
        assert_eq!(registry.current.len(), 1);
        assert!(registry.current.contains_key(&original));
        assert!(registry.staged.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn automatic_checks_confirm_deletion_without_revalidating_outputs_or_blocking_jobs() {
        let dir = crate::test_support::TestDir::new();
        let (original, saved, reader, ticket) = deletion::pending_fixture(&dir.0);
        let state = AppState::default();
        let info = register_removal(
            &state,
            Removal {
                info: DeletionInfo {
                    state: DeletionState::Pending,
                    source: original.display().to_string(),
                    reason: None,
                    retry_id: None,
                },
                retry: Some(ticket),
            },
        );
        let id = info.retry_id.unwrap();
        state.running.store(true, Ordering::Release);
        state.cancelled.store(true, Ordering::Release);
        fs::remove_file(saved).unwrap();
        let pending = pending_deletion_updates(&state, &[id.clone(), id.clone()]);
        assert_eq!(pending.len(), 1);
        let info = pending[0].deletion.as_ref().unwrap();
        assert_eq!(info.state, DeletionState::Pending);
        assert_eq!(info.retry_id.as_ref(), Some(&id));
        assert!(state.running.load(Ordering::Acquire));
        assert!(state.cancelled.load(Ordering::Acquire));
        assert_eq!(lock(&state.deletions).current.len(), 1);

        drop(reader);
        let removed = pending_deletion_updates(&state, std::slice::from_ref(&id));
        let info = removed[0].deletion.as_ref().unwrap();
        assert_eq!(info.state, DeletionState::Removed);
        assert!(info.retry_id.is_none());
        assert!(!original.exists());
        assert_eq!(lock(&state.deletions).confirmed.len(), 1);
        // A lost response can be recovered without querying a replacement or
        // turning a confirmed deletion back into pending.
        fs::write(&original, b"replacement").unwrap();
        {
            let _failed_report = DeletionBatch::new(&state);
        }
        let repeated = pending_deletion_updates(&state, std::slice::from_ref(&id));
        assert_eq!(
            repeated[0].deletion.as_ref().unwrap().state,
            DeletionState::Removed
        );
        assert_eq!(fs::read(original).unwrap(), b"replacement");
        DeletionBatch::new(&state).commit();
        assert!(lock(&state.deletions).current.is_empty());
        assert!(lock(&state.deletions).confirmed.is_empty());
        assert!(pending_deletion_updates(&state, &[id])[0]
            .deletion
            .is_none());
    }

    #[cfg(windows)]
    #[test]
    fn automatic_status_checks_never_retry_retained_files_or_resurrect_expired_receipts() {
        let dir = crate::test_support::TestDir::new();
        let state = AppState::default();
        let info = register_removal(&state, crate::test_support::retained_removal(&dir));
        let id = info.retry_id.unwrap();
        let updates = pending_deletion_updates(&state, std::slice::from_ref(&id));
        assert!(updates[0].deletion.is_none());
        assert_eq!(fs::read(&info.source).unwrap(), b"bytes");
        assert!(lock(&state.deletions).current.contains_key(&id));

        DeletionBatch::new(&state).commit();
        assert!(pending_deletion_updates(&state, &[id])[0]
            .deletion
            .is_none());
        assert!(lock(&state.deletions).current.is_empty());
        assert_eq!(fs::read(info.source).unwrap(), b"bytes");
    }
}
