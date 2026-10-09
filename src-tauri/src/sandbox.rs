//! Read-only previews. Plaintext is bounded, authenticated in memory, and never
//! passed to a filesystem writer or an external application.
use std::collections::{HashMap, HashSet};
use std::fmt::NumBuffer;
use std::io::{self, BufReader, Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
use zeroize::{Zeroize, Zeroizing};

use crate::commands::{lock, AppState};
use crate::{archive_read, crypto, key_file, source::Source};

const MAX_ITEMS: usize = 10_000;
const MAX_PREVIEW_BYTES: usize = 32 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_IMAGE_PIXELS: u64 = 40_000_000;
const MAX_IMAGE_DIMENSION: u32 = 16_384;
const MAX_PREVIEW_MEMORY: usize = 512 * 1024 * 1024;
const MAX_PREVIEW_WINDOWS: usize = 8;
const CANCELLED: &str = "Preview cancelled.";
const LOCKED: &str =
    "Sandbox locked. The loaded key or its readable key file is no longer available.";

#[derive(Default)]
pub(crate) struct Registry {
    revision: u64,
    current: Option<Arc<Session>>,
    previews: HashMap<String, PreviewTarget>,
    next_preview: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewTarget {
    session_id: String,
    item_id: usize,
    #[serde(skip)]
    cancelled: Arc<AtomicBool>,
    #[serde(skip)]
    memory_bytes: usize,
}

impl PreviewTarget {
    fn new(session_id: String, item_id: usize) -> Self {
        Self {
            session_id,
            item_id,
            cancelled: Arc::new(AtomicBool::new(false)),
            memory_bytes: 0,
        }
    }

    fn check(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(CANCELLED.into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosedPreview {
    session_id: String,
    item_id: usize,
    locked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewInfo {
    session_id: String,
    item: CatalogItem,
    navigation: ImageNavigation,
}

#[derive(Default, Serialize)]
struct ImageNavigation {
    previous: bool,
    next: bool,
    index: usize,
    total: usize,
}

struct Session {
    id: String,
    key: Zeroizing<[u8; 32]>,
    key_path: PathBuf,
    file_hash: [u8; 32],
    revoked: AtomicBool,
    reading: AtomicBool,
    preview_read: Mutex<()>,
    items: Vec<Item>,
    #[cfg(windows)]
    archives: HashMap<PathBuf, Mutex<CachedZip>>,
}

#[cfg(windows)]
struct CachedZip {
    // Windows sharing protection keeps the authenticated directory and names
    // valid for this exact source. The selected body is authenticated on every read.
    source: Source,
    entries: Vec<archive_read::Entry>,
}

struct Item {
    source: PathBuf,
    zip_index: Option<usize>,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    session_id: String,
    items: Vec<CatalogItem>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct CatalogItem {
    id: usize,
    name: String,
    kind: &'static str,
}

#[derive(Serialize)]
pub struct Content {
    kind: &'static str,
    mime: &'static str,
    data: String,
}

impl Drop for Content {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

fn format(name: &str) -> (&'static str, &'static str) {
    let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "txt" | "md" | "csv" | "tsv" | "json" | "jsonl" | "log" | "xml" | "yaml" | "yml"
        | "toml" | "ini" | "conf" | "html" | "htm" | "svg" | "css" | "js" | "ts" | "jsx"
        | "tsx" | "rs" | "py" | "sql" | "sh" | "ps1" | "c" | "h" | "cpp" | "java" => {
            ("text", "text/plain")
        }
        "png" => ("image", "image/png"),
        "jpg" | "jpeg" => ("image", "image/jpeg"),
        "gif" => ("image", "image/gif"),
        "webp" => ("image", "image/webp"),
        "bmp" => ("image", "image/bmp"),
        "ico" => ("image", "image/x-icon"),
        "mp3" => ("audio", "audio/mpeg"),
        "wav" => ("audio", "audio/wav"),
        "ogg" | "oga" => ("audio", "audio/ogg"),
        "m4a" => ("audio", "audio/mp4"),
        "flac" => ("audio", "audio/flac"),
        "mp4" | "m4v" => ("video", "video/mp4"),
        "webm" => ("video", "video/webm"),
        "ogv" => ("video", "video/ogg"),
        _ => ("unsupported", "application/octet-stream"),
    }
}

pub(crate) fn revoke(state: &AppState) {
    let mut registry = lock(&state.sandbox);
    registry.revision = registry.revision.wrapping_add(1);
    if let Some(session) = registry.current.take() {
        session.revoked.store(true, Ordering::Release);
    }
    for target in registry.previews.values() {
        target.cancelled.store(true, Ordering::Release);
    }
}

pub(crate) fn active(state: &AppState) -> bool {
    lock(&state.sandbox).current.is_some()
}

fn revoke_session(state: &AppState, session: &Session) {
    session.revoked.store(true, Ordering::Release);
    let mut registry = lock(&state.sandbox);
    if registry
        .current
        .as_ref()
        .is_some_and(|current| current.id == session.id)
    {
        registry.current = None;
        registry.revision = registry.revision.wrapping_add(1);
    }
    for target in registry
        .previews
        .values()
        .filter(|target| target.session_id == session.id)
    {
        target.cancelled.store(true, Ordering::Release);
    }
}

impl Session {
    fn validate_state(&self, state: &AppState) -> Result<(), String> {
        if state.emergency_locked.load(Ordering::Acquire)
            || self.revoked.load(Ordering::Acquire)
            || lock(&state.key).as_deref() != Some(&*self.key)
            || lock(&state.key_path).as_ref() != Some(&self.key_path)
            || *lock(&state.key_file_hash) != Some(self.file_hash)
        {
            return Err(LOCKED.into());
        }
        Ok(())
    }

    fn validate_monitored(&self, state: &AppState) -> Result<(), String> {
        self.validate_state(state)?;
        let revision = state.key_revision.load(Ordering::Acquire);
        let observation = lock(&state.key_file_observation);
        if !observation.as_ref().is_some_and(|sample| {
            sample.path == self.key_path
                && sample.revision == revision
                && sample.hash == self.file_hash
                && sample.checked_at.elapsed() <= Duration::from_millis(1000)
        }) {
            return Err(LOCKED.into());
        }
        Ok(())
    }

    fn validate(&self, state: &AppState) -> Result<(), String> {
        self.validate_state(state)?;
        let revision = state.key_revision.load(Ordering::Acquire);
        // Open the path anew on every check: a cached handle can outlive removal
        // or a disconnected drive. Hash all bytes, not just metadata/existence.
        let bytes = key_file::read_key_snapshot(&self.key_path).map_err(|_| LOCKED.to_string())?;
        let actual: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        if actual != self.file_hash || self.revoked.load(Ordering::Acquire) {
            return Err(LOCKED.into());
        }
        self.validate_state(state)?;
        crate::commands::observe_key_file(state, &self.key_path, revision, actual);
        Ok(())
    }
}

fn current(state: &AppState, id: &str) -> Result<Arc<Session>, String> {
    let session = lock(&state.sandbox).current.clone().ok_or(LOCKED)?;
    if session.id != id {
        return Err(LOCKED.into());
    }
    if let Err(error) = session.validate(state) {
        revoke_session(state, &session);
        return Err(error);
    }
    Ok(session)
}

fn open(state: &AppState, paths: Vec<String>) -> Result<Catalog, String> {
    if paths.is_empty() || paths.len() > MAX_ITEMS {
        return Err("Select between 1 and 10,000 encrypted files.".into());
    }
    revoke(state);
    let revision = lock(&state.sandbox).revision;
    let key = lock(&state.key)
        .clone()
        .ok_or("Load a saved key file first.")?;
    let key_path = lock(&state.key_path).clone().ok_or("Sandbox viewing requires a saved key file. Session-only keys cannot keep a sandbox active." )?;
    let file_hash =
        lock(&state.key_file_hash).ok_or("Reload the saved key file to enable sandbox viewing.")?;
    let mut session = Session {
        id: revision.format_into(&mut NumBuffer::new()).to_owned(),
        key,
        key_path,
        file_hash,
        revoked: AtomicBool::new(false),
        reading: AtomicBool::new(false),
        preview_read: Mutex::new(()),
        items: Vec::new(),
        #[cfg(windows)]
        archives: HashMap::new(),
    };
    session.validate(state)?;
    let mut warnings = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        let path = PathBuf::from(path);
        if !seen.insert(path.clone()) {
            continue;
        }
        session.validate_state(state)?;
        let mut source = Source::open(&path, false).map_err(|error| error.to_string())?;
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            let mut reader = BufReader::new(&mut source.file);
            let entries = archive_read::entries_from_reader(&mut reader)
                .map_err(|error| error.to_string())?;
            if session.items.len() + entries.len() > MAX_ITEMS {
                return Err(
                    "The sandbox supports at most 10,000 files, including ZIP contents.".into(),
                );
            }
            let (names, authenticated) =
                archive_read::inspect_names_from_reader(&mut reader, &session.key, &entries)
                    .map_err(|error| error.to_string())?;
            if !authenticated {
                warnings.push(format!("{}: older ZIP; each opened file is authenticated, but bundle completeness cannot be checked.", path.display()));
            }
            for (zip_index, name) in names.into_iter().enumerate() {
                session.items.push(Item {
                    source: path.clone(),
                    zip_index: Some(zip_index),
                    name,
                });
            }
            drop(reader);
            source.check().map_err(|error| error.to_string())?;
            #[cfg(windows)]
            session
                .archives
                .insert(path, Mutex::new(CachedZip { source, entries }));
            continue;
        } else {
            if session.items.len() == MAX_ITEMS {
                return Err("The sandbox supports at most 10,000 files.".into());
            }
            let name = crypto::sandbox_name(&session.key, &path, &mut source.file)
                .map_err(|error| error.to_string())?;
            session.items.push(Item {
                source: path,
                zip_index: None,
                name,
            });
        }
        source.check().map_err(|error| error.to_string())?;
    }
    session.validate(state)?;
    let catalog = Catalog {
        session_id: session.id.clone(),
        warnings,
        items: session
            .items
            .iter()
            .enumerate()
            .map(|(id, item)| CatalogItem {
                id,
                name: item.name.clone(),
                kind: format(&item.name).0,
            })
            .collect(),
    };
    let mut registry = lock(&state.sandbox);
    if registry.revision != revision {
        return Err(LOCKED.into());
    }
    registry.current = Some(Arc::new(session));
    Ok(catalog)
}

struct MemoryWriter<'a> {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    revoked: &'a AtomicBool,
    cancelled: Option<&'a AtomicBool>,
}

impl Write for MemoryWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .cancelled
            .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, CANCELLED));
        }
        if self.revoked.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, LOCKED));
        }
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "This file exceeds the sandbox preview limit of {} MiB.",
                    self.limit / (1024 * 1024)
                ),
            ));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            // Never let Vec reallocate plaintext into an unwiped old allocation.
            // Compressed entries can outgrow their ciphertext-size reservation.
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
            replacement.extend_from_slice(&self.bytes);
            self.bytes.zeroize();
            self.bytes = replacement;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MemoryWriter<'_> {
    fn reserve_ciphertext(&mut self, size: u64) {
        let capacity = size.min(self.limit as u64) as usize;
        self.bytes = Zeroizing::new(Vec::with_capacity(capacity));
    }
}

fn read(state: &AppState, id: &str, item_id: usize) -> Result<Content, String> {
    read_controlled(state, id, item_id, None)
}

fn read_controlled(
    state: &AppState,
    id: &str,
    item_id: usize,
    preview: Option<(&str, &PreviewTarget)>,
) -> Result<Content, String> {
    if let Some((_, target)) = preview {
        target.check()?;
    }
    let session = current(state, id)?;
    if session
        .reading
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("A preview is loading. Try again when it finishes.".into());
    }
    struct Reading<'a>(&'a AtomicBool);
    impl Drop for Reading<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _reading = Reading(&session.reading);
    let item = session.items.get(item_id).ok_or("Unknown sandbox file.")?;
    let (kind, mime) = format(&item.name);
    if kind == "unsupported" {
        return Err("This file type has no in-app preview. The sandbox supports UTF-8 text, images, audio, and video; PDF and Office files are not supported.".into());
    }
    let limit = if kind == "text" {
        MAX_TEXT_BYTES
    } else {
        MAX_PREVIEW_BYTES
    };
    let mut writer = MemoryWriter {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        revoked: &session.revoked,
        cancelled: preview.map(|(_, target)| target.cancelled.as_ref()),
    };
    #[cfg(windows)]
    let cached = item
        .zip_index
        .and_then(|_| session.archives.get(&item.source));
    #[cfg(not(windows))]
    let cached: Option<&Mutex<()>> = None;
    if let Some(cached) = cached {
        #[cfg(windows)]
        {
            let mut cached = lock(cached);
            cached.source.check().map_err(|error| error.to_string())?;
            let index = item.zip_index.ok_or("Unknown ZIP entry.")?;
            let entry = cached
                .entries
                .get(index)
                .ok_or("The encrypted ZIP changed.")?
                .clone();
            writer.reserve_ciphertext(entry.size);
            let mut source_reader = BufReader::new(&mut cached.source.file);
            {
                let mut reader = archive_read::entry_reader(&mut source_reader, &entry, None)
                    .map_err(|error| error.to_string())?;
                crypto::sandbox_decrypt_entry(&session.key, &mut reader, &mut writer)
                    .map_err(|error| error.to_string())?;
            }
            drop(source_reader);
            cached.source.check().map_err(|error| error.to_string())?;
        }
        #[cfg(not(windows))]
        let _ = cached;
    } else {
        let mut source = Source::open(&item.source, false).map_err(|error| error.to_string())?;
        let size = source.len();
        let mut source_reader = BufReader::new(&mut source.file);
        if let Some(index) = item.zip_index {
            // Platforms without mandatory sharing protection reauthenticate the
            // directory and names; metadata alone cannot prove a cached ZIP is unchanged.
            let entries = archive_read::entries_from_reader(&mut source_reader)
                .map_err(|error| error.to_string())?;
            let (names, _) =
                archive_read::inspect_names_from_reader(&mut source_reader, &session.key, &entries)
                    .map_err(|error| error.to_string())?;
            if names.get(index) != Some(&item.name) {
                return Err("The encrypted ZIP changed. Close and reopen the sandbox.".into());
            }
            let entry = entries.get(index).ok_or("The encrypted ZIP changed.")?;
            writer.reserve_ciphertext(entry.size);
            let mut reader = archive_read::entry_reader(&mut source_reader, entry, None)
                .map_err(|error| error.to_string())?;
            crypto::sandbox_decrypt_entry(&session.key, &mut reader, &mut writer)
                .map_err(|error| error.to_string())?;
        } else {
            writer.reserve_ciphertext(size);
            let mut reader = &mut source_reader;
            if crypto::sandbox_name(&session.key, &item.source, &mut reader)
                .map_err(|error| error.to_string())?
                != item.name
            {
                return Err("The encrypted file changed. Close and reopen the sandbox.".into());
            }
            crypto::sandbox_decrypt(&session.key, &mut reader, &mut writer)
                .map_err(|error| error.to_string())?;
        }
        drop(source_reader);
        source.check().map_err(|error| error.to_string())?;
    }
    if kind == "text" && std::str::from_utf8(&writer.bytes).is_err() {
        return Err("This text file is not UTF-8 and cannot be previewed.".into());
    }
    let (mime, image_pixels) = if kind == "image" {
        image_info(&writer.bytes)?
    } else {
        (mime, 0)
    };
    current(state, id)?;
    if let Some((label, target)) = preview {
        target.check()?;
        // Conservative accounting for base64/IPC copies and two RGBA surfaces.
        // Browser/process memory itself is controlled by the webview.
        let cost = writer
            .bytes
            .len()
            .saturating_mul(8)
            .saturating_add((image_pixels as usize).saturating_mul(8));
        reserve_preview_memory(state, label, target, cost)?;
    }
    // Only return bytes after the final authentication tag, source checks, and
    // a fresh key-file read have all succeeded.
    Ok(Content {
        kind,
        mime,
        data: STANDARD.encode(writer.bytes.as_slice()),
    })
}

fn image_info(bytes: &[u8]) -> Result<(&'static str, u64), String> {
    // Detect only after authentication. An image's extension may not match its
    // bytes, and both dimension checks and the webview must use the real format.
    let format = image::guess_format(bytes)
        .map_err(|_| "This image's format could not be recognized.".to_string())?;
    let mime = match format {
        image::ImageFormat::Png => "image/png",
        image::ImageFormat::Jpeg => "image/jpeg",
        image::ImageFormat::Gif => "image/gif",
        image::ImageFormat::WebP => "image/webp",
        image::ImageFormat::Bmp => "image/bmp",
        image::ImageFormat::Ico => "image/x-icon",
        _ => return Err("Unsupported image format.".into()),
    };
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_PREVIEW_MEMORY as u64);
    reader.limits(limits);
    let (width, height) = reader.into_dimensions().map_err(|_| {
        "This image is damaged, unsupported, or exceeds the safe image dimensions.".to_string()
    })?;
    let pixels = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
        || pixels > MAX_IMAGE_PIXELS
    {
        return Err(
            "This image exceeds the preview limit of 40 megapixels or 16,384 pixels per side."
                .into(),
        );
    }
    Ok((mime, pixels))
}

fn reserve_preview_memory(
    state: &AppState,
    label: &str,
    target: &PreviewTarget,
    cost: usize,
) -> Result<(), String> {
    target.check()?;
    let mut registry = lock(&state.sandbox);
    let stored = registry.previews.get(label).ok_or(CANCELLED)?;
    stored.check()?;
    if !Arc::ptr_eq(&stored.cancelled, &target.cancelled) {
        return Err(CANCELLED.into());
    }
    let used: usize = registry
        .previews
        .iter()
        .filter(|(other, _)| other.as_str() != label)
        .map(|(_, entry)| entry.memory_bytes)
        .sum();
    if used.saturating_add(cost) > MAX_PREVIEW_MEMORY {
        return Err(
            "The sandbox preview memory budget is full. Close another preview and try again."
                .into(),
        );
    }
    registry
        .previews
        .get_mut(label)
        .ok_or(CANCELLED)?
        .memory_bytes = cost;
    Ok(())
}

fn preview_read_turn<'a>(
    session: &'a Session,
    target: &PreviewTarget,
) -> Result<MutexGuard<'a, ()>, String> {
    loop {
        target.check()?;
        if session.revoked.load(Ordering::Acquire) {
            return Err(LOCKED.into());
        }
        match session.preview_read.try_lock() {
            Ok(turn) => {
                target.check()?;
                return Ok(turn);
            }
            Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[tauri::command]
pub async fn open_sandbox(app: tauri::AppHandle, paths: Vec<String>) -> Result<Catalog, String> {
    tauri::async_runtime::spawn_blocking(move || open(app.state::<AppState>().inner(), paths))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn read_sandbox_file(
    app: tauri::AppHandle,
    session_id: String,
    item_id: usize,
) -> Result<Content, String> {
    tauri::async_runtime::spawn_blocking(move || {
        read(app.state::<AppState>().inner(), &session_id, item_id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn check_sandbox(
    app: tauri::AppHandle,
    session_id: String,
    fresh: Option<bool>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        if fresh.unwrap_or(false) {
            return current(&state, &session_id).map(|_| ());
        }
        let session = lock(&state.sandbox).current.clone().ok_or(LOCKED)?;
        if session.id != session_id {
            return Err(LOCKED.into());
        }
        if let Err(error) = session.validate_monitored(&state) {
            revoke_session(&state, &session);
            return Err(error);
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn close_sandbox(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    session_id: Option<String>,
) {
    if let Some(id) = session_id {
        let session = lock(&state.sandbox).current.clone();
        if let Some(session) = session.filter(|session| session.id == id) {
            revoke_session(&state, &session);
        }
    } else {
        revoke(&state);
    }
    close_invalid_previews(&app);
}

fn preview_target(state: &AppState, label: &str) -> Result<PreviewTarget, String> {
    lock(&state.sandbox)
        .previews
        .get(label)
        .cloned()
        .ok_or_else(|| LOCKED.into())
}

pub(crate) fn forget_preview(state: &AppState, label: &str) {
    if let Some(target) = lock(&state.sandbox).previews.remove(label) {
        target.cancelled.store(true, Ordering::Release);
    }
}

pub(crate) fn preview_closed(app: &tauri::AppHandle, label: &str) {
    notify_preview_closed(app, label, false);
}

fn take_closed_preview(state: &AppState, label: &str, locked: bool) -> Option<ClosedPreview> {
    let mut registry = lock(&state.sandbox);
    let target = registry.previews.remove(label)?;
    target.cancelled.store(true, Ordering::Release);
    // A native close may race the key monitor. Losing the session must not be
    // mistaken for a manual dismissal of the file we need to restore.
    let locked = locked
        || !registry.current.as_ref().is_some_and(|session| {
            session.id == target.session_id && !session.revoked.load(Ordering::Acquire)
        });
    Some(ClosedPreview {
        session_id: target.session_id,
        item_id: target.item_id,
        locked,
    })
}

fn notify_preview_closed(app: &tauri::AppHandle, label: &str, locked: bool) {
    if let Some(closed) = take_closed_preview(&app.state::<AppState>(), label, locked) {
        let _ = app.emit_to("main", "sandbox-preview-closed", closed);
    }
}

pub(crate) fn close_invalid_previews(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let labels = {
        let mut registry = lock(&state.sandbox);
        let active = registry
            .current
            .as_ref()
            .filter(|session| !session.revoked.load(Ordering::Acquire))
            .map(|session| session.id.clone());
        let labels: Vec<_> = registry
            .previews
            .iter()
            .filter(|(_, target)| active.as_deref() != Some(&target.session_id))
            .map(|(label, _)| label.clone())
            .collect();
        for label in &labels {
            if let Some(target) = registry.previews.remove(label) {
                target.cancelled.store(true, Ordering::Release);
            }
        }
        labels
    };
    for label in labels {
        if let Some(window) = app.get_webview_window(&label) {
            let _ = window.set_title("Private preview - FileEncrypt");
            let _ = window.close();
        }
    }
}

#[tauri::command]
pub async fn open_sandbox_preview(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    session_id: String,
    item_id: usize,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Open previews from the sandbox explorer.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let session = current(&state, &session_id)?;
        let item = session.items.get(item_id).ok_or("Unknown sandbox file.")?;
        let name = item.name.rsplit(['/', '\\']).next().unwrap_or(&item.name);
        let existing_label = lock(&state.sandbox)
            .previews
            .iter()
            .find(|(_, target)| target.session_id == session.id && target.item_id == item_id)
            .map(|(label, _)| label.clone());
        if let Some(existing) = existing_label.and_then(|label| app.get_webview_window(&label)) {
            let _ = existing.unminimize();
            return existing.set_focus().map_err(|error| error.to_string());
        }
        let label = register_preview(&state, session_id.clone(), item_id)?;
        let builder = tauri::WebviewWindowBuilder::new(
            &app,
            &label,
            tauri::WebviewUrl::App("sandbox-preview.html".into()),
        )
        .title(format!("{name} - FileEncrypt"))
        .theme(window.theme().ok())
        .inner_size(900.0, 680.0)
        .min_inner_size(460.0, 360.0)
        .center()
        .on_navigation(|url| {
            url.path() == "/sandbox-preview.html"
                || matches!(url.as_str(), "about:blank" | "about:srcdoc")
        });
        // Wry also uses this flag for WebView2's IsPinchZoomEnabled. Allow
        // image gestures through; the isolated viewer cancels browser zoom
        // and applies them to the image instead.
        #[cfg(windows)]
        let builder = builder.zoom_hotkeys_enabled(format(&item.name).0 == "image");
        // Owned windows on Windows have no taskbar entry and minimize to a
        // small floating title bar. Keep previews as regular top-level windows;
        // the sandbox monitor still closes them when the main window exits.
        #[cfg(windows)]
        let result = builder.build();
        #[cfg(not(windows))]
        let result = builder.parent(&window).and_then(|builder| builder.build());
        let preview = match result {
            Ok(preview) => preview,
            Err(error) => {
                forget_preview(&state, &label);
                return Err(error.to_string());
            }
        };
        // Creation can race a disconnect or a closed explorer. Never retain a
        // preview for a session that was revoked while the webview was starting.
        if let Err(error) = current(&state, &session_id) {
            forget_preview(&state, &label);
            let _ = preview.set_title("Private preview - FileEncrypt");
            let _ = preview.close();
            return Err(error);
        }
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn sandbox_preview_info(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<PreviewInfo, String> {
    let label = window.label().to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let target = preview_target(&state, &label)?;
        let session = current(&state, &target.session_id)?;
        preview_info(&session, target.item_id)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn read_sandbox_preview(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Content, String> {
    let label = window.label().to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let target = preview_target(&state, &label)?;
        let session = current(&state, &target.session_id)?;
        // Native windows may open together. Serialize their bounded reads so a
        // second preview waits instead of showing a spurious "already loading".
        let _turn = preview_read_turn(&session, &target)?;
        read_controlled(
            &state,
            &target.session_id,
            target.item_id,
            Some((&label, &target)),
        )
    })
    .await
    .map_err(|error| error.to_string())?
}

fn image_items(session: &Session) -> Vec<usize> {
    session
        .items
        .iter()
        .enumerate()
        .filter(|(_, item)| format(&item.name).0 == "image")
        .map(|(id, _)| id)
        .collect()
}

fn register_preview(
    state: &AppState,
    session_id: String,
    item_id: usize,
) -> Result<String, String> {
    let mut registry = lock(&state.sandbox);
    if registry.previews.len() >= MAX_PREVIEW_WINDOWS {
        return Err(
            "Up to 8 preview windows can be open. Close a preview before opening another.".into(),
        );
    }
    registry.next_preview = registry.next_preview.wrapping_add(1);
    let mut item_buffer = NumBuffer::new();
    let mut preview_buffer = NumBuffer::new();
    let item = item_id.format_into(&mut item_buffer);
    let preview = registry.next_preview.format_into(&mut preview_buffer);
    let mut label = String::with_capacity(18 + session_id.len() + item.len() + preview.len());
    label.push_str("sandbox-preview-");
    label.push_str(&session_id);
    label.push('-');
    label.push_str(item);
    label.push('-');
    label.push_str(preview);
    registry
        .previews
        .insert(label.clone(), PreviewTarget::new(session_id, item_id));
    Ok(label)
}

fn preview_info(session: &Session, item_id: usize) -> Result<PreviewInfo, String> {
    let item = session.items.get(item_id).ok_or("Unknown sandbox file.")?;
    let images = image_items(session);
    let navigation = images
        .iter()
        .position(|id| *id == item_id)
        .map(|index| ImageNavigation {
            previous: index > 0,
            next: index + 1 < images.len(),
            index: index + 1,
            total: images.len(),
        })
        .unwrap_or_default();
    Ok(PreviewInfo {
        session_id: session.id.clone(),
        item: CatalogItem {
            id: item_id,
            name: item.name.clone(),
            kind: format(&item.name).0,
        },
        navigation,
    })
}

fn reset_preview_target(
    state: &AppState,
    label: &str,
    item_id: Option<usize>,
) -> Result<PreviewTarget, String> {
    let mut registry = lock(&state.sandbox);
    let old = registry.previews.get(label).ok_or(CANCELLED)?;
    old.cancelled.store(true, Ordering::Release);
    let target = PreviewTarget::new(old.session_id.clone(), item_id.unwrap_or(old.item_id));
    registry.previews.insert(label.to_string(), target.clone());
    Ok(target)
}

#[tauri::command]
pub fn cancel_sandbox_preview_read(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<(), String> {
    reset_preview_target(&app.state::<AppState>(), window.label(), None).map(|_| ())
}

#[tauri::command]
pub async fn navigate_sandbox_preview(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    direction: i32,
) -> Result<PreviewInfo, String> {
    if !matches!(direction, -1 | 1) {
        return Err("Choose the previous or next image.".into());
    }
    let label = window.label().to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let target = preview_target(&state, &label)?;
        let session = current(&state, &target.session_id)?;
        let images = image_items(&session);
        let index = images
            .iter()
            .position(|id| *id == target.item_id)
            .ok_or("Image navigation is only available for images.")?;
        let next = index
            .checked_add_signed(direction as isize)
            .and_then(|index| images.get(index))
            .copied()
            .ok_or("There are no more images in that direction.")?;
        reset_preview_target(&state, &label, Some(next))?;
        let info = preview_info(&session, next)?;
        current(&state, &target.session_id)?;
        if let Some(window) = app.get_webview_window(&label) {
            let name = info
                .item
                .name
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&info.item.name);
            let _ = window.set_title(&format!("{name} - FileEncrypt"));
        }
        let _ = app.emit_to(
            "main",
            "sandbox-preview-navigated",
            PreviewTarget::new(target.session_id, next),
        );
        Ok(info)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn close_sandbox_preview(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    locked: Option<bool>,
) -> Result<(), String> {
    preview_target(&app.state::<AppState>(), window.label())?;
    notify_preview_closed(&app, window.label(), locked.unwrap_or(false));
    let _ = window.set_title("Private preview - FileEncrypt");
    window.close().map_err(|error| error.to_string())
}

pub(crate) fn start_monitor(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if app.get_webview_window("main").is_none() {
            revoke(&app.state::<AppState>());
            close_invalid_previews(&app);
            break;
        }
        let state = app.state::<AppState>();
        let session = lock(&state.sandbox).current.clone();
        if let Some(session) = session {
            if session.validate_monitored(&state).is_err() {
                revoke_session(&state, &session);
                let _ = app.emit("sandbox-locked", &session.id);
            }
        }
        close_invalid_previews(&app);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{archive, crypto::JobOptions, test_support::TestDir};
    use std::fs;

    #[test]
    fn monitored_checks_require_a_recent_read_for_the_current_key_revision() {
        let (dir, state, key_path, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        let session = current(&state, &catalog.session_id).unwrap();
        session.validate_monitored(&state).unwrap();
        // A completed old read cannot mask a blocked/disconnected drive forever.
        lock(&state.key_file_observation)
            .as_mut()
            .unwrap()
            .checked_at -= Duration::from_millis(1501);
        assert!(session.validate_monitored(&state).is_err());
        session.validate(&state).unwrap();
        state.key_revision.fetch_add(1, Ordering::AcqRel);
        assert!(session.validate_monitored(&state).is_err());
        session.validate(&state).unwrap();
        fs::remove_file(key_path).unwrap();
        assert!(session.validate(&state).is_err());
    }

    #[test]
    fn preview_buffers_fit_small_files_and_grow_without_losing_plaintext() {
        let revoked = AtomicBool::new(false);
        let mut writer = MemoryWriter {
            bytes: Zeroizing::new(Vec::new()),
            limit: 1024,
            revoked: &revoked,
            cancelled: None,
        };
        writer.reserve_ciphertext(40);
        assert_eq!(writer.bytes.capacity(), 40);
        writer.write_all(&[7; 32]).unwrap();
        writer.write_all(&[8; 80]).unwrap();
        assert_eq!(&writer.bytes[..32], &[7; 32]);
        assert_eq!(&writer.bytes[32..], &[8; 80]);
        assert!(writer.bytes.capacity() < 1024);
        assert!(writer.write_all(&[0; 1024]).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn cached_zip_is_pinned_and_revocation_releases_its_source_handle() {
        let (dir, state, _, key) = fixture();
        let input = dir.0.join("note.txt");
        fs::write(&input, b"private contents").unwrap();
        let zip = archive::encrypt_to_zip(&key, &[input], &options())
            .unwrap()
            .path;
        let catalog = open(&state, vec![zip.display().to_string()]).unwrap();
        assert!(fs::write(&zip, b"replacement").is_err());
        assert!(fs::remove_file(&zip).is_err());
        for _ in 0..2 {
            let content = read(&state, &catalog.session_id, 0).unwrap();
            assert_eq!(STANDARD.decode(&content.data).unwrap(), b"private contents");
        }
        revoke(&state);
        fs::remove_file(zip).unwrap();
    }

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(width, height)
            .write_to(&mut output, image::ImageFormat::Png)
            .unwrap();
        output.into_inner()
    }

    #[test]
    fn image_dimensions_are_checked_before_exporting_to_the_webview() {
        let bytes = png_bytes(12, 8);
        assert_eq!(image_info(&bytes).unwrap(), ("image/png", 96));
        assert!(image_info(b"damaged image").is_err());
        // A recognized signature must still belong to a supported format.
        assert!(image_info(b"II\x2a\x00\x08\x00\x00\x00").is_err());
        assert!(image_info(b"\xff\xd8\xff").is_err());
        for (width, height) in [(20_000u32, 1u32), (10_000, 10_000)] {
            let mut oversized = bytes.clone();
            oversized[16..20].copy_from_slice(&width.to_be_bytes());
            oversized[20..24].copy_from_slice(&height.to_be_bytes());
            let crc = crc32fast::hash(&oversized[12..29]);
            oversized[29..33].copy_from_slice(&crc.to_be_bytes());
            assert!(image_info(&oversized).is_err());
        }
    }

    #[test]
    fn image_preview_uses_content_format_when_the_extension_is_wrong() {
        let mut output = Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(12, 8)
            .write_to(&mut output, image::ImageFormat::Jpeg)
            .unwrap();
        let jpeg = output.into_inner();
        assert_eq!(image_info(&jpeg).unwrap(), ("image/jpeg", 96));
        for (name, bytes, mime) in [
            ("IMG_4753.PNG", jpeg, "image/jpeg"),
            ("renamed.jpg", png_bytes(12, 8), "image/png"),
        ] {
            let (dir, state, _, key) = fixture();
            let path = encrypted(&dir, name, &bytes, &key);
            let before = files(&dir);
            let catalog = open(&state, vec![path]).unwrap();
            assert_eq!(catalog.items[0].kind, "image");
            assert_eq!(catalog.items[0].name, name);
            let content = read(&state, &catalog.session_id, 0).unwrap();
            assert_eq!(content.kind, "image");
            assert_eq!(content.mime, mime);
            assert_eq!(STANDARD.decode(&content.data).unwrap(), bytes);
            assert_eq!(files(&dir), before);
        }
    }

    #[test]
    fn preview_budget_is_aggregate_and_released_when_a_window_closes() {
        let state = AppState::default();
        let first = register_preview(&state, "1".into(), 0).unwrap();
        let second = register_preview(&state, "1".into(), 1).unwrap();
        let first_target = preview_target(&state, &first).unwrap();
        let second_target = preview_target(&state, &second).unwrap();
        reserve_preview_memory(&state, &first, &first_target, MAX_PREVIEW_MEMORY / 2).unwrap();
        assert!(reserve_preview_memory(
            &state,
            &second,
            &second_target,
            MAX_PREVIEW_MEMORY / 2 + 1
        )
        .is_err());
        forget_preview(&state, &first);
        assert!(first_target.check().is_err());
        reserve_preview_memory(&state, &second, &second_target, MAX_PREVIEW_MEMORY).unwrap();
        reset_preview_target(&state, &second, Some(2)).unwrap();
        assert!(reserve_preview_memory(&state, &second, &second_target, 1).is_err());
        assert_eq!(preview_target(&state, &second).unwrap().memory_bytes, 0);
    }

    #[test]
    fn preview_window_count_is_bounded_and_labels_do_not_collide_after_navigation() {
        let state = AppState::default();
        let mut labels = Vec::new();
        for item in 0..MAX_PREVIEW_WINDOWS {
            labels.push(register_preview(&state, "1".into(), item).unwrap());
        }
        assert!(register_preview(&state, "1".into(), 20).is_err());
        forget_preview(&state, &labels[0]);
        let replacement = register_preview(&state, "1".into(), 0).unwrap();
        assert!(!labels.contains(&replacement));
    }

    #[test]
    fn closing_a_queued_preview_cancels_without_waiting_for_the_active_read() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        let session = current(&state, &catalog.session_id).unwrap();
        let target = PreviewTarget::new(catalog.session_id, 0);
        let queued = target.clone();
        let held = lock(&session.preview_read);
        let other_session = session.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = preview_read_turn(&other_session, &queued).err();
            send.send(result).unwrap();
        });
        target.cancelled.store(true, Ordering::Release);
        let result = receive.recv_timeout(Duration::from_millis(500));
        drop(held);
        thread.join().unwrap();
        assert_eq!(result.unwrap().as_deref(), Some(CANCELLED));
    }

    #[test]
    fn cancellation_stops_chunk_writes_and_navigation_skips_non_images() {
        let revoked = AtomicBool::new(false);
        let cancelled = AtomicBool::new(true);
        let mut writer = MemoryWriter {
            bytes: Zeroizing::new(Vec::new()),
            limit: 1024,
            revoked: &revoked,
            cancelled: Some(&cancelled),
        };
        assert_eq!(
            writer.write_all(b"plaintext").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(writer.bytes.is_empty());
        let (dir, state, _, key) = fixture();
        let first = encrypted(&dir, "first.png", &png_bytes(12, 8), &key);
        let text = encrypted(&dir, "notes.txt", b"notes", &key);
        let second = encrypted(&dir, "second.png", &png_bytes(8, 12), &key);
        let catalog = open(&state, vec![first, text, second]).unwrap();
        let session = current(&state, &catalog.session_id).unwrap();
        assert_eq!(image_items(&session), vec![0, 2]);
        let navigation = preview_info(&session, 0).unwrap().navigation;
        assert!(!navigation.previous && navigation.next);
        assert_eq!((navigation.index, navigation.total), (1, 2));
        assert_eq!(preview_info(&session, 1).unwrap().navigation.total, 0);
        let label = register_preview(&state, catalog.session_id.clone(), 0).unwrap();
        let target = preview_target(&state, &label).unwrap();
        read_controlled(&state, &catalog.session_id, 0, Some((&label, &target))).unwrap();
        assert!(preview_target(&state, &label).unwrap().memory_bytes > 0);
        reset_preview_target(&state, &label, Some(2)).unwrap();
        assert!(target.check().is_err());
    }

    #[test]
    fn preview_targets_are_bound_to_registered_windows() {
        let state = AppState::default();
        lock(&state.sandbox).previews.insert(
            "sandbox-preview-1-4".into(),
            PreviewTarget::new("1".into(), 4),
        );
        let target = preview_target(&state, "sandbox-preview-1-4").unwrap();
        assert_eq!(target.session_id, "1");
        assert_eq!(target.item_id, 4);
        assert!(preview_target(&state, "main").is_err());
        assert!(preview_target(&state, "sandbox-preview-1-5").is_err());
        forget_preview(&state, "sandbox-preview-1-4");
        assert!(preview_target(&state, "sandbox-preview-1-4").is_err());
    }

    fn fixture() -> (TestDir, AppState, PathBuf, [u8; 32]) {
        let dir = TestDir::new();
        let key_path = dir.0.join("vault.key");
        let key = [42; 32];
        key_file::write_key_file(&key_path, &key).unwrap();
        let state = AppState::default();
        *lock(&state.key) = Some(Zeroizing::new(key));
        *lock(&state.key_path) = Some(key_path.clone());
        *lock(&state.key_file_hash) =
            Some(key_file::checked_file_hash(&key_path, &key, None).unwrap());
        (dir, state, key_path, key)
    }

    fn options() -> JobOptions {
        JobOptions {
            overwrite: false,
            remove_original: false,
            key_file: None,
            output_dir: None,
        }
    }

    fn encrypted(dir: &TestDir, name: &str, bytes: &[u8], key: &[u8; 32]) -> String {
        let path = dir.0.join(name);
        fs::write(&path, bytes).unwrap();
        let encrypted = crypto::encrypt_file(key, &path, &options()).unwrap();
        fs::remove_file(path).unwrap();
        encrypted.display().to_string()
    }

    #[test]
    fn preview_closure_distinguishes_manual_dismissal_from_key_loss() {
        for (frontend_locked, revoke_before_close) in [(false, false), (true, false), (false, true)]
        {
            let (dir, state, _, key) = fixture();
            let path = encrypted(&dir, "private.txt", b"private contents", &key);
            let catalog = open(&state, vec![path]).unwrap();
            let label = format!("sandbox-preview-{}-0", catalog.session_id);
            lock(&state.sandbox).previews.insert(
                label.clone(),
                PreviewTarget::new(catalog.session_id.clone(), 0),
            );
            if revoke_before_close {
                revoke(&state);
            }
            let closed = take_closed_preview(&state, &label, frontend_locked).unwrap();
            assert_eq!(closed.session_id, catalog.session_id);
            assert_eq!(closed.item_id, 0);
            assert_eq!(closed.locked, frontend_locked || revoke_before_close);
            assert!(take_closed_preview(&state, &label, frontend_locked).is_none());
        }
    }

    fn files(dir: &TestDir) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(&dir.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    #[test]
    fn authenticated_preview_never_creates_a_plaintext_file() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let before = files(&dir);
        let catalog = open(&state, vec![path]).unwrap();
        assert_eq!(catalog.items[0].name, "private.txt");
        let content = read(&state, &catalog.session_id, 0).unwrap();
        assert_eq!(STANDARD.decode(&content.data).unwrap(), b"private contents");
        assert_eq!(files(&dir), before);
        revoke(&state);
        assert!(read(&state, &catalog.session_id, 0).is_err());
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn removed_or_changed_key_revokes_access_despite_cached_master_key() {
        for removed in [true, false] {
            let (dir, state, key_path, key) = fixture();
            let path = encrypted(&dir, "private.txt", b"private contents", &key);
            let catalog = open(&state, vec![path]).unwrap();
            let original = fs::read(&key_path).unwrap();
            if removed {
                fs::remove_file(&key_path).unwrap();
            } else {
                key_file::write_key_file(&key_path, &[43; 32]).unwrap();
            }
            assert!(lock(&state.key).is_some());
            assert!(current(&state, &catalog.session_id).is_err());
            assert!(lock(&state.sandbox).current.is_none());
            fs::write(&key_path, original).unwrap();
            assert!(
                read(&state, &catalog.session_id, 0).is_err(),
                "reconnecting cannot revive a revoked session"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn an_existing_but_unreadable_key_file_locks_the_sandbox() {
        use std::os::windows::fs::OpenOptionsExt;
        let (dir, state, key_path, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        let _exclusive = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&key_path)
            .unwrap();
        assert!(key_path.exists());
        assert!(current(&state, &catalog.session_id).is_err());
    }

    #[test]
    fn session_only_keys_and_key_switches_cannot_authorize_a_preview() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path.clone()]).unwrap();
        *lock(&state.key) = Some(Zeroizing::new([9; 32]));
        assert!(read(&state, &catalog.session_id, 0).is_err());
        *lock(&state.key) = Some(Zeroizing::new(key));
        *lock(&state.key_path) = None;
        assert!(open(&state, vec![path]).is_err());
    }

    #[test]
    fn protected_keys_are_rechecked_without_retaining_a_passphrase() {
        let (dir, state, key_path, key) = fixture();
        key_file::write_protected_key_file(&key_path, &key, "sandbox test passphrase").unwrap();
        *lock(&state.key_file_hash) = Some(
            key_file::checked_file_hash(&key_path, &key, Some("sandbox test passphrase")).unwrap(),
        );
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let catalog = open(&state, vec![path]).unwrap();
        assert!(read(&state, &catalog.session_id, 0).is_ok());
        let mut bytes = fs::read(&key_path).unwrap();
        let index = bytes.len() - 4;
        bytes[index] ^= 1;
        fs::write(&key_path, bytes).unwrap();
        assert!(current(&state, &catalog.session_id).is_err());
    }

    #[test]
    fn damaged_ciphertext_returns_no_partial_plaintext() {
        let (dir, state, _, key) = fixture();
        let path = encrypted(&dir, "private.txt", b"private contents", &key);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![path]).unwrap();
        assert!(read(&state, &catalog.session_id, 0).is_err());
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn compressed_zip_previews_keep_paths_without_extracting_files() {
        let (dir, state, _, key) = fixture();
        let folder = dir.0.join("notes");
        fs::create_dir(&folder).unwrap();
        let input = folder.join("private.txt");
        fs::write(&input, b"compressed private contents").unwrap();
        let zipped = archive::encrypt_to_zip_with_progress(
            &key,
            std::slice::from_ref(&input),
            &JobOptions {
                output_dir: Some(dir.0.clone()),
                ..options()
            },
            Some(&dir.0),
            true,
            None,
            None,
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![zipped.path.display().to_string()]).unwrap();
        assert_eq!(catalog.items[0].name, "notes/private.txt");
        assert!(catalog.warnings.is_empty());
        let content = read(&state, &catalog.session_id, 0).unwrap();
        assert_eq!(
            STANDARD.decode(&content.data).unwrap(),
            b"compressed private contents"
        );
        assert_eq!(files(&dir), before);
        assert_eq!(fs::read_dir(folder).unwrap().count(), 0);
    }

    #[test]
    fn decompression_is_bounded_by_the_preview_limit() {
        let (dir, state, _, key) = fixture();
        let input = dir.0.join("oversized.txt");
        fs::write(&input, vec![b'x'; MAX_TEXT_BYTES + 1]).unwrap();
        let zipped = archive::encrypt_to_zip_with_progress(
            &key,
            std::slice::from_ref(&input),
            &options(),
            None,
            true,
            None,
            None,
        )
        .unwrap();
        fs::remove_file(input).unwrap();
        let before = files(&dir);
        let catalog = open(&state, vec![zipped.path.display().to_string()]).unwrap();
        assert!(read(&state, &catalog.session_id, 0)
            .err()
            .unwrap()
            .contains("limit"));
        assert_eq!(files(&dir), before);
    }

    #[test]
    fn unsupported_formats_and_non_utf8_text_are_never_opened_externally() {
        let (dir, state, _, key) = fixture();
        let unsupported = encrypted(&dir, "private.docx", b"not a document preview", &key);
        let invalid_text = encrypted(&dir, "private.txt", &[255, 254], &key);
        let catalog = open(&state, vec![unsupported, invalid_text]).unwrap();
        assert_eq!(catalog.items[0].kind, "unsupported");
        assert!(read(&state, &catalog.session_id, 0)
            .err()
            .unwrap()
            .contains("no in-app preview"));
        assert!(read(&state, &catalog.session_id, 1)
            .err()
            .unwrap()
            .contains("not UTF-8"));
    }
}
