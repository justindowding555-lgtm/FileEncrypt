//! Persistent access lock and explicitly armed, one-shot key-file deletion.
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use sha2::{Digest, Sha256};
use tauri::{Emitter, Manager};
use zeroize::Zeroizing;

use crate::commands::{self, lock, AppState, AppStatus};
use crate::{file_guard, key_file, source::Source};

pub(crate) const UNAVAILABLE: &str = "Unable to read the saved key.";

#[derive(Default)]
pub(crate) struct Controls {
    marker: Option<PathBuf>,
    deletion: Option<ArmedDeletion>,
    next_arm: u64,
    pub(crate) report: Option<String>,
}

#[derive(Clone)]
struct ArmedDeletion {
    id: u64,
    path: PathBuf,
    identity: file_guard::Identity,
    digest: [u8; 32],
    missing: bool,
}

impl Controls {
    pub(crate) fn armed_path(&self) -> Option<String> {
        self.deletion
            .as_ref()
            .map(|arm| arm.path.display().to_string())
    }
    pub(crate) fn disarm(&mut self) {
        self.deletion = None;
    }
}

pub(crate) fn ensure_unlocked(state: &AppState) -> Result<(), String> {
    if state.emergency_locked.load(Ordering::Acquire) {
        Err(UNAVAILABLE.into())
    } else {
        Ok(())
    }
}

pub(crate) fn restore(app: &tauri::AppHandle, state: &AppState) -> tauri::Result<()> {
    let marker = app.path().app_config_dir()?.join("emergency.lock");
    // An unreadable marker fails closed rather than silently restoring a key.
    state
        .emergency_locked
        .store(marker.try_exists().unwrap_or(true), Ordering::Release);
    lock(&state.emergency).marker = Some(marker);
    Ok(())
}

fn persist_lock(marker: &Path) -> io::Result<()> {
    fs::create_dir_all(
        marker
            .parent()
            .ok_or_else(|| io::Error::other("Missing config directory"))?,
    )?;
    match OpenOptions::new().write(true).create_new(true).open(marker) {
        Ok(file) => file.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

// Caller holds key_change. No key activation can pass this transition.
fn lock_inner(state: &AppState) -> Result<(), String> {
    state.emergency_locked.store(true, Ordering::Release);
    commands::deactivate_file_key(state, true, UNAVAILABLE.into());
    let marker = lock(&state.emergency)
        .marker
        .clone()
        .ok_or("Emergency lock storage is unavailable.")?;
    persist_lock(&marker).map_err(|error| {
        format!("Access is locked, but the lock could not be saved for restart: {error}")
    })
}

pub(crate) fn lock_key(state: &AppState) -> Result<(), String> {
    let _change = lock(&state.key_change);
    lock(&state.emergency).disarm();
    lock_inner(state)
}

pub(crate) fn unlock_key(state: &AppState, passphrase: Option<&str>) -> Result<(), String> {
    let (revision, path) = {
        let _change = lock(&state.key_change);
        if !state.emergency_locked.load(Ordering::Acquire) {
            return Ok(());
        }
        if state.running.load(Ordering::Acquire) {
            return Err("Wait for the cancelled file job to finish before unlocking.".into());
        }
        (
            state.key_revision.load(Ordering::Acquire),
            lock(&state.key_path).clone(),
        )
    };
    let mut attempt = crate::key_protection::Attempt::begin(state)?;
    crate::key_protection::verify_emergency_password(state, passphrase)?;
    // Read outside key_change, keeping the persistent lock until validation succeeds.
    let loaded = path
        .as_ref()
        .map(|path| {
            let bytes = key_file::read_key_snapshot(path).map_err(|_| UNAVAILABLE.to_string())?;
            let key = key_file::parse_key_snapshot(path, &bytes, None).or_else(|error| {
                if crate::key_protection::setup_required(state) {
                    key_file::parse_key_snapshot(path, &bytes, passphrase)
                } else { Err(error) }
            })
                .map_err(|error| error.to_string())?;
            Ok::<_, String>((key, Sha256::digest(bytes.as_slice()).into()))
        })
        .transpose()?;
    let _change = lock(&state.key_change);
    if state.key_revision.load(Ordering::Acquire) != revision
        || state.running.load(Ordering::Acquire)
    {
        return Err("Key access changed. Try the unlock shortcut again.".into());
    }
    let marker = lock(&state.emergency)
        .marker
        .clone()
        .ok_or("Emergency lock storage is unavailable.")?;
    match fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "The saved access lock could not be cleared: {error}"
            ))
        }
    }
    state.emergency_locked.store(false, Ordering::Release);
    if let Some((key, hash)) = loaded {
        *lock(&state.key) = Some(key);
        *lock(&state.key_file_hash) = Some(hash);
    }
    commands::finish_emergency_unlock(state);
    attempt.success();
    Ok(())
}

fn key_digest(source: &mut Source) -> Result<[u8; 32], String> {
    if source.len() > 4096 {
        return Err("The selected key file is too large.".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut source.file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("The selected key file changed.".into());
    }
    source.check().map_err(|error| error.to_string())?;
    Ok(Sha256::digest(bytes.as_slice()).into())
}

fn arm_deletion(state: &AppState) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Emergency key deletion is available on Windows only.".into());
    }
    let (revision, path, expected) = {
        let _change = lock(&state.key_change);
        ensure_unlocked(state)?;
        if state.running.load(Ordering::Acquire) {
            return Err("Finish the current file job before arming deletion.".into());
        }
        if lock(&state.key).is_none() {
            return Err("Load the saved key before arming deletion.".into());
        }
        (
            state.key_revision.load(Ordering::Acquire),
            lock(&state.key_path)
                .clone()
                .ok_or("Load a saved key file first.")?,
            lock(&state.key_file_hash).ok_or("Reload the saved key before arming deletion.")?,
        )
    };
    // Pin the exact file and volume as well as its contents. A different USB or
    // replacement file at the same path must never become a deletion target.
    let mut source = Source::open(&path, false).map_err(|error| error.to_string())?;
    let identity = file_guard::identity(&source.file).map_err(|error| error.to_string())?;
    if key_digest(&mut source)? != expected {
        return Err("The saved key changed. Load it again before arming deletion.".into());
    }
    let absolute = std::path::absolute(&path).map_err(|error| error.to_string())?;
    let _change = lock(&state.key_change);
    ensure_unlocked(state)?;
    if state.key_revision.load(Ordering::Acquire) != revision
        || state.running.load(Ordering::Acquire)
    {
        return Err("Key access changed. Arm deletion again.".into());
    }
    let mut controls = lock(&state.emergency);
    controls.next_arm = controls.next_arm.wrapping_add(1);
    controls.deletion = Some(ArmedDeletion {
        id: controls.next_arm,
        path: absolute,
        identity,
        digest: expected,
        missing: false,
    });
    controls.report = None;
    Ok(())
}

fn disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || matches!(error.raw_os_error(), Some(3 | 21 | 55 | 1167))
}

fn deletion_held(state: &AppState) -> bool {
    #[cfg(all(windows, not(test)))]
    {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            GetAsyncKeyState, VK_CONTROL, VK_D, VK_F11, VK_F12, VK_MENU, VK_SHIFT,
        };
        let down = |key| unsafe { GetAsyncKeyState(key as i32) < 0 };
        let _ = state;
        // Re-sample at each destructive boundary rather than trusting a
        // potentially stale value from the shortcut monitor's last tick.
        down(VK_CONTROL)
            && down(VK_SHIFT)
            && down(VK_MENU)
            && down(VK_D)
            && !down(VK_F11)
            && !down(VK_F12)
    }
    #[cfg(any(not(windows), test))]
    state.emergency_delete_held.load(Ordering::Acquire)
}

/// Runs before ordinary key refresh, even when its automatic load is disabled.
/// A genuine absent -> present transition consumes the arm whether held or not.
pub(crate) fn check_deletion(state: &AppState) -> bool {
    let Some(arm) = lock(&state.emergency).deletion.clone() else {
        return false;
    };
    let mut source = match Source::open(&arm.path, true) {
        Ok(source) => source,
        Err(error) if disappeared(&error) => {
            if let Some(current) = lock(&state.emergency)
                .deletion
                .as_mut()
                .filter(|current| current.id == arm.id)
            {
                current.missing = true;
            }
            return false;
        }
        // Access denial/sharing errors are not evidence of a removed drive.
        Err(_) => return false,
    };
    if !arm.missing {
        return false;
    }
    let _change = lock(&state.key_change);
    let mut controls = lock(&state.emergency);
    if !controls
        .deletion
        .as_ref()
        .is_some_and(|current| current.id == arm.id)
    {
        return false;
    }
    controls.disarm();
    if !deletion_held(state) {
        controls.report =
            Some("Deletion disarmed: the key returned without the held shortcut.".into());
        return true;
    }
    drop(controls);
    let result = (|| -> Result<String, String> {
        // Lock and persist before deletion; a failed check never leaves a live key.
        lock_inner(state)?;
        if file_guard::identity(&source.file).map_err(|error| error.to_string())? != arm.identity
            || key_digest(&mut source)? != arm.digest
        {
            return Err("Deletion cancelled: a different or changed key file returned.".into());
        }
        if !deletion_held(state) {
            return Err("Deletion cancelled: the shortcut was released.".into());
        }
        #[cfg(windows)]
        {
            match source.remove().map_err(|error| format!("Key deletion failed: {error}"))? {
                crate::deletion::DeletionState::Removed => Ok("The armed key file was deleted. Deletion is now disarmed.".into()),
                _ => Ok("Key deletion was accepted but removal is not yet confirmed. Deletion is now disarmed.".into()),
            }
        }
        #[cfg(not(windows))]
        Err("Emergency key deletion is available on Windows only.".into())
    })();
    lock(&state.emergency).report = Some(result.unwrap_or_else(|error| error));
    true
}

fn publish(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    crate::sandbox::close_invalid_previews(app);
    let _ = app.emit("key-status-changed", commands::status(&state));
}

#[tauri::command]
pub fn emergency_lock(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<AppStatus, String> {
    if window.label() != "main" {
        return Err("Use emergency controls from the main window.".into());
    }
    let result = lock_key(&app.state::<AppState>());
    publish(&app);
    result?;
    Ok(commands::status(&app.state::<AppState>()))
}

#[tauri::command]
pub async fn emergency_unlock(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    passphrase: Option<String>,
) -> Result<AppStatus, String> {
    if window.label() != "main" {
        return Err("Use emergency controls from the main window.".into());
    }
    let passphrase = passphrase.map(Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        unlock_key(
            &app.state::<AppState>(),
            passphrase.as_deref().map(String::as_str),
        )?;
        publish(&app);
        Ok(commands::status(&app.state::<AppState>()))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn arm_emergency_deletion(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    enabled: bool,
) -> Result<AppStatus, String> {
    if window.label() != "main" {
        return Err("Use emergency controls from Key options.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        if enabled {
            arm_deletion(&state)?;
        } else {
            let _change = lock(&state.key_change);
            lock(&state.emergency).disarm();
        }
        publish(&app);
        Ok(commands::status(&state))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(windows)]
pub(crate) fn start_shortcuts(app: tauri::AppHandle) {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_CONTROL, VK_D, VK_F11, VK_F12, VK_MENU, VK_SHIFT,
    };
    // Only the current-down high bit is used; Windows' "pressed since last call"
    // bit is shared and unreliable. No keyboard input is recorded or stored.
    let down = |key| unsafe { GetAsyncKeyState(key as i32) < 0 };
    std::thread::spawn(move || {
        let mut lock_was_down = false;
        let mut unlock_was_down = false;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(40));
            if app.get_webview_window("main").is_none() {
                break;
            }
            let ctrl_shift = down(VK_CONTROL) && down(VK_SHIFT);
            let lock_down = ctrl_shift && !down(VK_MENU) && down(VK_F12);
            let unlock_down = ctrl_shift && !down(VK_MENU) && !down(VK_F12) && down(VK_F11);
            let state = app.state::<AppState>();
            state.emergency_delete_held.store(
                ctrl_shift && down(VK_MENU) && down(VK_D) && !down(VK_F11) && !down(VK_F12),
                Ordering::Release,
            );
            if lock_down && !lock_was_down {
                let result = lock_key(&state);
                publish(&app);
                if let Err(error) = result {
                    let _ = app.emit_to("main", "emergency-action-failed", error);
                }
            }
            if unlock_down && !unlock_was_down && state.emergency_locked.load(Ordering::Acquire) {
                let _ = app.emit_to("main", "emergency-unlock-requested", ());
            }
            lock_was_down = lock_down;
            unlock_was_down = unlock_down;
        }
    });
}

#[cfg(not(windows))]
pub(crate) fn start_shortcuts(_: tauri::AppHandle) {}

#[cfg(test)]
pub(crate) fn set_test_marker(state: &AppState, path: PathBuf) {
    lock(&state.emergency).marker = Some(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    fn fixture() -> (TestDir, AppState, PathBuf) {
        let dir = TestDir::new();
        let state = AppState::default();
        lock(&state.emergency).marker = Some(dir.0.join("emergency.lock"));
        crate::key_protection::set_test_access(&state, dir.0.join("access-setup.complete"), "correct passphrase");
        let path = dir.0.join("saved.key");
        key_file::write_key_file(&path, &[42; 32]).unwrap();
        commands::restore_saved_key_from_path(&state, &path);
        (dir, state, path)
    }

    #[test]
    fn lock_survives_restart_and_blocks_all_automatic_or_manual_activation() {
        let (dir, state, path) = fixture();
        lock_key(&state).unwrap();
        assert!(lock(&state.key).is_none());
        assert!(dir.0.join("emergency.lock").exists());
        for _ in 0..3 {
            fs::remove_file(&path).unwrap();
            assert!(!commands::refresh_key_file(&state));
            key_file::write_key_file(&path, &[42; 32]).unwrap();
            assert!(!commands::refresh_key_file(&state));
            commands::restore_saved_key_from_path(&state, &path);
            assert!(lock(&state.key).is_none());
            assert_eq!(ensure_unlocked(&state).unwrap_err(), UNAVAILABLE);
        }
        let restarted = AppState::default();
        let marker = dir.0.join("emergency.lock");
        restarted
            .emergency_locked
            .store(marker.try_exists().unwrap(), Ordering::Release);
        lock(&restarted.emergency).marker = Some(marker);
        crate::key_protection::restore_setup(&restarted, dir.0.join("access-setup.complete"));
        commands::restore_saved_key_from_path(&restarted, &path);
        assert!(lock(&restarted.key).is_none());
        assert!(unlock_key(&restarted, None).is_err());
        unlock_key(&restarted, Some("correct passphrase")).unwrap();
        assert!(lock(&restarted.key).is_some());
        assert!(!restarted.emergency_locked.load(Ordering::Acquire));
    }

    #[test]
    fn failed_unlock_preserves_the_persistent_lock() {
        let (dir, state, path) = fixture();
        lock_key(&state).unwrap();
        fs::remove_file(path).unwrap();
        assert!(unlock_key(&state, None).is_err());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(dir.0.join("emergency.lock").exists());
    }

    #[test]
    fn unprotected_key_still_requires_the_emergency_password_to_unlock() {
        let (_dir, state, _path) = fixture();
        lock_key(&state).unwrap();
        assert!(unlock_key(&state, None).is_err());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(unlock_key(&state, Some("incorrect")).is_err());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        unlock_key(&state, Some("correct passphrase")).unwrap();
        assert_eq!(lock(&state.key).as_deref(), Some(&[42; 32]));
    }

    #[test]
    fn lock_persistence_failure_keeps_current_access_locked() {
        let (dir, state, _) = fixture();
        let blocked = dir.0.join("blocked");
        fs::write(&blocked, b"not a directory").unwrap();
        lock(&state.emergency).marker = Some(blocked.join("emergency.lock"));
        assert!(lock_key(&state).is_err());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        assert!(lock(&state.key).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn deletion_requires_arming_departure_and_held_shortcut_and_is_one_shot() {
        let (_dir, state, path) = fixture();
        state.emergency_delete_held.store(true, Ordering::Release);
        assert!(!check_deletion(&state));
        assert!(path.exists());
        arm_deletion(&state).unwrap();
        assert!(!check_deletion(&state));
        let away = path.with_extension("away");
        fs::rename(&path, &away).unwrap();
        assert!(!check_deletion(&state));
        fs::rename(&away, &path).unwrap();
        assert!(check_deletion(&state));
        assert!(!path.exists());
        assert!(state.emergency_locked.load(Ordering::Acquire));
        key_file::write_key_file(&path, &[42; 32]).unwrap();
        assert!(!check_deletion(&state));
        assert!(path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn releasing_shortcut_or_replacing_the_key_preserves_files_and_disarms() {
        for different in [false, true] {
            let (_dir, state, path) = fixture();
            arm_deletion(&state).unwrap();
            let away = path.with_extension("away");
            fs::rename(&path, &away).unwrap();
            check_deletion(&state);
            if different {
                key_file::write_key_file(&path, &[9; 32]).unwrap();
            } else {
                fs::rename(&away, &path).unwrap();
            }
            state
                .emergency_delete_held
                .store(different, Ordering::Release);
            assert!(check_deletion(&state));
            assert!(path.exists());
            assert!(lock(&state.emergency).armed_path().is_none());
        }
    }

    #[cfg(windows)]
    #[test]
    fn identical_bytes_in_a_different_file_are_not_deleted() {
        let (_dir, state, path) = fixture();
        arm_deletion(&state).unwrap();
        let away = path.with_extension("away");
        fs::rename(&path, &away).unwrap();
        check_deletion(&state);
        key_file::write_key_file(&path, &[42; 32]).unwrap();
        state.emergency_delete_held.store(true, Ordering::Release);
        assert!(check_deletion(&state));
        assert!(path.exists());
        assert!(away.exists());
        assert!(state.emergency_locked.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn sharing_errors_do_not_count_as_a_removed_drive() {
        use std::os::windows::fs::OpenOptionsExt;
        let (_dir, state, path) = fixture();
        arm_deletion(&state).unwrap();
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        check_deletion(&state);
        drop(held);
        state.emergency_delete_held.store(true, Ordering::Release);
        assert!(!check_deletion(&state));
        assert!(path.exists());
        assert!(lock(&state.emergency).armed_path().is_some());
    }
}
