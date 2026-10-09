mod archive;
mod archive_read;
mod commands;
mod crypto;
mod deletion;
mod file_guard;
mod key_file;
mod publication;
mod sandbox;
mod source;
#[cfg(test)]
mod test_support;

/// Parse an in-memory archive with the same checks used for files selected in the app.
/// This entry point also lets the fuzz target exercise the parser without disk I/O.
pub fn inspect_zip_bytes(bytes: &[u8]) -> Result<usize, String> {
    archive_read::entries_from_reader(&mut std::io::Cursor::new(bytes))
        .map(|entries| entries.len())
        .map_err(|err| err.to_string())
}

#[cfg(not(fuzzing))]
use tauri::Manager;

#[cfg(not(fuzzing))]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(commands::AppState::default())
        .on_window_event(|window, event| {
            if window.label() == "main" && matches!(event, tauri::WindowEvent::Destroyed) {
                commands::clear_key_on_close(window.state::<commands::AppState>().inner());
            }
        })
        .setup(|app| {
            commands::restore_saved_key(app.handle(), app.state::<commands::AppState>().inner());
            commands::start_key_monitor(app.handle().clone());
            sandbox::start_monitor(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::recheck_key_file,
            commands::pick_input_files,
            commands::pick_input_folder,
            commands::expand_dropped_paths,
            commands::pick_save_path,
            commands::pick_output_dir,
            commands::set_output_dir,
            commands::generate_key,
            commands::save_typed_key,
            commands::use_typed_key,
            commands::load_key,
            commands::browse_key,
            commands::backup_key,
            commands::check_key_backup,
            commands::unload_key,
            commands::preview_job,
            commands::run_job,
            commands::cancel_job,
            commands::retry_deletion,
            commands::check_pending_deletions,
            commands::rotate_key,
            commands::check_for_updates,
            commands::install_update,
            sandbox::open_sandbox,
            sandbox::read_sandbox_file,
            sandbox::check_sandbox,
            sandbox::close_sandbox,
        ])
        .build(tauri::generate_context!())
        .expect("error while building FileEncrypt")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                commands::clear_key_on_close(app.state::<commands::AppState>().inner());
            }
        });
}
