mod archive;
mod archive_read;
mod commands;
mod crypto;
mod key_file;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::default())
        .setup(|app| {
            commands::restore_saved_key(app.handle(), app.state::<commands::AppState>().inner());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::pick_input_files,
            commands::pick_input_folder,
            commands::expand_dropped_paths,
            commands::pick_save_path,
            commands::pick_output_dir,
            commands::set_output_dir,
            commands::generate_key,
            commands::save_typed_key,
            commands::load_key,
            commands::browse_key,
            commands::backup_key,
            commands::check_key_backup,
            commands::unload_key,
            commands::preview_job,
            commands::run_job,
            commands::cancel_job,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FileEncrypt");
}
