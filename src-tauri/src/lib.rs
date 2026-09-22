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
            commands::pick_save_path,
            commands::pick_output_dir,
            commands::set_output_dir,
            commands::generate_key,
            commands::save_typed_key,
            commands::load_key,
            commands::browse_key,
            commands::unload_key,
            commands::encrypt_files,
            commands::decrypt_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running FileEncrypt");
}
