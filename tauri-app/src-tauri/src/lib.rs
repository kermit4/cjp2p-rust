use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir().expect("no app data dir");
            std::fs::create_dir_all(&data_dir).expect("create app data dir");

            // Start the cjp2p P2P backend in a background thread.
            // It binds HTTP+WebSocket on port 24255; pong.html connects to ws://localhost:24255/wt.
            std::thread::Builder::new()
                .name("cjp2p".into())
                .spawn(move || {
                    std::env::set_current_dir(&data_dir).ok();
                    let _ = cjp2p::run();
                })
                .expect("failed to spawn cjp2p thread");

            Ok(())
        })
        .plugin(tauri_plugin_notification::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
