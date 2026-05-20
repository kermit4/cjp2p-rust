use tauri::Manager;

// JNI entry point for BackendService (net.azai.cjp2p.NativeLib.start).
// Must live here in the cdylib crate -- symbols in rlib dependencies are
// dead-stripped and never appear in the final .so.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
mod android_jni {
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;

    #[no_mangle]
    pub extern "C" fn Java_net_azai_cjp2p_NativeLib_start<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        data_dir: JString<'local>,
        lcdp_port: i32,
        http_port: i32,
    ) {
        let dir: String = env
            .get_string(&data_dir)
            .map(|s| s.into())
            .unwrap_or_default();
        let lp = lcdp_port as u16;
        let hp = http_port as u16;
        let _ = std::thread::Builder::new()
            .name("cjp2p-svc".into())
            .spawn(move || {
                cjp2p::run_from_android(&dir, lp, hp);
            });
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir().expect("no app data dir");
            std::fs::create_dir_all(&data_dir).expect("create app data dir");

            // On Android the Rust backend runs as a separate Foreground Service
            // (BackendService.kt, android:process=":backend") so Android never
            // freezes it when the app is backgrounded.  The service starts itself
            // from MainActivity.onCreate; nothing to do here.
            #[cfg(not(target_os = "android"))]
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
