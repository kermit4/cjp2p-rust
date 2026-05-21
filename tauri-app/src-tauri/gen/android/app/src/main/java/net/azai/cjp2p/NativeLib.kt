package net.azai.cjp2p

class NativeLib {
    companion object {
        // The Tauri build compiles everything into libcjp2p_tauri_lib.so
        init { System.loadLibrary("cjp2p_tauri_lib") }

        @JvmStatic
        external fun start(dataDir: String, lcdpPort: Int, httpPort: Int)
    }
}
