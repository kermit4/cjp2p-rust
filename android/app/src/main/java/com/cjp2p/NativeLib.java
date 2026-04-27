package com.cjp2p;

class NativeLib {
    static {
        System.loadLibrary("cjp2p");
    }

    // Starts the P2P engine in a background thread inside the process.
    // dataDir is used as the working directory so relative paths (./cjp2p/...)
    // resolve correctly — pass getFilesDir().getAbsolutePath().
    static native void start(String dataDir);
}
