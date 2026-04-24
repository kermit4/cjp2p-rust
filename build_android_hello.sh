#!/bin/bash
# Diagnostic APK: runs the real binary but shows each step on screen.
# Backs up and restores all modified source files automatically.
set -e

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$PROJECT_DIR/android"
JAVA_DIR="$ANDROID_DIR/app/src/main/java/com/cjp2p"
JNILIBS="$ANDROID_DIR/app/src/main/jniLibs"

GRADLE_VERSION="8.9"
GRADLE_BIN="$HOME/.gradle/gradle-${GRADLE_VERSION}/bin/gradle"

restore() {
    echo "=== Restoring original source files ==="
    [ -f "$JAVA_DIR/MainActivity.java.bak" ] && mv "$JAVA_DIR/MainActivity.java.bak" "$JAVA_DIR/MainActivity.java"
    [ -f "$JAVA_DIR/BackendService.java.bak" ] && mv "$JAVA_DIR/BackendService.java.bak" "$JAVA_DIR/BackendService.java"
    [ -d "${JNILIBS}.bak" ] && mv "${JNILIBS}.bak" "$JNILIBS"
}
trap restore EXIT

echo "=== Swapping in hello-world source ==="
cp "$JAVA_DIR/MainActivity.java" "$JAVA_DIR/MainActivity.java.bak"
cp "$JAVA_DIR/BackendService.java" "$JAVA_DIR/BackendService.java.bak"

cat > "$JAVA_DIR/MainActivity.java" << 'EOF'
package com.cjp2p;

import android.app.Activity;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.Handler;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class MainActivity extends Activity {
    private TextView tv;
    private Handler handler;
    private StringBuilder log = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        tv = new TextView(this);
        tv.setTextSize(18);
        tv.setPadding(16, 16, 16, 16);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
        handler = new Handler(getMainLooper());

        say("started");
        new Thread(this::runTests).start();
    }

    private void say(String msg) {
        log.append(msg).append("\n");
        final String snap = log.toString();
        handler.post(() -> tv.setText(snap));
    }

    private void runTests() {
        // 1. UDP
        try {
            byte[] msg = "hello from cjp2p android".getBytes();
            DatagramSocket sock = new DatagramSocket();
            sock.send(new DatagramPacket(msg, msg.length,
                    InetAddress.getByName("148.71.89.128"), 4444));
            sock.close();
            say("udp: sent ok");
        } catch (Throwable e) {
            say("udp: FAIL " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // 2. Find the binary
        String binPath = getApplicationInfo().nativeLibraryDir + "/libcjp2p.so";
        File bin = new File(binPath);
        say("binary exists: " + bin.exists() + "  path: " + binPath);
        say("binary canExec: " + bin.canExecute());

        // 3. filesDir
        File filesDir = getFilesDir();
        say("filesDir: " + filesDir);
        say("filesDir exists: " + filesDir.exists());

        // 4. Extract assets
        try {
            AssetManager am = getAssets();
            String[] files = am.list("public");
            say("assets/public count: " + (files == null ? "null" : files.length));
            if (files != null && files.length > 0) {
                File pubDir = new File(filesDir, "cjp2p/public");
                pubDir.mkdirs();
                for (String name : files) {
                    File dest = new File(pubDir, name);
                    try (InputStream in = am.open("public/" + name);
                         OutputStream out = new FileOutputStream(dest)) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                    }
                }
                say("assets extracted to: " + pubDir);
            }
        } catch (Throwable e) {
            say("assets: FAIL " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // 5. Run the binary regardless of canExecute() - that flag is unreliable on Android
        say("attempting binary launch (exists=" + bin.exists() + " canExec=" + bin.canExecute() + ")");
        try {
            ProcessBuilder pb = new ProcessBuilder(binPath);
            pb.directory(filesDir);
            pb.redirectErrorStream(true);
            pb.environment().put("RUST_LOG", "info");
            Process proc = pb.start();
            say("process started");

            StringBuilder out = new StringBuilder();
            byte[] buf = new byte[4096];
            InputStream is = proc.getInputStream();
            long deadline = System.currentTimeMillis() + 3000;
            while (System.currentTimeMillis() < deadline) {
                if (is.available() > 0) {
                    int n = is.read(buf);
                    if (n == -1) break;
                    out.append(new String(buf, 0, n));
                } else {
                    Thread.sleep(100);
                }
            }
            boolean alive = true;
            try { int code = proc.exitValue(); alive = false; say("binary exited code " + code); }
            catch (IllegalThreadStateException ignored) { say("binary still running after 3s (good)"); }
            if (alive) proc.destroy();

            say("binary output:\n" + (out.length() > 0 ? out.toString() : "(none)"));
        } catch (Throwable e) {
            say("binary launch FAIL: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        say("--- done ---");
    }
}
EOF

cat > "$JAVA_DIR/BackendService.java" << 'EOF'
package com.cjp2p;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class BackendService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }
    @Override
    public IBinder onBind(Intent intent) { return null; }
}
EOF

# Keep jniLibs - we want the real binary included for testing

echo "=== Building APK ==="
echo "sdk.dir=$ANDROID_SDK_ROOT" > "$ANDROID_DIR/local.properties"
cd "$ANDROID_DIR"
"$GRADLE_BIN" assembleDebug

APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "======================================"
echo "Hello APK ready: $APK"
echo ""
echo "Copy to phone and install, you should see:"
echo "  'Hello from cjp2p APK - it works!'"
echo "======================================"
