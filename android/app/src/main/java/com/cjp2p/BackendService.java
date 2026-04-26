package com.cjp2p;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Environment;
import android.os.IBinder;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class BackendService extends Service {
    private static final String TAG = "cjp2p";
    private static final String CHANNEL_ID = "cjp2p_bg";
    private Process backendProcess;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "cjp2p", NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(ch);

        Notification note = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("cjp2p")
                .setContentText("P2P backend running")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .build();
        startForeground(1, note);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (backendProcess == null) {
            new Thread(this::runBackend).start();
        }
        return START_STICKY;
    }

    private File logFile() {
        return new File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            "cjp2p4.log");
    }

    private void log(String msg) {
        Log.i(TAG, msg);
        try (BufferedWriter w = new BufferedWriter(new FileWriter(logFile(), true))) {
            w.write(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())
                    + " " + msg + "\n");
        } catch (Throwable ignored) {}
    }

    private void runBackend() {
        try {
            File filesDir = getFilesDir();
            log("=== cjp2p service started ===");

            extractPublicAssets(filesDir);

            String binaryPath = getApplicationInfo().nativeLibraryDir + "/libcjp2p.so";
            log("binary: " + binaryPath);
            log("workdir: " + filesDir);

            ProcessBuilder pb = new ProcessBuilder(binaryPath);
            pb.directory(filesDir);
            pb.redirectErrorStream(true);
            pb.environment().put("RUST_LOG", "info");
            backendProcess = pb.start();
            log("process started, pid draining output...");

            byte[] buf = new byte[4096];
            int n;
            try (InputStream is = backendProcess.getInputStream();
                 BufferedWriter w = new BufferedWriter(new FileWriter(logFile(), true))) {
                while ((n = is.read(buf)) != -1) {
                    String chunk = new String(buf, 0, n);
                    Log.i(TAG, chunk.trim());
                    w.write(chunk);
                    w.flush();
                }
            }
            int code = backendProcess.waitFor();
            log("=== exited code " + code + " ===");
        } catch (Throwable e) {
            log("CRASH: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.e(TAG, "backend crashed", e);
        } finally {
            backendProcess = null;
        }
    }

    // Copies assets/public/* -> filesDir/cjp2p/public/ on first run
    private void extractPublicAssets(File filesDir) throws IOException {
        AssetManager am = getAssets();
        String[] files = am.list("public");
        if (files == null) return;

        File pubDir = new File(filesDir, "cjp2p/public");
        pubDir.mkdirs();

        for (String name : files) {
            File dest = new File(pubDir, name);
            // Always overwrite so updates to the APK take effect
            try (InputStream in = am.open("public/" + name);
                 OutputStream out = new FileOutputStream(dest)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            }
            Log.i(TAG, "asset extracted: " + name);
        }
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        if (backendProcess != null) {
            backendProcess.destroy();
            backendProcess = null;
        }
        super.onDestroy();
    }
}
