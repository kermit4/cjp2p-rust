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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class BackendService extends Service {
    private static final String TAG = "cjp2p";
    private static final String CHANNEL_ID = "cjp2p_bg";
    private static boolean started = false;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "cjp2p", NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(ch);

        Notification note = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("cjp2p")
                .setContentText("P2P engine running")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .build();
        startForeground(1, note);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!started) {
            started = true;
            try {
                File filesDir = getFilesDir();
                extractPublicAssets(filesDir);
                redirectStderrToFile();
                android.system.Os.setenv("RUST_LOG", "info", true);
                NativeLib.start(filesDir.getAbsolutePath());
                Log.i(TAG, "P2P engine started in-process");
            } catch (Exception e) {
                Log.e(TAG, "Failed to start P2P engine", e);
            }
        }
        return START_STICKY;
    }

    private void redirectStderrToFile() {
        try {
            File logFile = new File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                "cjp2p.log");
            FileOutputStream fos = new FileOutputStream(logFile, true);
            String header = "\n=== " +
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()) +
                " ===\n";
            fos.write(header.getBytes());
            fos.flush();
            // Rewire fd 2 (stderr) so env_logger output lands in the file
            android.system.Os.dup2(fos.getFD(), 2);
            Log.i(TAG, "Logging to " + logFile.getAbsolutePath());
        } catch (Exception e) {
            Log.w(TAG, "Could not open log file: " + e.getMessage());
        }
    }

    private void extractPublicAssets(File filesDir) throws IOException {
        AssetManager am = getAssets();
        String[] files = am.list("public");
        if (files == null) return;

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
            Log.i(TAG, "asset extracted: " + name);
        }
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
