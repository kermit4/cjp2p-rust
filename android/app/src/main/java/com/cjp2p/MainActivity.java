package com.cjp2p;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final String STATUS_URL = "http://127.0.0.1:24255/status.json";
    private static final int POLL_MS = 3000;
    private static final int PICK_FILE = 1;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView tvVersion, tvPubkey, tvStatusDot;
    private TextView tvTotalPeers, tvActivePeers, tvFastPeers, tvUniqueIps;
    private LinearLayout llPeers;
    private TextView tvLastUpdate;
    private boolean running = true;
    private File filesDir;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        filesDir = getFilesDir();

        tvVersion    = findViewById(R.id.tv_version);
        tvPubkey     = findViewById(R.id.tv_pubkey);
        tvStatusDot  = findViewById(R.id.tv_status_dot);
        tvTotalPeers = findViewById(R.id.tv_total_peers);
        tvActivePeers= findViewById(R.id.tv_active_peers);
        tvFastPeers  = findViewById(R.id.tv_fast_peers);
        tvUniqueIps  = findViewById(R.id.tv_unique_ips);
        llPeers      = findViewById(R.id.ll_peers);
        tvLastUpdate = findViewById(R.id.tv_last_update);

        findViewById(R.id.btn_share_file).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, PICK_FILE);
        });

        startForegroundService(new Intent(this, BackendService.class));
        schedulePoll(1500);
    }

    // -- File sharing ---------------------------------------------------------

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_FILE && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                Toast.makeText(this, "Hashing file…", Toast.LENGTH_SHORT).show();
                new Thread(() -> copyFileToPublic(uri)).start();
            }
        }
    }

    private void copyFileToPublic(Uri uri) {
        try {
            File pubDir = new File(filesDir, "cjp2p/public");
            pubDir.mkdirs();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];

            // Stream to a temp file while computing the hash in one pass
            File tmp = new File(pubDir, "tmp_" + System.currentTimeMillis());
            try (InputStream in = getContentResolver().openInputStream(uri);
                 FileOutputStream out = new FileOutputStream(tmp)) {
                int n;
                while ((n = in.read(buf)) != -1) {
                    digest.update(buf, 0, n);
                    out.write(buf, 0, n);
                }
            }

            // Rename to the hex SHA-256
            byte[] raw = digest.digest();
            StringBuilder sb = new StringBuilder(64);
            for (byte b : raw) sb.append(String.format("%02x", b));
            String hash = sb.toString();

            File dest = new File(pubDir, hash);
            if (!tmp.renameTo(dest)) {
                // renameTo can fail across filesystems; fall back to copy+delete
                try (InputStream in = getContentResolver().openInputStream(uri);
                     FileOutputStream out = new FileOutputStream(dest)) {
                    int n;
                    while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                }
                tmp.delete();
            }

            handler.post(() -> showHashDialog(hash));
        } catch (Exception e) {
            handler.post(() -> Toast.makeText(this,
                    "Error: " + e.getMessage(), Toast.LENGTH_LONG).show());
        }
    }

    private void showHashDialog(String hash) {
        new AlertDialog.Builder(this)
            .setTitle("File added to cjp2p/public/")
            .setMessage("Share this hash with anyone who wants to download it:\n\n" + hash)
            .setPositiveButton("Copy hash", (d, w) -> {
                ClipboardManager cm = getSystemService(ClipboardManager.class);
                cm.setPrimaryClip(ClipData.newPlainText("cjp2p hash", "http://localhost:24255/" + hash));
                Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
            })
            .setNegativeButton("OK", null)
            .show();
    }

    // -- Status polling -------------------------------------------------------

    private void schedulePoll(long delayMs) {
        handler.postDelayed(() -> {
            if (!running) return;
            new Thread(this::fetchAndUpdate).start();
            schedulePoll(POLL_MS);
        }, delayMs);
    }

    private void fetchAndUpdate() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(STATUS_URL).openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setRequestMethod("GET");

            int code = conn.getResponseCode();
            if (code != 200) return;

            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line);
            }
            JSONObject json = new JSONObject(sb.toString());
            handler.post(() -> applyJson(json));
        } catch (Exception ignored) {
            handler.post(this::markOffline);
        }
    }

    private void applyJson(JSONObject j) {
        try {
            tvStatusDot.setTextColor(android.graphics.Color.GREEN);
            tvVersion.setText(j.optString("version", ""));

            String pk = j.optString("public_key", "");
            if (pk.length() > 28) {
                tvPubkey.setText(pk.substring(0, 20) + "…" + pk.substring(pk.length() - 8));
            } else {
                tvPubkey.setText(pk);
            }

            tvTotalPeers.setText(String.valueOf(j.optInt("total_peers", 0)));
            tvActivePeers.setText(String.valueOf(j.optInt("active_peer_count", 0)));
            tvFastPeers.setText(String.valueOf(j.optInt("fast_peer_count", 0)));
            tvUniqueIps.setText(j.optInt("unique_ips", 0) + " unique IPs");

            JSONArray peers = j.optJSONArray("active_peers");
            llPeers.removeAllViews();
            if (peers != null) {
                for (int i = 0; i < peers.length(); i++) {
                    JSONObject p = peers.getJSONObject(i);
                    String pub  = p.optString("pub", "");
                    String addr = p.optString("addr", "");
                    long delay  = p.optLong("delay_ms", 0);

                    LinearLayout row = new LinearLayout(this);
                    row.setOrientation(LinearLayout.HORIZONTAL);
                    row.setPadding(0, 8, 0, 8);

                    TextView tvDelay = new TextView(this);
                    tvDelay.setText(delay + "ms");
                    tvDelay.setTextAppearance(android.R.style.TextAppearance_Small);
                    tvDelay.setTypeface(Typeface.MONOSPACE);
                    tvDelay.setMinWidth(dpToPx(56));
                    row.addView(tvDelay);

                    LinearLayout col = new LinearLayout(this);
                    col.setOrientation(LinearLayout.VERTICAL);
                    col.setLayoutParams(new LinearLayout.LayoutParams(
                            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

                    TextView tvPub = new TextView(this);
                    String shortPub = pub.length() > 22 ? pub.substring(0, 22) + "…" : pub;
                    tvPub.setText(shortPub);
                    tvPub.setTextAppearance(android.R.style.TextAppearance_Small);
                    tvPub.setTypeface(Typeface.MONOSPACE);

                    TextView tvAddr = new TextView(this);
                    tvAddr.setText(addr);
                    tvAddr.setTextAppearance(android.R.style.TextAppearance_Small);
                    tvAddr.setTextColor(android.graphics.Color.GRAY);
                    tvAddr.setTypeface(Typeface.MONOSPACE);

                    col.addView(tvPub);
                    col.addView(tvAddr);
                    row.addView(col);

                    View divider = new View(this);
                    LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT, 1);
                    divider.setLayoutParams(lp);
                    divider.setBackgroundColor(android.graphics.Color.LTGRAY);

                    llPeers.addView(row);
                    llPeers.addView(divider);
                }
            }

            String ts = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
            tvLastUpdate.setText("updated " + ts);
        } catch (Exception ignored) {}
    }

    private void markOffline() {
        tvStatusDot.setTextColor(android.graphics.Color.GRAY);
        tvVersion.setText("connecting…");
    }

    private int dpToPx(int dp) {
        return Math.round(dp * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        running = false;
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
