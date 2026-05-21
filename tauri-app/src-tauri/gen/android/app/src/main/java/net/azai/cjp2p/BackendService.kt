package net.azai.cjp2p

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.res.AssetManager
import android.os.Environment
import android.os.IBinder
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// Runs the cjp2p Rust engine in a dedicated Android process so it is never
// frozen when the user switches away from the app.  Declared in the manifest
// with android:process=":backend" and android:foregroundServiceType="dataSync".
class BackendService : Service() {

    companion object {
        private const val TAG = "cjp2p"
        private const val CHANNEL_ID = "cjp2p_bg"
        private var started = false
    }

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "cjp2p", NotificationManager.IMPORTANCE_LOW)
        )
        val note = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("cjp2p")
            .setContentText("P2P engine running")
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .build()
        startForeground(2, note)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!started) {
            started = true
            try {
                val filesDir = filesDir
                extractPublicAssets(filesDir)
                redirectStderrToFile()
                android.system.Os.setenv("RUST_LOG", "info", true)
                // Same default ports as parse_args() in src/main.rs: lcdp=24254, http=24255
                NativeLib.start(filesDir.absolutePath, 24254, 24255)
                Log.i(TAG, "P2P engine started in :backend process")
                // Poll until the engine accepts connections, then broadcast so
                // MainActivity can reload the WebView without a fixed delay.
                val pkg = packageName
                Thread {
                    waitForPort(24255)
                    val ready = Intent("net.azai.cjp2p.BACKEND_READY").apply { setPackage(pkg) }
                    sendBroadcast(ready)
                    Log.i(TAG, "Backend ready on :24255, broadcast sent")
                }.start()
            } catch (t: Throwable) {
                // Catches both Exception and Error (e.g. UnsatisfiedLinkError on wrong .so name)
                Log.e(TAG, "Failed to start P2P engine", t)
                writeThrowableToLog(t)
            }
        }
        return START_STICKY
    }

    private fun waitForPort(port: Int) {
        repeat(120) {
            try {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress("127.0.0.1", port), 250)
                }
                return
            } catch (_: Exception) { }
            Thread.sleep(250)
        }
        Log.w(TAG, "port $port never became available after 30s")
    }

    private fun writeThrowableToLog(t: Throwable) {
        try {
            val logFile = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                "cjp2p_tauri.log"
            )
            FileOutputStream(logFile, true).use { fos ->
                val msg = "\n=== CRASH ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())} ===\n" +
                    "$t\n" +
                    t.stackTraceToString() + "\n"
                fos.write(msg.toByteArray())
            }
        } catch (_: Exception) { }
    }

    private fun redirectStderrToFile() {
        try {
            val logFile = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                "cjp2p_tauri.log"
            )
            val fos = FileOutputStream(logFile, true)
            val header = "\n=== ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())} ===\n"
            fos.write(header.toByteArray())
            fos.flush()
            android.system.Os.dup2(fos.fd, 2)
            Log.i(TAG, "Logging to ${logFile.absolutePath}")
        } catch (e: Exception) {
            Log.w(TAG, "Could not open log file: ${e.message}")
        }
    }

    private fun extractPublicAssets(filesDir: File) {
        val am: AssetManager = assets
        val files: Array<String> = am.list("public") ?: return
        val pubDir = File(filesDir, "cjp2p/public")
        pubDir.mkdirs()
        for (name in files) {
            val dest = File(pubDir, name)
            try {
                am.open("public/$name").use { input ->
                    FileOutputStream(dest).use { output ->
                        input.copyTo(output)
                    }
                }
                Log.i(TAG, "asset extracted: $name")
            } catch (e: IOException) {
                Log.w(TAG, "Could not extract asset $name: ${e.message}")
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
