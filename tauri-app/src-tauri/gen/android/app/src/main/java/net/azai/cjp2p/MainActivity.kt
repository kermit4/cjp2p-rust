package net.azai.cjp2p

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.webkit.WebView
import androidx.core.content.ContextCompat

class MainActivity : TauriActivity() {
  private var webViewRef: WebView? = null

  // Fires once BackendService confirms port 24255 is accepting connections.
  private val backendReadyReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
      webViewRef?.post { webViewRef?.reload() }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    startBackendService()
  }

  // Called by WryActivity.setWebView() — store a reference so we can reload later.
  override fun onWebViewCreate(webView: WebView) {
    webViewRef = webView
  }

  override fun onStart() {
    super.onStart()
    ContextCompat.registerReceiver(
      this,
      backendReadyReceiver,
      IntentFilter("net.azai.cjp2p.BACKEND_READY"),
      ContextCompat.RECEIVER_NOT_EXPORTED
    )
  }

  override fun onStop() {
    super.onStop()
    unregisterReceiver(backendReadyReceiver)
  }

  private fun startBackendService() {
    val intent = Intent(this, BackendService::class.java)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      startForegroundService(intent)
    } else {
      startService(intent)
    }
  }
}
