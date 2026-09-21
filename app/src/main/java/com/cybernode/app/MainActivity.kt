package com.cybernode.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var firewall: CyberShieldFirewall
    private lateinit var wifiManager: WifiManager
    private var isReceiverRegistered = false

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val fineGranted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true
        if (fineGranted) {
            triggerWifiScan()
        }
    }

    private val wifiReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            runOnUiThread {
                webView.evaluateJavascript("if (typeof triggerScan === 'function') triggerScan();", null)
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        firewall = CyberShieldFirewall(this)
        wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

        webView = WebView(this).apply {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = true
                allowContentAccess = true
                useWideViewPort = false
                loadWithOverviewMode = false
                textZoom = 100
                setSupportZoom(false)
                displayZoomControls = false
                cacheMode = WebSettings.LOAD_DEFAULT
            }
            webViewClient = WebViewClient()
            webChromeClient = WebChromeClient()

            addJavascriptInterface(FirewallBridge(firewall), "AndroidFirewall")
            loadUrl("file:///android_asset/index.html")
        }

        setContentView(webView)
        checkAndRequestPermissions()
    }

    private fun checkAndRequestPermissions() {
        val permissionsToRequest = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionsToRequest.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }

        val missing = permissionsToRequest.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
        } else {
            triggerWifiScan()
        }
    }

    private fun triggerWifiScan(): Boolean {
        return try {
            @Suppress("DEPRECATION")
            wifiManager.startScan()
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    override fun onResume() {
        super.onResume()
        if (!isReceiverRegistered) {
            val filter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
            ContextCompat.registerReceiver(this, wifiReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
            isReceiverRegistered = true
        }
        triggerWifiScan()
    }

    override fun onPause() {
        super.onPause()
        if (isReceiverRegistered) {
            try {
                unregisterReceiver(wifiReceiver)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            isReceiverRegistered = false
        }
    }

    inner class FirewallBridge(private val firewall: CyberShieldFirewall) {
        @JavascriptInterface
        fun enforce(ssid: String, bssid: String, score: Int, encryption: String, channel: Int): String {
            val net = WifiNetwork(ssid, bssid, -50, encryption, channel)
            val assessment = ThreatEngine.assess(net, firewall.trustedNetworks)
            val action = firewall.enforce(assessment)
            return "{\"action\":\"${action.actionTaken}\",\"led\":\"${action.ledColor}\",\"vibrate\":${action.shouldVibrate}}"
        }

        @JavascriptInterface
        fun requestScan(): Boolean {
            return triggerWifiScan()
        }

        @JavascriptInterface
        fun getWifiScan(): String {
            return try {
                val hasFineLocation = ContextCompat.checkSelfPermission(
                    this@MainActivity,
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) == PackageManager.PERMISSION_GRANTED

                if (!hasFineLocation) {
                    return ""
                }

                @Suppress("DEPRECATION")
                val results: List<ScanResult> = wifiManager.scanResults ?: emptyList()
                if (results.isEmpty()) {
                    return ""
                }

                val allNetworks = results.map { scanResult ->
                    val rawSsid = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        scanResult.wifiSsid?.toString()?.replace("\"", "") ?: scanResult.SSID
                    } else {
                        scanResult.SSID
                    }
                    val ssid = if (rawSsid.isNullOrBlank()) "[Hidden Network]" else rawSsid
                    val bssid = scanResult.BSSID ?: "00:00:00:00:00:00"
                    val rssi = scanResult.level
                    val caps = scanResult.capabilities ?: ""
                    val encryption = when {
                        caps.contains("WPA3", ignoreCase = true) -> "WPA3"
                        caps.contains("WPA2", ignoreCase = true) -> "WPA2"
                        caps.contains("WEP", ignoreCase = true) -> "WEP"
                        caps.contains("WPA", ignoreCase = true) -> "WPA"
                        !caps.contains("WEP") && !caps.contains("WPA") && !caps.contains("PSK") && !caps.contains("EAP") -> "Open"
                        else -> "WPA2"
                    }
                    val channel = frequencyToChannel(scanResult.frequency)
                    WifiNetwork(ssid, bssid, rssi, encryption, channel)
                }

                val assessments = allNetworks.map { net ->
                    val assessment = ThreatEngine.assess(net, firewall.trustedNetworks)
                    if (assessment.level == ThreatLevel.DANGER) {
                        firewall.enforce(assessment)
                    }
                    assessment
                }.sortedByDescending { it.score }

                val jsonAssessments = assessments.joinToString(prefix = "[", postfix = "]") { a ->
                    """{"network":{"ssid":"${escapeJson(a.network.ssid)}","bssid":"${a.network.bssid}","rssi":${a.network.rssi},"encryption":"${a.network.encryption}","channel":${a.network.channel}},"score":${a.score},"level":"${a.level.name}","type":"${escapeJson(a.type)}","reason":"${escapeJson(a.reason)}"}"""
                }

                val trustedJson = firewall.trustedNetworks.joinToString(prefix = "[", postfix = "]") {
                    "\"${escapeJson(it)}\""
                }

                """{"assessments":$jsonAssessments,"mode":"live","trusted":$trustedJson}"""
            } catch (e: Exception) {
                e.printStackTrace()
                ""
            }
        }

        private fun frequencyToChannel(freq: Int): Int {
            return when {
                freq == 2484 -> 14
                freq in 2412..2472 -> (freq - 2412) / 5 + 1
                freq in 5170..5825 -> (freq - 5170) / 5 + 34
                freq in 5925..7125 -> (freq - 5925) / 5 + 1
                else -> 6
            }
        }

        private fun escapeJson(str: String): String {
            return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", " ")
                .replace("\r", "")
        }
    }

    override fun onBackPressed() {
        if (::webView.isInitialized && webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
