package com.cybernode.app

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private lateinit var firewall: CyberShieldFirewall

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        firewall = CyberShieldFirewall(this)

        webView = WebView(this).apply {
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = true
                allowContentAccess = true
                useWideViewPort = true
                loadWithOverviewMode = true
                cacheMode = WebSettings.LOAD_DEFAULT
            }
            webViewClient = WebViewClient()
            webChromeClient = WebChromeClient()

            addJavascriptInterface(FirewallBridge(firewall), "AndroidFirewall")
            loadUrl("file:///android_asset/index.html")
        }

        setContentView(webView)
    }

    inner class FirewallBridge(private val firewall: CyberShieldFirewall) {
        @JavascriptInterface
        fun enforce(ssid: String, bssid: String, score: Int, encryption: String, channel: Int): String {
            val net = WifiNetwork(ssid, bssid, -50, encryption, channel)
            val assessment = ThreatEngine.assess(net, firewall.trustedNetworks)
            val action = firewall.enforce(assessment)
            return "{\"action\":\"${action.actionTaken}\",\"led\":\"${action.ledColor}\",\"vibrate\":${action.shouldVibrate}}"
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
