package com.cybernode.app

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.widget.Toast

// Data class to capture the result of the firewall evaluation
data class FirewallAction(
    val actionTaken: String,
    val ledColor: String,
    val shouldVibrate: Boolean
)

class CyberShieldFirewall(private val context: Context) {
    val trustedNetworks = mutableSetOf("CyberNode Lab")

    /**
     * CyberShield Firewall logic implementation using if-else statements
     */
    fun enforce(assessment: ThreatAssessment): FirewallAction {
        val network = assessment.network
        val score = assessment.score

        if (network.ssid in trustedNetworks) {
            // Bypass security restrictions for explicitly trusted networks
            return FirewallAction("Allowed (Trusted Network)", "Green", false)
        } 
        else if (score <= 30) {
            // SAFE LEVEL (Score 0-30): Normal connection allowed, LED Green
            return FirewallAction("Allowed Connection", "Green", false)
        } 
        else if (score in 31..60) {
            // WARNING LEVEL (Score 31-60): Trigger Yellow LED and show system warning
            Toast.makeText(
                context,
                "WARNING: Suspicious network nearby (${network.ssid})",
                Toast.LENGTH_SHORT
            ).show()

            return FirewallAction("Warning Notification Displayed", "Yellow", false)
        } 
        else if (score >= 61) {
            // DANGER LEVEL (Score 61-100): Disconnect, Red LED, and trigger Vibration
            triggerVibration()
            disconnectFromWifi()
            
            Toast.makeText(
                context,
                "CRITICAL: CyberShield blocked malicious network (${network.ssid})",
                Toast.LENGTH_LONG
            ).show()

            return FirewallAction("Disconnected & Blocked Auto-Reconnect", "Red", true)
        } 
        else {
            return FirewallAction("No Action", "Off", false)
        }
    }

    private fun disconnectFromWifi() {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            wifiManager?.disconnect()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun triggerVibration() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vibratorManager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                vibratorManager?.defaultVibrator?.vibrate(
                    VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE)
                )
            } else {
                @Suppress("DEPRECATION")
                val vibrator = context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator?.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE))
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(500)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
