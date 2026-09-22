package com.cybernode.app

data class WifiNetwork(
    val ssid: String,
    val bssid: String,
    val rssi: Int,
    val encryption: String,
    val channel: Int
)

enum class ThreatLevel(val label: String) { SAFE("SAFE"), WARNING("WARNING"), DANGER("DANGER") }

data class ThreatAssessment(
    val network: WifiNetwork,
    val score: Int,
    val level: ThreatLevel,
    val type: String,
    val reason: String
)

object ThreatEngine {
    fun assess(network: WifiNetwork, trustedSsids: Set<String> = emptySet()): ThreatAssessment {
        var score = 0
        val reasons = mutableListOf<String>()
        // Randomized MAC check (informative, low risk alone)
        val bssid = network.bssid.lowercase()
        val isRandomizedMac = bssid.length >= 2 && bssid[1] in listOf('2', '6', 'a', 'e')
        if (isRandomizedMac) {
            score += 10
            reasons += "Private/Randomized MAC address (${bssid.take(8)}...) - softAP device"
        }

        if (network.encryption.equals("Open", ignoreCase = true)) {
            score += 45
            reasons += "Open network can expose traffic to nearby listeners"
        } else if (network.encryption.contains("WEP", ignoreCase = true)) {
            score += 35
            reasons += "Legacy WEP encryption is weak"
        } else if (network.encryption.contains("WPA3", ignoreCase = true)) {
            score = (score - 15).coerceAtLeast(0)
            reasons += "Robust WPA3-SAE encryption provides enterprise-grade protection"
        } else if (network.encryption.contains("WPA", ignoreCase = true) &&
            !network.encryption.contains("WPA2", ignoreCase = true) &&
            !network.encryption.contains("WPA3", ignoreCase = true)
        ) {
            score += 20
            reasons += "Legacy WPA1 protocol is weak"
        }

        val hotspotKeywords = listOf("phone", "android", "iphone", "5g", "pro", "galaxy", "realme", "iqoo", "redmi", "hotspot")
        if (hotspotKeywords.any { network.ssid.contains(it, ignoreCase = true) }) {
            score += 10
            reasons += "Personal mobile hotspot detected"
        }

        if (network.rssi > -38) {
            score += 15
            reasons += "Unusually strong signal for an unknown access point"
        }
        if (network.channel in 12..14) {
            score += 8
            reasons += "Channel is uncommon for this region"
        }
        if (network.ssid in trustedSsids) score = (score - 25).coerceAtLeast(0)
        val level = when {
            score >= 61 -> ThreatLevel.DANGER
            score >= 31 -> ThreatLevel.WARNING
            else -> ThreatLevel.SAFE
        }
        val type = when {
            network.encryption.equals("Open", ignoreCase = true) -> "Open Wi-Fi Risk"
            network.encryption.contains("WEP", ignoreCase = true) -> "Weak Encryption Vulnerability"
            score >= 61 -> "Rogue Access Point"
            score >= 31 -> "Suspicious Network"
            else -> "Secure Baseline"
        }
        return ThreatAssessment(network, score.coerceIn(0, 100), level, type,
            reasons.joinToString(". ").ifBlank { "Network matches the current safety baseline" })
    }
}
