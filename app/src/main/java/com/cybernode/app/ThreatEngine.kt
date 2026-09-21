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
        if (network.encryption.equals("Open", ignoreCase = true)) {
            score += 45
            reasons += "Open network can expose traffic to nearby listeners"
        } else if (network.encryption.contains("WEP", ignoreCase = true)) {
            score += 35
            reasons += "Legacy WEP encryption is weak"
        } else if (network.encryption.contains("WPA", ignoreCase = true)) {
            score += 5
        }
        if (network.rssi > -50) {
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
            score >= 61 -> "Rogue Access Point"
            score >= 31 -> "Suspicious Network"
            else -> "No immediate threat"
        }
        return ThreatAssessment(network, score.coerceIn(0, 100), level, type,
            reasons.joinToString(". ").ifBlank { "Network matches the current safety baseline" })
    }
}
