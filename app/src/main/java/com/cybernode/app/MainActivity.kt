package com.cybernode.app

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private val trustedNetworks = setOf("CyberNode Lab")
    private val scanResults = listOf(
        WifiNetwork("CyberNode Lab", "A4:CF:12:90:11:02", -58, "WPA3", 6),
        WifiNetwork("Airport_Free", "AA:BB:CC:DD:EE:FF", -42, "Open", 11),
        WifiNetwork("Guest-WiFi", "38:7A:0E:22:19:04", -67, "WPA2", 1),
        WifiNetwork("Cafe Network", "70:3A:CB:12:4E:91", -48, "WEP", 13)
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        renderScan(scanResults.map { ThreatEngine.assess(it, trustedNetworks) })
    }

    private fun renderScan(assessments: List<ThreatAssessment>) {
        val list = findViewById<LinearLayout>(R.id.networkList)
        list.removeAllViews()
        val highest = assessments.maxByOrNull { it.score }
        findViewById<TextView>(R.id.riskValue).text = "RISK  ${highest?.score ?: 0} / 100"
        findViewById<ProgressBar>(R.id.riskMeter).progress = highest?.score ?: 0
        findViewById<TextView>(R.id.networkCount).text = "${assessments.size} networks"
        val status = findViewById<TextView>(R.id.statusValue)
        status.text = highest?.level?.label ?: "SAFE"
        status.setTextColor(colorFor(highest?.level ?: ThreatLevel.SAFE))
        assessments.forEach { assessment -> list.addView(networkRow(assessment)) }
    }

    private fun networkRow(assessment: ThreatAssessment): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 14, 16, 14)
            setBackgroundColor(Color.rgb(17, 35, 44))
            setOnClickListener { showDetails(assessment) }
        }
        val title = TextView(this).apply {
            text = "${assessment.network.ssid}   ${assessment.score}"
            textSize = 17f
            setTextColor(Color.rgb(242, 247, 245))
        }
        val details = TextView(this).apply {
            text = "${assessment.network.encryption}  •  ${assessment.network.rssi} dBm  •  CH ${assessment.network.channel}  •  ${assessment.level.label}"
            textSize = 13f
            setTextColor(colorFor(assessment.level))
            setPadding(0, 6, 0, 0)
        }
        row.addView(title)
        row.addView(details)
        val params = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, 8) }
        row.layoutParams = params
        return row
    }

    private fun showDetails(assessment: ThreatAssessment) {
        findViewById<LinearLayout>(R.id.detailPanel).visibility = View.VISIBLE
        findViewById<TextView>(R.id.detailTitle).text = "${assessment.network.ssid}  •  ${assessment.level.label}"
        findViewById<TextView>(R.id.detailBody).text = "BSSID ${assessment.network.bssid}\n${assessment.network.encryption}  •  ${assessment.network.rssi} dBm  •  Channel ${assessment.network.channel}\nAI score ${assessment.score}/100  •  ${assessment.type}\n${assessment.reason}"
    }

    private fun colorFor(level: ThreatLevel) = when (level) {
        ThreatLevel.SAFE -> Color.rgb(56, 211, 159)
        ThreatLevel.WARNING -> Color.rgb(244, 194, 73)
        ThreatLevel.DANGER -> Color.rgb(255, 103, 94)
    }
}
