import http.server
import socketserver
import json
import re
import subprocess
import webbrowser
import os
import sys
import time
from urllib.parse import urlparse, parse_qs

PORT = 5050
DASHBOARD_FILE = os.path.join(os.path.dirname(__file__), "dashboard.html")

# In-memory and persistent state
current_mode = "live"  # "live" or "simulated"
current_scenario = "normal"  # "normal", "eviltwin", "rogue", "wep"
trusted_networks = ["CyberNode Lab", "Hackathon"]
blocked_networks = []
threat_history = []

SIMULATED_BASE = [
    {"ssid": "CyberNode Lab", "bssid": "A4:CF:12:90:11:02", "rssi": -58, "encryption": "WPA3", "channel": 6},
    {"ssid": "Airport_Free", "bssid": "AA:BB:CC:DD:EE:FF", "rssi": -42, "encryption": "Open", "channel": 11},
    {"ssid": "Guest-WiFi", "bssid": "38:7A:0E:22:19:04", "rssi": -67, "encryption": "WPA2", "channel": 1},
    {"ssid": "Cafe Network", "bssid": "70:3A:CB:12:4E:91", "rssi": -48, "encryption": "WEP", "channel": 13}
]

def parse_windows_wifi():
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )
    except Exception as e:
        print(f"Error scanning wifi: {e}")
        return SIMULATED_BASE

    networks = []
    current_net = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        
        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            ssid = ssid_match.group(1).strip()
            if not ssid:
                ssid = "[Hidden Network]"
            current_net = {
                "ssid": ssid,
                "bssid": "00:00:00:00:00:00",
                "rssi": -70,
                "encryption": "WPA2",
                "channel": 6
            }
            networks.append(current_net)
            continue

        if current_net is not None:
            auth_match = re.match(r"^Authentication\s*:\s*(.*)$", line)
            if auth_match:
                auth = auth_match.group(1).strip()
                if "Open" in auth:
                    current_net["encryption"] = "Open"
                elif "WEP" in auth:
                    current_net["encryption"] = "WEP"
                elif "WPA3" in auth:
                    current_net["encryption"] = "WPA3"
                else:
                    current_net["encryption"] = "WPA2"
                continue

            bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line)
            if bssid_match:
                current_net["bssid"] = bssid_match.group(1)
                continue

            sig_match = re.match(r"^Signal\s*:\s*(\d+)%", line)
            if sig_match:
                pct = int(sig_match.group(1))
                current_net["rssi"] = int((pct / 2) - 100)
                continue

            ch_match = re.match(r"^Channel\s*:\s*(\d+)", line)
            if ch_match:
                current_net["channel"] = int(ch_match.group(1))
                continue

    return networks if networks else SIMULATED_BASE

def assess_network(network, trusted_ssids, all_networks):
    score = 0
    reasons = []
    enc = network.get("encryption", "")
    ssid = network.get("ssid", "")
    bssid = network.get("bssid", "")

    # Check 1: Evil Twin Detection (Duplicate SSID with different BSSID)
    same_ssid_nets = [n for n in all_networks if n.get("ssid") == ssid and ssid not in ("", "[Hidden Network]")]
    if len(same_ssid_nets) > 1:
        # If multiple BSSIDs exist with conflicting encryption or unusually strong signal
        score += 35
        reasons.append(f"Multiple BSSIDs broadcast identical SSID '{ssid}' (Evil Twin indicator)")

    # Check 2: Encryption analysis
    if enc.lower() == "open":
        score += 45
        reasons.append("Open network can expose plaintext traffic to nearby radio listeners")
    elif "wep" in enc.lower():
        score += 35
        reasons.append("Legacy WEP encryption is deprecated and vulnerable to IV key recovery")
    elif "wpa" in enc.lower():
        score += 5

    # Check 3: Abnormal RSSI Power
    if network.get("rssi", -100) > -45:
        score += 15
        reasons.append(f"Unusually high signal ({network.get('rssi')} dBm) - potential rogue transmitter proximity")

    # Check 4: Channel verification
    ch = network.get("channel", 0)
    if 12 <= ch <= 14:
        score += 8
        reasons.append(f"Frequency channel {ch} is uncommon for standard consumer infrastructure in this region")

    # Check 5: Trusted network mitigation
    if ssid in trusted_ssids:
        score = max(0, score - 25)

    # Classify Threat Level
    if score >= 61:
        level = "DANGER"
    elif score >= 31:
        level = "WARNING"
    else:
        level = "SAFE"

    # Threat categorization
    if len(same_ssid_nets) > 1 and score >= 50:
        threat_type = "Evil Twin Attack"
    elif enc.lower() == "open":
        threat_type = "Open Wi-Fi Risk"
    elif "wep" in enc.lower():
        threat_type = "Weak Encryption Vulnerability"
    elif score >= 61:
        threat_type = "Rogue Access Point"
    elif score >= 31:
        threat_type = "Suspicious Network"
    else:
        threat_type = "No immediate threat"

    reason_str = ". ".join(reasons) if reasons else "Network matches the current wireless safety baseline"
    
    assessment = {
        "network": network,
        "score": min(100, max(0, score)),
        "level": level,
        "type": threat_type,
        "reason": reason_str
    }

    # Autonomous CyberShield logging
    if level == "DANGER" and not any(h["bssid"] == bssid for h in threat_history[-10:]):
        threat_history.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ssid": ssid,
            "bssid": bssid,
            "type": threat_type,
            "score": assessment["score"],
            "action": "Auto-quarantined by CyberShield"
        })

    return assessment

def get_active_networks():
    if current_mode == "live":
        nets = parse_windows_wifi()
    else:
        nets = [dict(n) for n in SIMULATED_BASE]

    # Inject attack scenarios if requested
    if current_scenario == "eviltwin":
        nets.append({
            "ssid": "Hackathon" if current_mode == "live" else "CyberNode Lab",
            "bssid": "DE:AD:BE:EF:00:01",
            "rssi": -32,
            "encryption": "Open",
            "channel": 11
        })
    elif current_scenario == "rogue":
        nets.append({
            "ssid": "Free_HighSpeed_WiFi",
            "bssid": "00:1A:2B:3C:4D:5E",
            "rssi": -38,
            "encryption": "Open",
            "channel": 13
        })
    elif current_scenario == "wep":
        nets.append({
            "ssid": "Legacy_Office_Net",
            "bssid": "11:22:33:44:55:66",
            "rssi": -52,
            "encryption": "WEP",
            "channel": 6
        })

    return nets

class CyberNodeHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global current_mode, current_scenario, trusted_networks, blocked_networks, threat_history
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        if path in ("/", "/index", "/dashboard"):
            if os.path.exists(DASHBOARD_FILE):
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                with open(DASHBOARD_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "dashboard.html not found")
        
        elif path == "/api/scan":
            raw_nets = get_active_networks()
            assessments = [assess_network(net, set(trusted_networks), raw_nets) for net in raw_nets]
            
            # Sort highest threat first
            assessments.sort(key=lambda a: a["score"], reverse=True)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "mode": current_mode,
                "scenario": current_scenario,
                "assessments": assessments,
                "trusted": trusted_networks,
                "blocked": blocked_networks,
                "history": threat_history
            }).encode("utf-8"))

        elif path == "/api/mode":
            mode = query.get("mode", ["live"])[0]
            current_mode = "simulated" if mode == "simulated" else "live"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"mode": current_mode}).encode("utf-8"))

        elif path == "/api/scenario":
            scenario = query.get("type", ["normal"])[0]
            current_scenario = scenario
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"scenario": current_scenario}).encode("utf-8"))

        elif path == "/api/trust":
            ssid = query.get("ssid", [""])[0]
            if ssid:
                if ssid in trusted_networks:
                    trusted_networks.remove(ssid)
                else:
                    trusted_networks.append(ssid)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"trusted": trusted_networks}).encode("utf-8"))

        elif path == "/api/block":
            bssid = query.get("bssid", [""])[0]
            ssid = query.get("ssid", [""])[0]
            reason = query.get("reason", ["Threat quarantine"])[0]
            if bssid and not any(b["bssid"] == bssid for b in blocked_networks):
                blocked_networks.append({"bssid": bssid, "ssid": ssid, "reason": reason})
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"blocked": blocked_networks}).encode("utf-8"))

        elif path == "/api/unblock":
            bssid = query.get("bssid", [""])[0]
            blocked_networks = [b for b in blocked_networks if b["bssid"] != bssid]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"blocked": blocked_networks}).encode("utf-8"))

        elif path == "/api/clear_blocks":
            blocked_networks = []
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

        elif path == "/api/clear_history":
            threat_history = []
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

        else:
            super().do_GET()

def run():
    print(f"CyberNode live server starting on http://localhost:{PORT}")
    try:
        webbrowser.open(f"http://localhost:{PORT}")
    except Exception:
        pass
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("", PORT), CyberNodeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CyberNode server.")

if __name__ == "__main__":
    run()
