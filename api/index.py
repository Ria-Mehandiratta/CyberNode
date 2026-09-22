from http.server import BaseHTTPRequestHandler
import json
import time
from urllib.parse import urlparse, parse_qs

SIMULATED_BASE = [
    {"ssid": "Hackathon", "bssid": "ac:4a:56:ce:f4:6f", "rssi": -49, "encryption": "WPA2", "channel": 52},
    {"ssid": "CyberNode", "bssid": "d4:e9:f4:b2:88:51", "rssi": -55, "encryption": "WPA2", "channel": 1},
    {"ssid": "HACKATHON", "bssid": "3e:7b:c8:a9:cc:3d", "rssi": -34, "encryption": "Open", "channel": 11},
    {"ssid": "CHITKARA", "bssid": "0a:7b:c8:aa:03:e1", "rssi": -62, "encryption": "WPA2", "channel": 6},
    {"ssid": "JioNet@Chitkara", "bssid": "00:11:74:ba:2f:e0", "rssi": -58, "encryption": "Open", "channel": 1},
    {"ssid": "realme P4 Pro 5G u2ds", "bssid": "b2:97:8c:4b:91:f6", "rssi": -68, "encryption": "WPA2", "channel": 44},
    {"ssid": "iQOO Z7 Pro 5G", "bssid": "f6:42:9d:7b:47:fa", "rssi": -72, "encryption": "WPA2", "channel": 149},
    {"ssid": "Airport_Free", "bssid": "aa:bb:cc:dd:ee:ff", "rssi": -42, "encryption": "Open", "channel": 11},
    {"ssid": "Cafe Network", "bssid": "70:3a:cb:12:4e:91", "rssi": -48, "encryption": "WEP", "channel": 13}
]

trusted_networks = ["Hackathon", "CyberNode", "CyberNode Lab"]
blocked_networks = []
threat_history = []
current_scenario = "eviltwin"

KNOWN_OUI = {
    "ac:4a:56": "Hewlett Packard Enterprise / Aruba",
    "d4:e9:f4": "Espressif Systems (ESP32)",
    "3e:7b:c8": "Standard Network Device (Rogue AP)",
    "0a:7b:c8": "Standard Network Device (Rogue AP)",
    "00:11:74": "Cisco Systems",
    "b2:97:8c": "Realme Mobile",
    "f6:42:9d": "Vivo / iQOO Mobile",
    "aa:bb:cc": "Unverified Hardware",
    "70:3a:cb": "Netgear Inc."
}

def get_vendor(mac):
    if not mac:
        return "Standard Network Device"
    prefix = mac.lower()[:8]
    return KNOWN_OUI.get(prefix, "Standard Network Device")

def assess_network(network, trusted_ssids, all_networks):
    score = 0
    reasons = []
    enc = network.get("encryption", "")
    ssid = (network.get("ssid") or "").strip()
    bssid = (network.get("bssid") or "").lower()
    ssid_lower = ssid.lower()
    vendor = get_vendor(bssid)

    is_randomized_mac = len(bssid) >= 2 and bssid[1].lower() in ('2', '6', 'a', 'e')
    if is_randomized_mac:
        score += 10
        reasons.append(f"Private/Randomized MAC address ({bssid[:8]}...) - client privacy / softAP device")

    same_ssid_nets = [n for n in all_networks if n.get("ssid", "").strip().lower() == ssid_lower and ssid_lower not in ("", "[hidden network]")]
    is_foreign_hardware = False
    is_evil_twin_clone = False
    is_official_victim = False

    if len(same_ssid_nets) > 1:
        bssid_prefix = bssid[:8].lower()
        known_ap_prefixes = [n.get("bssid", "")[:8].lower() for n in same_ssid_nets if n.get("bssid", "").lower() != bssid]
        is_foreign_hardware = any(p and p != bssid_prefix for p in known_ap_prefixes)

        if is_foreign_hardware:
            if is_randomized_mac or vendor == "Standard Network Device":
                score += 65
                is_evil_twin_clone = True
                reasons.append(f"CRITICAL Evil Twin Detected: Rogue transmitter mimicking SSID '{ssid}' with conflicting hardware MAC ({bssid})")
            else:
                is_official_victim = True
                reasons.append(f"Official AP Alert: An unauthorized rogue transmitter is currently impersonating this network ('{ssid}')")
        else:
            reasons.append(f"Multiple BSSIDs broadcast identical SSID '{ssid}' (BSSID multi-AP fleet)")

    if enc.lower() in ("open", "none") or "open" in enc.lower():
        score += 50
        reasons.append("Open unencrypted network exposes cleartext passwords and traffic to passive radio listeners")
    elif "wep" in enc.lower():
        score += 60
        reasons.append("Deprecated WEP encryption is vulnerable to instant RC4 keystream injection")
    elif "wpa3" in enc.lower():
        score = max(0, score - 15)
        reasons.append("Robust WPA3-SAE encryption provides enterprise-grade brute-force and eavesdropping protection")
    elif "wpa" in enc.lower() and "wpa2" not in enc.lower() and "wpa3" not in enc.lower():
        score += 30
        reasons.append("Legacy WPA1/TKIP protocol is vulnerable to keystream recovery attacks")

    hotspot_keywords = ["phone", "android", "iphone", "5g", "pro", "galaxy", "realme", "iqoo", "redmi", "vivo", "oppo", "oneplus", "hotspot"]
    if any(k in ssid_lower for k in hotspot_keywords):
        score += 10
        reasons.append("Personal mobile hotspot detected (unmanaged access point)")

    if network.get("rssi", -100) > -38:
        score += 15
        reasons.append(f"Abnormally intense signal ({network.get('rssi')} dBm) - rogue transmitter immediate proximity")

    is_trusted_ssid = any(t.lower() == ssid_lower for t in trusted_ssids)
    if is_trusted_ssid:
        if not is_evil_twin_clone:
            score = max(0, score - 25)
        else:
            score += 25
            reasons.append(f"HIGH SEVERITY: Rogue transmitter actively impersonating trusted network '{ssid}'")

    final_score = min(100, max(0, score))
    if final_score >= 60:
        level = "DANGER"
    elif final_score >= 30:
        level = "WARNING"
    else:
        level = "SAFE"

    if is_evil_twin_clone:
        threat_type = "Evil Twin Attack"
    elif is_official_victim:
        threat_type = "Official Network (Under Impersonation)"
    elif enc.lower() in ("open", "none") or "open" in enc.lower():
        threat_type = "Open Wi-Fi Risk"
    elif "wep" in enc.lower():
        threat_type = "Weak Encryption Vulnerability"
    elif is_randomized_mac and final_score >= 50:
        threat_type = "Rogue Access Point (SoftAP)"
    elif any(k in ssid_lower for k in hotspot_keywords) and final_score >= 30:
        threat_type = "Unmanaged Mobile Hotspot"
    elif final_score >= 60:
        threat_type = "Rogue Access Point"
    elif final_score >= 30:
        threat_type = "Suspicious Network"
    else:
        threat_type = "Secure Baseline"

    return {
        "network": network,
        "score": final_score,
        "level": level,
        "type": threat_type,
        "reason": ". ".join(reasons) if reasons else "Network matches wireless security baseline standards"
    }

class handler(BaseHTTPRequestHandler):
    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.endswith("/api/scan") or path == "/api/scan":
            raw_nets = list(SIMULATED_BASE)
            assessments = [assess_network(n, set(trusted_networks), raw_nets) for n in raw_nets]
            assessments.sort(key=lambda a: a["score"], reverse=True)

            resp = {
                "source": "CyberNode Cloud Threat Sentinel",
                "mode": "cloud_live",
                "scenario": current_scenario,
                "trusted": trusted_networks,
                "blocked": blocked_networks,
                "history": threat_history,
                "total_networks": len(assessments),
                "danger_count": sum(1 for a in assessments if a["level"] == "DANGER"),
                "warning_count": sum(1 for a in assessments if a["level"] == "WARNING"),
                "safe_count": sum(1 for a in assessments if a["level"] == "SAFE"),
                "connected_assessment": assessments[0] if assessments else None,
                "assessments": assessments
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif path.endswith("/api/network_scan") or path == "/api/network_scan":
            raw_nets = list(SIMULATED_BASE)
            assessments = [assess_network(n, set(trusted_networks), raw_nets) for n in raw_nets]
            devices = []
            for ass in assessments:
                net = ass["network"]
                ssid = net["ssid"]
                bssid = net["bssid"]
                ch = net["channel"]
                rssi = net["rssi"]
                enc = net["encryption"]
                vendor = get_vendor(bssid)
                is_conn = (ssid == "Hackathon")
                pct = max(5, min(100, int((rssi + 100) * 2)))
                band = "5 GHz" if ch > 14 else "2.4 GHz"

                devices.append({
                    "ip": "10.20.0.174 (LAN)" if is_conn else f"Over-The-Air (CH {ch})",
                    "mac": bssid,
                    "bssid": bssid,
                    "ssid": ssid,
                    "hostname": ssid,
                    "device_name": ssid,
                    "node_role": f"Wireless AP • {vendor}",
                    "vendor": vendor,
                    "device_type": "Connected Wi-Fi Gateway" if is_conn else "Wireless Access Point",
                    "icon": "router" if not any(k in ssid.lower() for k in ["phone", "5g", "pro"]) else "phone",
                    "is_local": False,
                    "is_gateway": is_conn,
                    "is_connected": is_conn,
                    "latency_ms": 2 if is_conn else max(5, abs(rssi) // 2),
                    "open_ports": [{"port": 80, "service": "HTTP Router Admin", "risk": "MEDIUM"}, {"port": 53, "service": "DNS", "risk": "LOW"}] if is_conn else [],
                    "risk_score": ass["score"],
                    "risk_level": ass["level"],
                    "threat_type": ass["type"],
                    "threats": [ass["reason"]],
                    "status": "ONLINE",
                    "wifi": {
                        "ssid": ssid,
                        "bssid": bssid,
                        "band": band,
                        "channel": ch,
                        "radio_type": "802.11ac" if ch > 14 else "802.11n",
                        "auth": enc,
                        "cipher": "CCMP",
                        "signal": f"{pct}%",
                        "rssi": rssi,
                        "rx_rate": "400 Mbps",
                        "tx_rate": "400 Mbps",
                        "adapter": "CyberNode Cloud Guard"
                    }
                })

            resp = {
                "context": {
                    "interface": "Cloud Wi-Fi Sentinel",
                    "local_ip": "10.20.0.174",
                    "gateway_ip": "10.20.0.1",
                    "subnet": "10.20.0.0/24",
                    "wifi": {"ssid": "Hackathon", "band": "5 GHz", "channel": 52, "auth": "WPA2-Personal"}
                },
                "devices": devices,
                "total_hosts": len(devices),
                "online_hosts": len(devices),
                "vulnerable_count": sum(1 for d in devices if d["risk_level"] != "SAFE"),
                "scan_time": time.strftime("%H:%M:%S")
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif "/api/trust" in path:
            ssid = query.get("ssid", [""])[0]
            if ssid and ssid not in trusted_networks:
                trusted_networks.append(ssid)
            self.send_response(200)
            self.send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "trusted": trusted_networks}).encode("utf-8"))

        elif "/api/disconnect" in path:
            self.send_response(200)
            self.send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "disconnected", "message": "Severed connection safely."}).encode("utf-8"))

        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "service": "CyberNode Vercel API"}).encode("utf-8"))
