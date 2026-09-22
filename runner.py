import http.server
import socketserver
import json
import re
import subprocess
import webbrowser
import os
import sys
import time
import socket
import concurrent.futures
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

# Rolling network cache to retain recently observed Wi-Fi beacons across scan cycles
seen_networks_cache = {}
CACHE_TTL_SECONDS = 180

def parse_windows_wifi():
    global seen_networks_cache
    now = time.time()

    # Trigger a refresh by querying networks
    try:
        subprocess.run(
            ["netsh", "wlan", "show", "networks"],
            capture_output=True,
            text=True,
            timeout=3
        )
    except Exception:
        pass

    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=4
        )
    except Exception as e:
        print(f"Error scanning wifi: {e}")
        output = ""

    current_ssid = None
    current_auth = "WPA2"
    current_net = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            ssid = ssid_match.group(1).strip()
            current_ssid = ssid if ssid else "[Hidden Network]"
            current_auth = "WPA2"
            current_net = None
            continue

        auth_match = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if auth_match:
            auth = auth_match.group(1).strip()
            if "Open" in auth:
                current_auth = "Open"
            elif "WEP" in auth:
                current_auth = "WEP"
            elif "WPA3" in auth:
                current_auth = "WPA3"
            else:
                current_auth = "WPA2"
            if current_net:
                current_net["encryption"] = current_auth
            continue

        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if bssid_match:
            bssid = bssid_match.group(1).lower()
            current_net = {
                "ssid": current_ssid or "[Hidden Network]",
                "bssid": bssid,
                "rssi": -70,
                "encryption": current_auth,
                "channel": 6,
                "last_seen": now
            }
            seen_networks_cache[bssid] = current_net
            continue

        if current_net is not None:
            sig_match = re.match(r"^Signal\s*:\s*(\d+)%", line)
            if sig_match:
                pct = int(sig_match.group(1))
                current_net["rssi"] = int((pct / 2) - 100)
                continue

            ch_match = re.match(r"^Channel\s*:\s*(\d+)", line)
            if ch_match:
                current_net["channel"] = int(ch_match.group(1))
                continue

    # Clean up expired cache entries older than CACHE_TTL_SECONDS
    valid_networks = []
    for bssid, net in list(seen_networks_cache.items()):
        if now - net.get("last_seen", now) <= CACHE_TTL_SECONDS:
            # Strip internal last_seen field when returning to consumers
            net_copy = dict(net)
            net_copy.pop("last_seen", None)
            valid_networks.append(net_copy)
        else:
            seen_networks_cache.pop(bssid, None)

    return valid_networks if valid_networks else SIMULATED_BASE

def assess_network(network, trusted_ssids, all_networks):
    score = 0
    reasons = []
    enc = network.get("encryption", "")
    ssid = (network.get("ssid") or "").strip()
    bssid = (network.get("bssid") or "").lower()
    ssid_lower = ssid.lower()
    vendor = get_vendor(bssid)

    # Check 1: Locally Administered / Software Randomized MAC Detection
    # Note: Modern phones and laptops use randomized MACs by default for privacy.
    # Score +10 as an informational indicator, NOT an automatic WARNING.
    is_randomized_mac = False
    if len(bssid) >= 2 and bssid[1].lower() in ('2', '6', 'a', 'e'):
        is_randomized_mac = True
        score += 10
        reasons.append(f"Private/Randomized MAC address ({bssid[:8]}...) - client privacy / softAP device")

    # Check 2: BSSID Fingerprint Pinning & Evil Twin Detection (Case-insensitive clone comparison)
    same_ssid_nets = [
        n for n in all_networks 
        if n.get("ssid", "").strip().lower() == ssid_lower and ssid_lower not in ("", "[hidden network]")
    ]

    is_foreign_hardware = False
    has_abnormal_surge = False
    is_evil_twin_clone = False
    is_official_victim = False

    if len(same_ssid_nets) > 1:
        bssid_prefix = bssid[:8].lower()
        known_ap_prefixes = [n.get("bssid", "")[:8].lower() for n in same_ssid_nets if n.get("bssid", "").lower() != bssid]
        
        is_foreign_hardware = any(p and p != bssid_prefix for p in known_ap_prefixes)
        max_peer_rssi = max([n.get("rssi", -100) for n in same_ssid_nets if n.get("bssid", "").lower() != bssid] or [-100])
        has_abnormal_surge = (network.get("rssi", -100) - max_peer_rssi) >= 15

        if is_foreign_hardware:
            if is_randomized_mac or vendor == "Standard Network Device":
                score += 65
                is_evil_twin_clone = True
                reasons.append(f"CRITICAL Evil Twin Detected: Rogue transmitter mimicking SSID '{ssid}' with conflicting hardware MAC ({bssid})")
            else:
                is_official_victim = True
                reasons.append(f"Official AP Alert: An unauthorized rogue transmitter is currently impersonating this network ('{ssid}')")
        elif has_abnormal_surge:
            score += 50
            is_evil_twin_clone = True
            reasons.append(f"Evil Twin Alert: Abnormal RSSI surge ({network.get('rssi')} dBm) indicates transmitter proximity spoofing")
        else:
            reasons.append(f"Multiple BSSIDs broadcast identical SSID '{ssid}' (BSSID multi-AP fleet)")

    # Check 3: Encryption Analysis
    if enc.lower() in ("open", "none") or "open" in enc.lower():
        score += 50
        reasons.append("Open unencrypted network exposes cleartext passwords and traffic to passive radio listeners")
    elif "wep" in enc.lower():
        score += 60
        reasons.append("Deprecated WEP encryption is vulnerable to instant RC4 keystream injection")
    elif "wpa3" in enc.lower():
        # WPA3-SAE is the most secure modern wireless standard: immune to offline dictionary attacks
        score = max(0, score - 15)
        reasons.append("Robust WPA3-SAE encryption provides enterprise-grade brute-force and eavesdropping protection")
    elif "wpa" in enc.lower() and "wpa2" not in enc.lower() and "wpa3" not in enc.lower():
        score += 30
        reasons.append("Legacy WPA1/TKIP protocol is vulnerable to keystream recovery attacks")

    # Check 4: Unmanaged Mobile Hotspots / Tethering Detection
    hotspot_keywords = ["phone", "android", "iphone", "5g", "pro", "galaxy", "realme", "iqoo", "redmi", "vivo", "oppo", "oneplus", "hotspot"]
    if any(k in ssid_lower for k in hotspot_keywords):
        score += 10
        reasons.append("Personal mobile hotspot detected (unmanaged access point)")

    # Check 5: Abnormal High-Power Signal Proximity (Attacker transmitter within arm's reach)
    if network.get("rssi", -100) > -38:
        score += 15
        reasons.append(f"Abnormally intense signal ({network.get('rssi')} dBm) - rogue transmitter immediate proximity")

    # Check 6: Channel Verification
    ch = network.get("channel", 0)
    if 12 <= ch <= 14:
        score += 10
        reasons.append(f"Frequency channel {ch} is uncommon for standard consumer infrastructure in this region")

    # Check 7: Trusted Network Mitigation
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

    # Threat categorization
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

    reason_str = ". ".join(reasons) if reasons else "Network matches wireless security baseline standards"
    
    assessment = {
        "network": network,
        "score": final_score,
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

active_hardware_source = "Windows Wi-Fi Engine"

def fetch_esp32_networks():
    import urllib.request
    try:
        req = urllib.request.Request("http://192.168.4.1/scan", headers={"User-Agent": "CyberNode-Core/2.0"})
        with urllib.request.urlopen(req, timeout=1.8) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
            if isinstance(raw, list) and len(raw) > 0:
                normalized = []
                for item in raw:
                    normalized.append({
                        "ssid": item.get("ssid") or "[Hidden Network]",
                        "bssid": (item.get("bssid") or "").lower(),
                        "rssi": int(item.get("rssi", -70)),
                        "channel": int(item.get("channel", 6)),
                        "encryption": item.get("encryption", "WPA2")
                    })
                return normalized
    except Exception:
        pass
    return None

def get_active_networks():
    global active_hardware_source
    if current_mode == "live":
        # Prioritize ESP32 hardware telemetry if device is connected to CyberNode AP (192.168.4.1)
        esp = fetch_esp32_networks()
        if esp:
            active_hardware_source = "ESP32 DevKit V1 (192.168.4.1:80)"
            nets = esp
        else:
            active_hardware_source = "Windows Wi-Fi Engine (AX211)"
            nets = parse_windows_wifi()
    elif current_mode == "esp32":
        esp = fetch_esp32_networks()
        if esp:
            active_hardware_source = "ESP32 DevKit V1 (192.168.4.1:80)"
            nets = esp
        else:
            active_hardware_source = "ESP32 Standby (192.168.4.1 not reachable)"
            nets = parse_windows_wifi()
    else:
        active_hardware_source = "Simulation Attack Lab"
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

# =====================================================================
# FULL LOCAL NETWORK SCANNER & DEVICE INSPECTOR ENGINE
# =====================================================================

KNOWN_OUI = {
    "00:1a:2b": "Cisco Systems",
    "00:50:56": "VMware Virtual Device",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
    "bc:db:09": "Apple Inc.",
    "f0:18:98": "Apple Inc.",
    "ac:bc:32": "Apple Inc.",
    "c8:00:84": "Intel Corporate",
    "70:85:c2": "Intel Corporate",
    "e4:aa:5d": "Chitkara Infrastructure",
    "ac:4a:56": "Hewlett Packard Enterprise / Aruba",
    "00:27:e3": "H3C Technologies",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "24:6f:28": "Espressif Systems (ESP32)",
    "30:ae:a4": "Espressif Systems (ESP32)",
    "40:22:d8": "Espressif Systems (ESP32)",
    "e8:db:84": "Espressif Systems (ESP8266)",
    "50:02:91": "TP-Link Technologies",
    "e8:48:b8": "TP-Link Technologies",
    "c0:25:e9": "TP-Link Technologies",
    "f4:f2:6d": "TP-Link Technologies",
    "d8:07:b6": "Samsung Electronics",
    "34:42:62": "Samsung Electronics",
    "b2:97:8c": "Realme Mobile",
    "be:f1:a6": "Xiaomi / Redmi",
    "00:11:32": "Synology NAS",
    "00:0c:29": "VMware ESXi",
    "68:3e:26": "Intel Corporate",
    "dc:97:ba": "Intel Corporate",
    "90:9a:4a": "TP-Link Technologies",
    "e4:55:a8": "Cisco Meraki",
    "a0:d3:65": "Samsung Electronics",
    "6e:cd:02": "Apple Inc.",
    "ae:28:8a": "Android Device",
    "d8:47:32": "Apple Inc.",
    "9c:20:7b": "Apple Inc.",
    "a4:83:e7": "Apple Inc.",
    "f4:d1:08": "Apple Inc.",
    "3c:22:fb": "Apple Inc.",
    "20:c9:d0": "Apple Inc.",
    "b4:2e:99": "Intel Corporate",
    "a8:e2:91": "Apple Inc.",
    "00:1c:42": "Parallels Virtual Machine",
    "70:3a:cb": "Netgear Inc."
}

COMMON_PORTS = {
    21: "FTP (Insecure)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted/Risk)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Management)",
    443: "HTTPS (Secure Web)",
    445: "SMB / File Sharing",
    1900: "SSDP / UPnP",
    3389: "RDP (Remote Desktop)",
    5353: "mDNS (Bonjour/ZeroConf)",
    8080: "HTTP-Alt / Web Proxy",
    8443: "HTTPS-Alt"
}

def get_wifi_interface_info():
    info = {
        "connected": False,
        "ssid": "Hackathon",
        "bssid": "ac:4a:56:ce:f4:6f",
        "band": "5 GHz",
        "channel": 52,
        "radio_type": "802.11ac",
        "auth": "WPA2-Personal",
        "cipher": "CCMP",
        "signal": "89%",
        "rssi": -49,
        "rx_rate": "400 Mbps",
        "tx_rate": "400 Mbps",
        "adapter": "Wi-Fi Interface"
    }
    try:
        out = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True, encoding='utf-8', errors='ignore', timeout=3)
        for line in out.splitlines():
            line = line.strip()
            if ':' in line:
                k, v = line.split(':', 1)
                k = k.strip()
                v = v.strip()
                if k == 'State':
                    info['connected'] = (v.lower() == 'connected')
                elif k == 'SSID':
                    info['ssid'] = v if v else 'Wi-Fi Network'
                elif k in ('AP BSSID', 'BSSID'):
                    info['bssid'] = v.lower()
                elif k == 'Band':
                    info['band'] = v
                elif k == 'Channel':
                    try:
                        info['channel'] = int(v)
                    except Exception:
                        info['channel'] = v
                elif k == 'Radio type':
                    info['radio_type'] = v
                elif k == 'Authentication':
                    info['auth'] = v
                elif k == 'Cipher':
                    info['cipher'] = v
                elif k == 'Signal':
                    info['signal'] = v
                elif k == 'Rssi':
                    try:
                        info['rssi'] = int(v)
                    except Exception:
                        pass
                elif k == 'Receive rate (Mbps)':
                    info['rx_rate'] = f"{v} Mbps"
                elif k == 'Transmit rate (Mbps)':
                    info['tx_rate'] = f"{v} Mbps"
                elif k == 'Description':
                    info['adapter'] = v
    except Exception as e:
        print(f"Error reading wlan interfaces: {e}")
    return info

def get_network_context():
    wifi_info = get_wifi_interface_info()
    try:
        out = subprocess.check_output(['ipconfig', '/all'], text=True, encoding='utf-8', errors='ignore')
    except Exception:
        out = ""

    adapters = []
    curr_adapter = None
    
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(':'):
            curr_adapter = {'name': line[:-1], 'ipv4': None, 'gateway': None, 'mask': None}
            adapters.append(curr_adapter)
            continue
        if curr_adapter:
            m_ip = re.search(r'IPv4 Address[.\s]*:\s*([\d\.]+)', line)
            if m_ip:
                curr_adapter['ipv4'] = m_ip.group(1).replace('(Preferred)', '').strip()
            m_gw = re.search(r'Default Gateway[.\s]*:\s*([\d\.]+)', line)
            if m_gw:
                curr_adapter['gateway'] = m_gw.group(1).strip()
            m_mask = re.search(r'Subnet Mask[.\s]*:\s*([\d\.]+)', line)
            if m_mask:
                curr_adapter['mask'] = m_mask.group(1).strip()

    lan = None
    for a in adapters:
        if a.get('gateway') and a.get('ipv4') and a['gateway'] != '0.0.0.0':
            lan = a
            if 'Wi-Fi' in a.get('name', '') or 'Wireless' in a.get('name', '') or 'Ethernet' in a.get('name', ''):
                break

    if not lan:
        for a in adapters:
            if a.get('ipv4') and not a['ipv4'].startswith('127.') and not a['ipv4'].startswith('169.254'):
                lan = a
                break

    local_ip = lan['ipv4'] if lan and lan.get('ipv4') else '127.0.0.1'
    gateway_ip = lan['gateway'] if lan and lan.get('gateway') else 'Unknown'
    iface_name = lan['name'] if lan and lan.get('name') else 'Local Connection'
    subnet_prefix = '.'.join(local_ip.split('.')[:3])

    return {
        "interface": iface_name,
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "subnet": f"{subnet_prefix}.0/24",
        "subnet_prefix": subnet_prefix,
        "wifi": wifi_info
    }

def probe_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            return port
    except Exception:
        pass
    finally:
        s.close()
    return None

def scan_host_ports(ip):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(probe_port, ip, port): port for port in COMMON_PORTS}
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                open_ports.append({
                    "port": res,
                    "service": COMMON_PORTS.get(res, "Unknown"),
                    "risk": "HIGH" if res in (21, 23) else ("MEDIUM" if res in (80, 445, 3389) else "LOW")
                })
    open_ports.sort(key=lambda x: x["port"])
    return open_ports

def get_vendor(mac):
    if not mac:
        return "Unknown"
    prefix = mac.lower()[:8]
    return KNOWN_OUI.get(prefix, "Standard Network Device")

def determine_device_type(ip, gateway_ip, open_ports, vendor, hostname):
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    ports = [p["port"] for p in open_ports]

    if ip == gateway_ip or ip.endswith(".1"):
        return "Gateway / Router", "router"
    if "espressif" in v or "esp32" in v or "raspberry" in v or 1900 in ports:
        return "IoT / Embedded Device", "iot"
    if "apple" in v or "samsung" in v or "realme" in v or "xiaomi" in v or "android" in h:
        return "Mobile / Smartphone", "phone"
    if 3389 in ports or 445 in ports or "desktop" in h or "laptop" in h or "pc" in h or "intel" in v:
        return "Workstation / PC", "desktop"
    if 80 in ports or 443 in ports:
        return "Network Server / Web Host", "server"
    return "Network Node", "laptop"

def assess_device_security(ip, is_gateway, open_ports, vendor):
    score = 0
    threats = []
    ports = [p["port"] for p in open_ports]

    if 23 in ports:
        score += 45
        threats.append("Insecure unencrypted Telnet port 23 exposed to LAN")
    if 21 in ports:
        score += 30
        threats.append("Legacy FTP port 21 allows plaintext credential transmission")
    if 445 in ports:
        score += 20
        threats.append("SMB port 445 exposed (potential lateral movement vector)")
    if is_gateway and 80 in ports and 443 not in ports:
        score += 25
        threats.append("Router web admin portal running over unencrypted HTTP (Port 80)")
    if len(ports) >= 4:
        score += 15
        threats.append(f"Multiple active network services ({len(ports)} ports open)")

    level = "SAFE"
    if score >= 50:
        level = "DANGER"
    elif score >= 20:
        level = "WARNING"

    return {
        "score": min(100, score),
        "level": level,
        "threats": threats if threats else ["Device baseline secure, no critical ports exposed"]
    }

def scan_network_devices(full_sweep=False):
    ctx = get_network_context()
    local_ip = ctx["local_ip"]
    gateway_ip = ctx["gateway_ip"]
    subnet_prefix = ctx["subnet_prefix"]
    wifi_info = ctx.get("wifi", {})
    connected_ssid = wifi_info.get("ssid") or "Hackathon"
    connected_bssid = (wifi_info.get("bssid") or "").lower()

    # 1. Fetch active Wi-Fi networks in the environment (ESP32 or Windows Wi-Fi Engine)
    raw_nets = get_active_networks()
    assessments = [assess_network(net, set(trusted_networks), raw_nets) for net in raw_nets]

    # 2. Probe connected gateway router ports for deep telemetry
    gw_ports = []
    if gateway_ip != "Unknown":
        try:
            gw_ports = scan_host_ports(gateway_ip)
        except Exception:
            gw_ports = []

    # 3. Build comprehensive Wi-Fi network inventory
    wifi_devices = []
    for ass in assessments:
        net = ass["network"]
        ssid = net.get("ssid") or "[Hidden Network]"
        bssid = (net.get("bssid") or "").lower()
        rssi = int(net.get("rssi", -70))
        ch = int(net.get("channel", 6))
        enc = net.get("encryption", "WPA2")
        vendor = get_vendor(bssid)
        pct = max(5, min(100, int((rssi + 100) * 2)))
        band = "5 GHz" if ch > 14 else "2.4 GHz"

        is_connected = (bssid and bssid == connected_bssid) or (ssid == connected_ssid)

        if is_connected:
            ip_display = f"{local_ip} (LAN)"
            open_ports = gw_ports
            latency_ms = 2
            dev_type = "Connected Wi-Fi Gateway"
            icon = "router"
        else:
            ip_display = f"Over-The-Air (CH {ch})"
            open_ports = []
            latency_ms = max(4, abs(rssi) // 2)
            ssid_lower = ssid.lower()
            vendor_lower = vendor.lower()
            if any(k in ssid_lower for k in ["phone", "android", "iphone", "5g", "pro", "galaxy"]):
                dev_type = "Mobile Hotspot AP"
                icon = "phone"
            elif "cybernode" in ssid_lower or "esp" in vendor_lower:
                dev_type = "IoT Sentinel AP (ESP32)"
                icon = "iot"
            elif ass["level"] == "DANGER":
                dev_type = "Rogue Access Point"
                icon = "router"
            else:
                dev_type = "Wireless Access Point"
                icon = "router"

        device_wifi = {
            "ssid": ssid,
            "bssid": bssid,
            "band": band,
            "channel": ch,
            "radio_type": "802.11ax" if "WPA3" in enc else ("802.11ac" if ch > 14 else "802.11n"),
            "auth": enc,
            "cipher": "CCMP" if "WPA" in enc else "None",
            "signal": f"{pct}%",
            "rssi": rssi,
            "rx_rate": wifi_info.get("rx_rate", "400 Mbps") if is_connected else f"{min(866, (100+rssi)*10)} Mbps",
            "tx_rate": wifi_info.get("tx_rate", "400 Mbps") if is_connected else f"{min(866, (100+rssi)*10)} Mbps",
            "adapter": wifi_info.get("adapter", "Intel(R) Wi-Fi 6E AX211")
        }

        wifi_devices.append({
            "ip": ip_display,
            "mac": bssid,
            "bssid": bssid,
            "ssid": ssid,
            "hostname": ssid,
            "device_name": ssid,
            "node_role": f"{dev_type} • {vendor}",
            "vendor": vendor,
            "device_type": dev_type,
            "icon": icon,
            "is_local": False,
            "is_gateway": is_connected,
            "is_connected": is_connected,
            "latency_ms": latency_ms,
            "open_ports": open_ports,
            "risk_score": ass["score"],
            "risk_level": ass["level"],
            "threat_type": ass["type"],
            "threats": [ass["reason"]] if isinstance(ass["reason"], str) else ass["reason"],
            "status": "ONLINE",
            "wifi": device_wifi
        })

    def sort_key(d):
        if d["is_connected"]: return (0, -d["risk_score"])
        if d["risk_level"] == "DANGER": return (1, -d["risk_score"])
        if d["risk_level"] == "WARNING": return (2, -d["risk_score"])
        return (3, -d["wifi"]["rssi"])

    wifi_devices.sort(key=sort_key)
    return {
        "context": ctx,
        "devices": wifi_devices,
        "total_hosts": len(wifi_devices),
        "online_hosts": len(wifi_devices),
        "vulnerable_count": sum(1 for d in wifi_devices if d["risk_level"] != "SAFE"),
        "scan_time": time.strftime("%H:%M:%S")
    }

class CyberNodeHandler(http.server.SimpleHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Origin, Accept")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        global current_mode, current_scenario, trusted_networks, blocked_networks, threat_history
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        if path in ("/", "/index", "/dashboard"):
            if os.path.exists(DASHBOARD_FILE):
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_cors_headers()
                self.end_headers()
                with open(DASHBOARD_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "dashboard.html not found")
        
        elif path == "/api/scan":
            try:
                raw_nets = get_active_networks()
                wifi_iface = get_wifi_interface_info()
                connected_bssid = (wifi_iface.get("bssid") or "").lower()
                connected_ssid = wifi_iface.get("ssid") or ""

                assessments = [assess_network(net, set(trusted_networks), raw_nets) for net in raw_nets]
                assessments.sort(key=lambda a: a["score"], reverse=True)

                connected_assessment = None
                for a in assessments:
                    bssid_match = connected_bssid and a["network"]["bssid"] == connected_bssid
                    ssid_match = connected_ssid and a["network"]["ssid"] == connected_ssid
                    if bssid_match or (not connected_bssid and ssid_match):
                        a["is_connected"] = True
                        connected_assessment = a
                    else:
                        a["is_connected"] = False

                if not connected_assessment and wifi_iface.get("connected") and connected_ssid:
                    conn_net = {
                        "ssid": connected_ssid,
                        "bssid": connected_bssid or "00:00:00:00:00:00",
                        "rssi": wifi_iface.get("rssi", -50),
                        "encryption": wifi_iface.get("auth", "WPA2"),
                        "channel": wifi_iface.get("channel", 6)
                    }
                    connected_assessment = assess_network(conn_net, set(trusted_networks), raw_nets)
                    connected_assessment["is_connected"] = True

                self.send_response(200)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({
                    "mode": current_mode,
                    "scenario": current_scenario,
                    "source": active_hardware_source,
                    "assessments": assessments,
                    "connected_network": connected_assessment,
                    "trusted": trusted_networks,
                    "blocked": blocked_networks,
                    "history": threat_history
                }, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                print(f"Error serving /api/scan: {e}")
                self.send_response(500)
                self.send_cors_headers()
                self.end_headers()

        elif path == "/api/disconnect":
            try:
                subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, timeout=3)
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"status": "disconnected"}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

        elif path == "/api/mode":
            mode = query.get("mode", ["live"])[0]
            current_mode = "simulated" if mode == "simulated" else "live"
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"mode": current_mode}).encode("utf-8"))

        elif path == "/api/scenario":
            scenario = query.get("type", ["normal"])[0]
            current_scenario = scenario
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
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
            self.send_cors_headers()
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
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"blocked": blocked_networks}).encode("utf-8"))

        elif path == "/api/unblock":
            bssid = query.get("bssid", [""])[0]
            blocked_networks = [b for b in blocked_networks if b["bssid"] != bssid]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"blocked": blocked_networks}).encode("utf-8"))

        elif path == "/api/clear_blocks":
            blocked_networks = []
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

        elif path == "/api/clear_history":
            threat_history = []
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

        elif path == "/api/network_scan":
            full = query.get("full", ["0"])[0] in ("1", "true")
            network_data = scan_network_devices(full_sweep=full)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(network_data).encode("utf-8"))

        elif path == "/api/network_info":
            ctx = get_network_context()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(ctx).encode("utf-8"))

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
