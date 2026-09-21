/* ==========================================
   CyberNode Dashboard V1 (AP Mode)
   ESP32 DevKit V1
   WiFi: CyberNode
   Password: 12345678
   Dashboard: http://192.168.4.1
   Integrated with CyberNode AI Threat Engine
   ========================================== */

#include <WiFi.h>
#include <WebServer.h>

WebServer server(80);

String encryptionType(wifi_auth_mode_t type) {
  switch (type) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    default: return "UNKNOWN";
  }
}

void handleScan() {
  int n = WiFi.scanNetworks();

  String json = "[";

  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";

    json += "{";
    json += "\"ssid\":\"" + WiFi.SSID(i) + "\",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"encryption\":\"" + encryptionType(WiFi.encryptionType(i)) + "\"";
    json += "}";
  }

  json += "]";

  // CORS Headers allow CyberNode Web & Mobile Software to read data from 192.168.4.1
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server.send(200, "application/json", json);

  // Also print to Serial for USB Serial Monitoring
  Serial.print("[SCAN_DATA] ");
  Serial.println(json);
}

void handleOptions() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server.send(204);
}

void handleRoot() {

String page = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>CyberNode Dashboard</title>
<style>
body{font-family:Arial;background:#F4F7FC;padding:20px;}
h1{color:#1565C0;text-align:center;}
.card{background:#fff;padding:15px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.15);margin-bottom:20px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;font-size:14px;}
th{background:#1565C0;color:white;}
.safe{color:green;font-weight:bold;}
.warning{color:orange;font-weight:bold;}
.danger{color:red;font-weight:bold;}
button{background:#1565C0;color:white;padding:10px 18px;border:none;border-radius:8px;cursor:pointer;}
</style>
</head>
<body>

<h1>CyberNode WiFi Security Dashboard</h1>

<div class='card'>
<b>ESP32 Access Point:</b> CyberNode<br>
<b>Dashboard IP:</b> 192.168.4.1<br><br>
<button onclick='loadScan()'>Scan WiFi</button>
</div>

<div class='card'>
<h3>Nearby WiFi Networks</h3>
<table>
<thead>
<tr>
<th>SSID</th>
<th>BSSID</th>
<th>RSSI</th>
<th>Encryption</th>
<th>Risk</th>
</tr>
</thead>
<tbody id='wifiTable'></tbody>
</table>
</div>

<script>
async function loadScan(){
const res = await fetch('/scan');
const data = await res.json();
let rows='';

data.forEach(net=>{
let risk='SAFE';
let cls='safe';

if(net.encryption=='OPEN'){
risk='HIGH';
cls='danger';
}
else if(net.rssi>-40){
risk='MEDIUM';
cls='warning';
}

rows += `
<tr>
<td>${net.ssid}</td>
<td>${net.bssid}</td>
<td>${net.rssi} dBm</td>
<td>${net.encryption}</td>
<td class='${cls}'>${risk}</td>
</tr>`;
});

document.getElementById('wifiTable').innerHTML = rows;
}

loadScan();
setInterval(loadScan,5000);
</script>

</body>
</html>
)rawliteral";

server.send(200,"text/html",page);
}

void setup(){
Serial.begin(115200);

WiFi.mode(WIFI_AP_STA);
WiFi.softAP("CyberNode","12345678");

Serial.println("==============================");
Serial.println("CyberNode Dashboard Started");
Serial.println("WiFi Name : CyberNode");
Serial.println("Password  : 12345678");
Serial.print("Dashboard : http://");
Serial.println(WiFi.softAPIP());
Serial.println("==============================");

server.on("/",handleRoot);
server.on("/scan",HTTP_GET,handleScan);
server.on("/scan",HTTP_OPTIONS,handleOptions);
server.begin();
}

void loop(){
server.handleClient();
}
