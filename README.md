# CyberNode

CyberNode is a portable Wi-Fi safety monitor built around an ESP32-S3 Zero and an Android companion app.

## Project layout

- `app/` Native Android dashboard and threat engine.
- `firmware/` ESP32-S3 Arduino sketch with BLE JSON notifications and physical alerts.
- `dashboard.html` & `runner.py` Live web monitoring dashboard with Dark/Light themes, live ambient Wi-Fi telemetry, and attack simulation.

## Run the Live Monitoring Dashboard (Web)

Run the Python runner to launch the real-time cybersecurity dashboard:
```bash
python runner.py
```
Open `http://localhost:5050` to inspect live Wi-Fi telemetry, test Evil Twin and Rogue AP attack simulations, manage the CyberShield Firewall, and view threat history.

## Run the Android app

Open the repository in Android Studio, sync Gradle, and run the `app` configuration on an Android 8+ device or emulator. The first build uses simulated scan data so the dashboard can be exercised before hardware is paired.

## Flash the firmware

Open `firmware/CyberNode.ino` in Arduino IDE with an ESP32-S3 board package installed. Set the LED, vibration, and battery pins for the board revision before flashing. The sketch advertises the `CyberNode` BLE service and notifies one JSON object per scanned network.

## Security note

The scoring engine is a transparent baseline heuristic, not a replacement for a trained TensorFlow Lite model. Integrate a validated model and Android Wi-Fi/BLE permissions before production deployment. Disconnect and reconnect actions must be confirmed against the device's Android version and OEM restrictions.
