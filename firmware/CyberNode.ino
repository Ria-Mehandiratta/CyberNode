#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <WiFi.h>

static const int LED_GREEN = 4;
static const int LED_YELLOW = 5;
static const int LED_RED = 6;
static const int VIBRATION_PIN = 7;
static const char *SERVICE_UUID = "8f2a0001-7c3a-4b31-9d0c-cybernode01";
static const char *CHARACTERISTIC_UUID = "8f2a0002-7c3a-4b31-9d0c-cybernode01";
BLECharacteristic *networkCharacteristic;

void setAlert(int score) {
  digitalWrite(LED_GREEN, score < 31);
  digitalWrite(LED_YELLOW, score >= 31 && score < 61);
  digitalWrite(LED_RED, score >= 61);
  digitalWrite(VIBRATION_PIN, score >= 61);
}

String escapeJson(String value) {
  value.replace("\\", "\\\\");
  value.replace("\"", "\\\"");
  return value;
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_GREEN, OUTPUT); pinMode(LED_YELLOW, OUTPUT);
  pinMode(LED_RED, OUTPUT); pinMode(VIBRATION_PIN, OUTPUT);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  BLEDevice::init("CyberNode");
  BLEServer *server = BLEDevice::createServer();
  BLEService *service = server->createService(SERVICE_UUID);
  networkCharacteristic = service->createCharacteristic(
      CHARACTERISTIC_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
  networkCharacteristic->addDescriptor(new BLE2902());
  networkCharacteristic->setValue("{\"status\":\"ready\"}");
  service->start();
  BLEAdvertising *advertising = BLEDevice::getAdvertising();
  advertising->addServiceUUID(SERVICE_UUID);
  advertising->start();
}

void loop() {
  int count = WiFi.scanNetworks(false, true);
  for (int index = 0; index < count; index++) {
    String ssid = escapeJson(WiFi.SSID(index));
    int score = WiFi.encryptionType(index) == WIFI_AUTH_OPEN ? 45 : 5;
    if (WiFi.RSSI(index) > -50) score += 15;
    setAlert(score);
    String payload = "{\"ssid\":\"" + ssid + "\",\"bssid\":\"" + WiFi.BSSIDstr(index) +
                     "\",\"rssi\":" + String(WiFi.RSSI(index)) +
                     ",\"encryption\":\"" + (WiFi.encryptionType(index) == WIFI_AUTH_OPEN ? "Open" : "WPA2") +
                     "\",\"channel\":" + String(WiFi.channel(index)) + "}";
    networkCharacteristic->setValue(payload.c_str());
    networkCharacteristic->notify();
    delay(150);
  }
  WiFi.scanDelete();
  delay(3000);
}
