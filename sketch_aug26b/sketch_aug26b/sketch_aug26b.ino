#include <CBOR.h>
#include <CBORArray.h>
#include <CBORComposed.h>
#include <CBORPair.h>
#include <YACL.h>

#include <Ed25519.h>
#include <Ascon128.h>

#include <ESP8266WiFi.h>
#include <WiFiClient.h>

#include <Ticker.h>

#include "LittleFS.h"

const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
const char* host     = "YOUR_SERVER_IP";
const unsigned int port     = 12345;

const unsigned int serverRetryDelay = 2000; // Interval to server reconnection (in milliseconds)

struct Ed25519KeyPair {
  uint8_t privateKey[32] = {(uint8_t) -1};
  uint8_t publicKey[32] = {(uint8_t) -1};
};

std::vector<float> randomFloats;

Ticker ticker;
WiFiClient client;

bool internetAutoCheck(Ticker& t) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("WiFi not connected! Attempting reconnection..."));
    WiFi.disconnect();
    WiFi.reconnect();
    unsigned long startAttemptTime = millis();

    while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 10000) {
      delay(500);
      Serial.print(".");
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println(F("\nReconnected to WiFi!"));
      return true;
    } else {
      Serial.println(F("\nFailed to reconnect to WiFi."));
      return false;
    }
  } else {
    return true;
  }
  return false;
}

void setup() {
  Serial.begin(115200);
  Serial.print(F("Starting FS..."));

  if(!LittleFS.begin()){
    Serial.println(F("An Error has occurred while mounting LittleFS"));
    while(true);
  }else{
    Serial.println(F("LittleFS mounted successfully"));
  }

  Serial.print(F("Connecting to WiFi"));

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println(F("\nWiFi connected"));
}

Ed25519KeyPair keyPair;

Ed25519KeyPair setupEd25519() {
  Ed25519KeyPair keyPair;
  if(LittleFS.check()){
    if(!LittleFS.exists("/ed25519_pri.key")){
      if(LittleFS.exists("/ed25519_pub.key")){LittleFS.remove("/ed25519_pub.key");}

      Ed25519::generatePrivateKey(keyPair.privateKey);
      Ed25519::derivePublicKey(keyPair.publicKey, keyPair.privateKey);

      File priFile = LittleFS.open("/ed25519_pri.key","w");
      priFile.write(keyPair.privateKey,32);
      priFile.close();

      File pubFile = LittleFS.open("/ed25519_pub.key","w");
      pubFile.write(keyPair.publicKey,32);
      pubFile.close();

      Serial.println(F("New Ed25519 keys generated and saved to LittleFS"));

      return keyPair;
    }else{
      File priFile = LittleFS.open("/ed25519_pri.key","r");
      priFile.read(keyPair.privateKey,32);
      priFile.close();

      if(LittleFS.exists("/ed25519_pub.key")){
        File pubFile = LittleFS.open("/ed25519_pub.key","r");
        pubFile.read(keyPair.publicKey,32);
        pubFile.close();

        Serial.println(F("Ed25519 keys loaded from LittleFS"));

        return keyPair;
      }else{
        Ed25519::derivePublicKey(keyPair.publicKey, keyPair.privateKey);

        File pubFile = LittleFS.open("/ed25519_pub.key","w");
        pubFile.write(keyPair.publicKey,32);
        pubFile.close();

        Serial.println(F("Ed25519 public key derived and saved to LittleFS"));

        return keyPair;
      }
    }
  }else{
    Serial.println(F("LittleFS not available, generating keys in memory only"));

    Ed25519::generatePrivateKey(keyPair.privateKey);
    Ed25519::derivePublicKey(keyPair.publicKey, keyPair.privateKey);

    return keyPair;
  }
}

bool setupEncrypt(Ed25519KeyPair& keyPair, WiFiClient& client) {
  if (!client.connected()) {

    Serial.println(F("Client not connected, cannot setup encryption."));

    return false;
  }

  CBORPair root;
  
  root.append("PK",keyPair.publicKey); //public key

  const uint8_t *buf = root.to_CBOR();
  size_t bufLen = root.length();

  if(buf == nullptr || bufLen == 0){
    Serial.println(F("Failed to encode CBOR data."));
    return false;
  }

  client.write(buf, bufLen);

  Serial.println(F("Encryption setup message sent."));

  uint8_t serverPK[32] = {(uint8_t) -1};
  std::vector<byte> serverBuffer;

  ticker.attach_ms(5000, [&client](){
    Serial.println(F("Timeout waiting for server response."));
    client.stop();
  });

  while (client.available()){
    serverBuffer.push_back(client.read());
  }

  if(serverBuffer.size() > 0){
    CBOR response = CBOR(serverBuffer.data(), serverBuffer.size());
    if(!response.is_pair()){ Serial.println(F("Response is not a CBOR pair.")); return false; }
    if(!response["PK"].is_array()){ Serial.println(F("Response does not contain 'PK' array or the 'PK' in Pair is not an array.")); return false;}
    memcpy(serverPK, response["PK"].get_buffer(), 32);
  }

  ticker.detach();

  if(serverPK[31] == (uint8_t) -1){
    Serial.println(F("Failed to receive server public key."));
    return false;
  }

  Serial.println(F("Received server public key:"));
  for(int i=0;i<32;i++){
    Serial.printf("%02X", serverPK[i]);
  }

  return true;
}

void loop() {
  if(internetAutoCheck(ticker)){
    if(!client.connected()){
      Serial.println(F("Connecting to server..."));
      if (!client.connect(host, port)) {
        Serial.println(F("Connection to host failed"));
        delay(serverRetryDelay); // Wait before retrying
        return;
      }
      Serial.println(F("Connected to server")); 
    }else{
      if(keyPair.privateKey[31] == (uint8_t) -1 || keyPair.publicKey[31] == (uint8_t) -1){
        keyPair = setupEd25519();
      }
      if(setupEncrypt(keyPair,client)){
        Serial.println(F("Encryption setup completed"));
        delay(5000); // Wait before next operation
      }else{
        Serial.println(F("Failed to setup encryption"));
        delay(500); // Wait before retrying
        return;
      }
    }
  }else{
    delay(2000); // Wait before next WiFi check
  }
}
