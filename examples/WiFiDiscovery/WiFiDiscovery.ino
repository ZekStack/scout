#include <Arduino.h>
#include <Scout.h>
#include <soc/soc_caps.h>

#if SOC_WIFI_SUPPORTED
#include <WiFi.h>

Scout scout;

// Replace these with credentials for the network to scan.
constexpr char WifiSsid[] = "";
constexpr char WifiPassword[] = "";

void setup() {
	Serial.begin(115200);
	if (WifiSsid[0] == '\0') {
		Serial.println("Set WifiSsid and WifiPassword before running this example.");
		return;
	}

	WiFi.mode(WIFI_STA);
	WiFi.begin(WifiSsid, WifiPassword);

	const uint32_t startedAt = millis();
	while (WiFi.status() != WL_CONNECTED && millis() - startedAt < 15000U) {
		delay(100);
	}
	if (WiFi.status() != WL_CONNECTED) {
		Serial.println("Wi-Fi connection timed out.");
		return;
	}

	Serial.print("Connected with IP ");
	Serial.println(WiFi.localIP());

	scout.onEvent([](const ScoutEvent &event) {
		if (event.type == ScoutEventType::DeviceDiscovered && event.hasDevice) {
			Serial.printf(
			    "Discovered %02X:%02X:%02X:%02X:%02X:%02X\n",
			    event.device.mac.bytes[0],
			    event.device.mac.bytes[1],
			    event.device.mac.bytes[2],
			    event.device.mac.bytes[3],
			    event.device.mac.bytes[4],
			    event.device.mac.bytes[5]
			);
		} else if (event.type == ScoutEventType::ScanCompleted) {
			Serial.printf("Scan completed: %s\n", scout.statusToString(event.status));
		} else if (event.type == ScoutEventType::CoverageLost) {
			Serial.println("No eligible ARP interface is available.");
		}
	});

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

#else

void setup() {
	Serial.begin(115200);
	Serial.println("WiFiDiscovery requires a Wi-Fi-capable ESP32 board.");
}

#endif

void loop() {
	delay(1000);
}
