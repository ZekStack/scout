#include <Arduino.h>
#include <Scout.h>

Scout scout;

constexpr uint32_t ManualScanIntervalMs = 30U * 1000U;
uint32_t lastRequestAt = 0;

void requestScan() {
	const ScoutResult result = scout.scanNow();
	if (!result) {
		Serial.printf("scanNow failed: %s\n", result.message);
		return;
	}

	lastRequestAt = millis();
	Serial.println("Manual scan requested");
}

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		switch (event.type) {
		case ScoutEventType::ScanStarted:
			Serial.printf(
			    "scan %llu started\n",
			    static_cast<unsigned long long>(event.scanId)
			);
			break;
		case ScoutEventType::ScanCompleted:
			Serial.printf(
			    "scan %llu completed, devices=%u\n",
			    static_cast<unsigned long long>(event.scanId),
			    static_cast<unsigned>(scout.deviceCount())
			);
			break;
		case ScoutEventType::ScanSkipped:
			Serial.printf(
			    "scan %llu skipped: %s\n",
			    static_cast<unsigned long long>(event.scanId),
			    event.message
			);
			break;
		default:
			break;
		}
	});

	ScoutConfig config;
	config.scanOnInit = false;
	config.scanIntervalMs = 10U * 60U * 1000U;

	const ScoutResult result = scout.init(config);
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
		return;
	}

	requestScan();
}

void loop() {
	if (scout.isInitialized() && millis() - lastRequestAt >= ManualScanIntervalMs) {
		requestScan();
	}

	delay(100);
}
