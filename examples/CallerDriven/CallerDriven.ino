// This sketch expects the application to start an eligible network interface first.
// Caller-driven mode lets the application decide which task executes Scout work.
#include <Arduino.h>
#include <Scout.h>

Scout scout;

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		if (event.type == ScoutEventType::DeviceDiscovered && event.hasDevice) {
			char mac[18]{};
			if (scoutFormatMac(event.device.mac, mac, sizeof(mac))) {
				Serial.printf("Scout discovered %s\n", mac);
			}
		}
	});

	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 1000;

	const ScoutResult result = scout.init(config);
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	const ScoutResult result = scout.process();
	if (!result && result.status != ScoutStatus::Cancelled) {
		Serial.printf("Scout process failed: %s\n", result.message);
	}

	const uint32_t waitMs = scout.timeUntilNextWork();
	if (waitMs == UINT32_MAX) {
		delay(100);
	} else if (waitMs > 0) {
		delay(waitMs < 25U ? waitMs : 25U);
	} else {
		yield();
	}
}
