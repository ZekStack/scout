#include <Arduino.h>
#include <Scout.h>

Scout scout;
Strata::UniquePtr<ScoutDeviceDetails> details;

void setup() {
	Serial.begin(115200);

	// Scout expects the application to start Wi-Fi/Ethernet first.
	details =
	    Strata::makeUnique<ScoutDeviceDetails>(Strata::Placement::PreferExternal);

	if (!details) {
		Serial.println("Failed to allocate the rich device-details buffer");
		return;
	}

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.println(result.message);
	}
}

void loop() {
	static uint32_t lastPrintedAt = 0;
	if (millis() - lastPrintedAt < 10000) {
		delay(100);
		return;
	}
	lastPrintedAt = millis();

	for (size_t i = 0; i < scout.deviceCount(); ++i) {
		ScoutDeviceInfo info;
		if (!scout.deviceAt(i, info) || !scout.deviceDetailsAt(i, *details)) {
			continue;
		}

		ScoutPreferredName name;
		scout.preferredName(info.mac, name);

		Serial.printf(
		    "%s | vendor=%s | manufacturer=%s | model=%s | endpoints=%u | services=%u\n",
		    name.value,
		    details->vendor.known ? details->vendor.name : "",
		    details->manufacturer,
		    details->modelName,
		    static_cast<unsigned>(info.endpointCount),
		    static_cast<unsigned>(details->serviceCount)
		);
	}
}
