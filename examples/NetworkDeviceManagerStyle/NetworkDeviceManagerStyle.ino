#include <Arduino.h>
#include <Scout.h>

Scout scout;
Strata::UniquePtr<ScoutDeviceDetails> details;

void setup() {
	Serial.begin(115200);
	details =
	    Strata::makeUnique<ScoutDeviceDetails>(Strata::Placement::PreferExternal);

	// A product can back this callback with a generated IEEE OUI table in PSRAM or flash.
	scout.setOuiLookup([](const ScoutMacAddress &mac, ScoutVendorInfo &vendor) {
		if (mac.bytes[0] == 0x24 && mac.bytes[1] == 0x6F && mac.bytes[2] == 0x28) {
			vendor.known = true;
			strncpy(vendor.name, "Example vendor", sizeof(vendor.name) - 1);
			return true;
		}
		return false;
	});

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.println(result.message);
	}
}

void loop() {
	static uint32_t lastPrintedAt = 0;
	if (!details || millis() - lastPrintedAt < 10000) {
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

		// This is approximately the information a non-technical UI should consume.
		Serial.printf(
		    "%s | %s | %s | %u network path(s)\n",
		    name.value,
		    details->manufacturer[0] != '\0'
		        ? details->manufacturer
		        : (details->vendor.known ? details->vendor.name : "Unknown vendor"),
		    details->modelName[0] != '\0' ? details->modelName : "Unknown model",
		    static_cast<unsigned>(info.endpointCount)
		);
	}
}
