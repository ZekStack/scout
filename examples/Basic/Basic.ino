#include <Arduino.h>
#include <Scout.h>

Scout scout;

void printMac(const ScoutMacAddress &mac) {
	for (size_t i = 0; i < sizeof(mac.bytes); ++i) {
		if (i != 0) {
			Serial.print(':');
		}
		Serial.printf("%02X", mac.bytes[i]);
	}
}

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		if (event.type == ScoutEventType::DeviceDiscovered && event.hasDevice) {
			Serial.print("Scout discovered ");
			printMac(event.device.mac);
			Serial.printf(
			    " source=%u confirmedAt=%llu\n",
			    static_cast<unsigned>(event.source),
			    static_cast<unsigned long long>(event.device.lastConfirmedAtMs)
			);
		}
	});

	ScoutConfig config;
	config.memory.allocation = Strata::Placement::PreferExternal;
	config.memory.taskStack = Strata::Placement::PreferExternal;

	const ScoutResult result = scout.init(config);
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	delay(10000);

	const ScoutDiagnostics diagnostics = scout.diagnostics();
	Serial.printf(
	    "devices=%u scans=%llu coverage=%s\n",
	    static_cast<unsigned>(diagnostics.deviceCount),
	    static_cast<unsigned long long>(diagnostics.completedScanCount),
	    diagnostics.coverageAvailable ? "yes" : "no"
	);
}
