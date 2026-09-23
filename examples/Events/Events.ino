// This sketch expects the application to start an eligible network interface first.
// See WiFiDiscovery for a standalone Wi-Fi setup example.
#include <Arduino.h>
#include <Scout.h>

Scout scout;

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		Serial.printf(
		    "event=%s scan=%llu status=%s source=0x%08X message=%s\n",
		    scout.eventTypeToString(event.type),
		    static_cast<unsigned long long>(event.scanId),
		    scout.statusToString(event.status),
		    static_cast<unsigned>(scoutObservationMask(event.source)),
		    event.message
		);

		if (event.hasDevice) {
			Serial.printf(
			    "  observations=%u endpoints=%u lastSeen=%llu lastConfirmed=%llu\n",
			    static_cast<unsigned>(event.device.observationCount),
			    static_cast<unsigned>(event.device.endpointCount),
			    static_cast<unsigned long long>(event.device.lastSeenAtMs),
			    static_cast<unsigned long long>(event.device.lastConfirmedAtMs)
			);
		}
	});

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	delay(1000);
}
