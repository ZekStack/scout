#include <Arduino.h>
#include <Scout.h>

Scout scout;

void setup() {
	Serial.begin(115200);

	// Start Wi-Fi/Ethernet (and application-owned mDNS, if used) before Scout.
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

	Serial.printf(
	    "identity groups=%u relations=%u\n",
	    static_cast<unsigned>(scout.identityGroupCount()),
	    static_cast<unsigned>(scout.identityRelationCount())
	);

	for (size_t i = 0; i < scout.identityGroupCount(); ++i) {
		ScoutIdentityGroup group;
		if (!scout.identityGroupAt(i, group)) {
			continue;
		}

		Serial.printf(
		    "group %llu members=%u confidence=%u\n",
		    static_cast<unsigned long long>(group.runtimeId),
		    static_cast<unsigned>(group.memberCount),
		    static_cast<unsigned>(group.confidence)
		);

		for (size_t member = 0; member < group.memberCount; ++member) {
			const auto &mac = group.members[member].mac;
			Serial.printf(
			    "  %02X:%02X:%02X:%02X:%02X:%02X\n",
			    mac.bytes[0],
			    mac.bytes[1],
			    mac.bytes[2],
			    mac.bytes[3],
			    mac.bytes[4],
			    mac.bytes[5]
			);
		}
	}
}
