#include <Arduino.h>
#include <Scout.h>

#include <lwip/def.h>

Scout scout;

void printMac(const ScoutMacAddress &mac) {
	for (size_t i = 0; i < sizeof(mac.bytes); ++i) {
		if (i != 0) {
			Serial.print(':');
		}
		Serial.printf("%02X", mac.bytes[i]);
	}
}

void printIpv4(const ScoutIpv4Address &address) {
	const uint32_t value = lwip_ntohl(address.value);
	Serial.printf(
	    "%u.%u.%u.%u",
	    static_cast<unsigned>((value >> 24U) & 0xFFU),
	    static_cast<unsigned>((value >> 16U) & 0xFFU),
	    static_cast<unsigned>((value >> 8U) & 0xFFU),
	    static_cast<unsigned>(value & 0xFFU)
	);
}

void printDevice(const ScoutDeviceInfo &device) {
	printMac(device.mac);
	Serial.printf(
	    " observations=%u sources=0x%08X firstSeen=%llu lastSeen=%llu confirmed=%llu\n",
	    static_cast<unsigned>(device.observationCount),
	    static_cast<unsigned>(device.observationSources),
	    static_cast<unsigned long long>(device.firstSeenAtMs),
	    static_cast<unsigned long long>(device.lastSeenAtMs),
	    static_cast<unsigned long long>(device.lastConfirmedAtMs)
	);

	for (size_t i = 0; i < device.endpointCount; ++i) {
		const ScoutEndpoint &endpoint = device.endpoints[i];
		Serial.printf(
		    "  endpoint[%u] interface=%s(%u) ip=",
		    static_cast<unsigned>(i),
		    endpoint.interfaceName,
		    static_cast<unsigned>(endpoint.interfaceIndex)
		);
		printIpv4(endpoint.ipv4);
		Serial.printf(
		    " lastSeen=%llu\n",
		    static_cast<unsigned long long>(endpoint.lastSeenAtMs)
		);
	}
}

void setup() {
	Serial.begin(115200);

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	delay(15000);

	const size_t count = scout.deviceCount();
	Serial.printf("\nScout registry: %u device(s)\n", static_cast<unsigned>(count));

	for (size_t i = 0; i < count; ++i) {
		ScoutDeviceInfo device;
		const ScoutResult result = scout.deviceAt(i, device);
		if (result) {
			printDevice(device);
		}
	}

	if (count > 0) {
		ScoutDeviceInfo first;
		if (scout.deviceAt(0, first)) {
			ScoutDeviceInfo byMac;
			const ScoutResult lookup = scout.findByMac(first.mac, byMac);
			Serial.printf(
			    "findByMac(first device): %s\n",
			    lookup ? "found" : lookup.message
			);
		}
	}
}
