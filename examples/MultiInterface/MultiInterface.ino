// This sketch expects the application to start an eligible network interface first.
// See WiFiDiscovery for a standalone Wi-Fi setup example.
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

void printEndpoints(const ScoutDeviceInfo &device) {
	printMac(device.mac);
	Serial.printf(" has %u endpoint(s)\n", static_cast<unsigned>(device.endpointCount));

	for (size_t i = 0; i < device.endpointCount; ++i) {
		const ScoutEndpoint &endpoint = device.endpoints[i];
		Serial.printf(
		    "  interface=%s index=%u ip=",
		    endpoint.interfaceName,
		    static_cast<unsigned>(endpoint.interfaceIndex)
		);
		printIpv4(endpoint.ipv4);
		Serial.println();
	}
}

void setup() {
	Serial.begin(115200);

	// Configure and start all desired ESP-NETIF interfaces before Scout.
	// Scout automatically observes every up, link-up, ARP-capable IPv4 interface.

	scout.onEvent([](const ScoutEvent &event) {
		if (!event.hasDevice) {
			return;
		}

		if (event.type == ScoutEventType::DeviceDiscovered ||
		    event.type == ScoutEventType::DeviceChanged) {
			Serial.printf("%s: ", scout.eventTypeToString(event.type));
			printEndpoints(event.device);
		}
	});

	const ScoutResult result = scout.init();
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	delay(15000);

	const ScoutDiagnostics diag = scout.diagnostics();
	Serial.printf(
	    "eligible interfaces=%u registry devices=%u\n",
	    static_cast<unsigned>(diag.activeInterfaceCount),
	    static_cast<unsigned>(diag.deviceCount)
	);
}
