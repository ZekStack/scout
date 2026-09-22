# Scout

Scout is a continuous local-network discovery and observation library for ESP32.

Scout owns a background FreeRTOS task, discovers ARP-capable IPv4 interfaces, actively probes bounded local subnets, and maintains an in-memory device registry keyed by MAC address. It deliberately reports observations rather than application-level online/offline state.

The first implementation slice focuses on a safe ARP foundation. mDNS, SSDP, ICMP confirmation, hostname enrichment, and higher-level presence policy are intentionally separate follow-up layers.

## Design goals

- Continuous, bounded LAN discovery.
- No private lwIP ARP-table access and no hand-crafted Ethernet frames.
- All non-BSD lwIP interaction runs inside the lwIP TCP/IP context through ESP-NETIF.
- MAC-first device identity with per-interface IPv4 endpoints.
- Explicit coverage-lost/restored events so consumers can distinguish a missing device from a blind scanner.
- No Hitec-specific policy, Signal Bus dependency, persistence, or automation semantics.
- Strata-owned memory and task lifetime.

## Memory policy

Scout prefers external RAM everywhere it can safely do so.

The default policy is:

~~~cpp
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
~~~

Scout's runtime object, registry, scan target buffer, ARP scratch buffers, and task stack all prefer external RAM. Strata may still keep safety-critical FreeRTOS control blocks in internal memory, and PreferExternal falls back to internal memory when external memory is unavailable.

## Quick start

~~~cpp
#include <Arduino.h>
#include <Scout.h>

Scout scout;

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		if (event.type == ScoutEventType::DeviceDiscovered && event.hasDevice) {
			Serial.printf(
			    "device discovered, observations=%u\n",
			    static_cast<unsigned>(event.device.observationCount)
			);
		}
	});

	ScoutResult result = scout.init();
	if (!result) {
		Serial.println(result.message);
	}
}

void loop() {
	delay(1000);
}
~~~

Scout does not initialize Wi-Fi or Ethernet. The application owns network-interface setup.

## Current discovery semantics

Scout currently uses public lwIP ARP functions from inside ESP-NETIF's TCP/IP execution context.

An ARP mapping already present before a probe is reported as ArpCache. A mapping that was absent before the request and present after the response window is reported as ArpProbe and updates lastConfirmedAtMs.

This distinction is intentional: an existing stable ARP-cache entry is useful for discovery, but it is not proof that the device answered the most recent probe. Future ICMP and protocol-specific observation sources will provide stronger ongoing liveness confirmation.

## API overview

~~~cpp
ScoutConfig config;
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
config.scanIntervalMs = 60000;
config.maxDevices = 128;
config.maxHostsPerSubnet = 512;

Scout scout;
scout.init(config);
scout.scanNow();

ScoutDiagnostics diagnostics = scout.diagnostics();

ScoutDeviceInfo device;
if (scout.deviceAt(0, device)) {
	// Consume a snapshot.
}

scout.deinit();
~~~

## Documentation

- docs/architecture.md - ownership and responsibility boundaries.
- docs/discovery.md - ARP scanning and observation semantics.
- docs/memory.md - Strata integration and external-memory policy.

## Compatibility

- Framework: Arduino ESP32 / ESP-IDF underneath.
- Language: C++20.
- Memory: Strata v0.1.2.
- Status: early v0.1.0 implementation.

## License

MIT - see LICENSE.
