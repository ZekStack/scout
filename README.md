# Scout

Scout is a continuous local-network discovery and observation library for ESP32.

Scout discovers devices on directly connected IPv4 networks, keeps a bounded in-memory registry keyed by MAC address, tracks per-interface endpoints and observation timestamps, and reports discovery and coverage events from a dedicated background task. Scout owns discovery and observation only; application-level online/offline policy belongs in the consuming application.

[![CI](https://github.com/ZekStack/scout/actions/workflows/ci.yml/badge.svg)](https://github.com/ZekStack/scout/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZekStack/scout?sort=semver)](https://github.com/ZekStack/scout/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Why use Scout?

* **Continuous discovery** - periodically scans eligible local IPv4 interfaces from a background FreeRTOS task.
* **Public lwIP path** - active ARP requests and lookups run through ESP-NETIF's TCP/IP-context bridge instead of touching private lwIP ARP structures.
* **MAC-first identity** - devices are keyed by MAC address while IPv4 addresses are tracked as per-interface endpoints.
* **Coverage-aware** - reports when Scout can or cannot observe an eligible ARP-capable interface.
* **Bounded work** - device capacity, subnet size, ARP batch size, response wait, and scan cadence are explicit.
* **PSRAM-first** - Scout-owned movable storage and the Scout task stack prefer external memory by default.
* **Application-neutral** - Scout does not define online/offline thresholds, persistence, automation semantics, or Hitec-specific behavior.
* **Strata-owned runtime** - memory placement, task ownership, and synchronization use Strata.

## Install

Scout `0.1.0` requires Strata `v0.1.2`, C++20, and the PIOArduino ESP32 platform used by CI.

### PlatformIO

Install PIOArduino Core `6.1.19` and use its ESP32 platform `55.03.39`:

```sh
python -m pip install "pioarduino==6.1.19"
```

```ini
[env:esp32dev]
platform = https://github.com/pioarduino/platform-espressif32/releases/download/55.03.39/platform-espressif32.zip
board = esp32dev
framework = arduino

lib_deps =
  https://github.com/ZekStack/scout.git#v0.1.0
  https://github.com/ZekStack/strata.git#v0.1.2

build_flags =
  -std=gnu++20
build_unflags =
  -std=gnu++11
```

Scout's `library.json` pins Strata `v0.1.2`, so PIOArduino can also resolve Strata transitively.

### Arduino IDE

Scout and Strata are not published to Arduino Library Manager yet.

Install both repositories into your Arduino libraries folder:

```txt
Arduino/libraries/Scout
Arduino/libraries/Strata
```

## Quick start

Scout does not initialize Wi-Fi or Ethernet. Initialize the network interface in the application before expecting useful discovery results.

```cpp
#include <Arduino.h>
#include <Scout.h>

Scout scout;

void setup() {
	Serial.begin(115200);

	scout.onEvent([](const ScoutEvent &event) {
		if (event.type != ScoutEventType::DeviceDiscovered || !event.hasDevice) {
			return;
		}

		Serial.printf(
		    "device observations=%u confirmedAt=%llu\n",
		    static_cast<unsigned>(event.device.observationCount),
		    static_cast<unsigned long long>(event.device.lastConfirmedAtMs)
		);
	});

	ScoutResult result = scout.init();
	if (!result) {
		Serial.println(result.message);
	}
}

void loop() {
	delay(1000);
}
```

## Memory model

Scout uses the shared ZekStack Strata memory-policy shape:

```cpp
ScoutConfig config;

// These are already the defaults.
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
```

`memory.allocation` controls movable Scout-owned storage, including the device registry, subnet target buffer, and ARP scratch buffers.

`memory.taskStack` controls the Scout background task stack.

The Scout runtime object itself is also created with `Strata::Placement::PreferExternal`. `PreferExternal` uses external RAM when possible and falls back to internal memory according to Strata's placement contract. Safety-critical FreeRTOS control blocks remain internal when Strata requires it.

Diagnostics report both requested placement and observed regions:

```cpp
ScoutDiagnostics diag = scout.diagnostics();

Serial.println(Strata::toString(diag.allocationPlacement));
Serial.println(Strata::toString(diag.taskStackPlacement));
Serial.println(Strata::toString(diag.registryRegion));
Serial.println(Strata::toString(diag.taskStackRegion));
```

## Discovery model

Scout v0.1.0 starts with active ARP discovery.

For each eligible interface, Scout calculates the directly connected IPv4 subnet, rejects scans larger than `maxHostsPerSubnet`, and processes targets in small batches. Direct lwIP calls such as `etharp_request()`, `etharp_find_addr()`, and interface lookup execute through `esp_netif_tcpip_exec()` in the lwIP TCP/IP context.

Scout distinguishes two ARP observation sources:

* `ArpCache` - the same mapping already existed before Scout's active request.
* `ArpProbe` - the mapping appeared or changed during the active probe window.

Only an `ArpProbe` observation advances `lastConfirmedAtMs`. A pre-existing ARP cache entry is useful discovery evidence, but Scout does not claim that it proves a fresh response.

The registry and source mask are intended to accept additional discovery providers such as ICMP, mDNS/DNS-SD, SSDP, and optional NBNS without changing higher-level presence policy.

## Coverage model

Coverage is separate from device observations.

Scout reports `CoverageLost` when no eligible interface is available or a scan of any eligible interface is skipped or fails. It reports `CoverageRestored` after every eligible interface completes a scan successfully. A skipped or failed interface gives the final `ScanCompleted` event a non-OK status.

A presence layer built on Scout should suppress offline inference while coverage is unavailable and revalidate known devices after coverage returns.

## Important notes

> [!IMPORTANT]
> Scout reports network observations, not application-level online/offline state.

* `scanNow()` schedules an immediate scan and returns; it does not block until the subnet sweep completes.
* Event callbacks run from the Scout task. Keep them short and do not call `deinit()` from a Scout callback.
* Scout never retains lwIP `struct netif` or ARP-table pointers outside the TCP/IP-context callback.
* Large directly connected networks are skipped when their usable host count exceeds `maxHostsPerSubnet`.
* A device can have more than one IPv4 endpoint when it is observed through multiple local interfaces.
* Scout currently performs no persistence, port scanning, device-type classification, or OUI-vendor lookup.
* `PreferExternal` is deliberately different from `RequireExternal`; systems without usable PSRAM can still operate using Strata's fallback behavior.

## API overview

```cpp
ScoutConfig config;
config.scanIntervalMs = 60'000;
config.maxDevices = 128;
config.maxHostsPerSubnet = 512;

Scout scout;

ScoutResult initResult = scout.init(config);
if (!initResult) {
	// Handle initResult.status.
}

scout.scanNow();

ScoutDeviceInfo device;
if (scout.deviceAt(0, device)) {
	// Consume a snapshot.
}

ScoutDiagnostics diag = scout.diagnostics();
scout.deinit();
```

## Examples

| Example | Description |
| --- | --- |
| `Basic` | Initialize Scout, receive discovery events, and inspect runtime diagnostics. |
| `Events` | Observe scan, device, coverage, and error events. |
| `Registry` | Enumerate the device registry, inspect endpoints, and look up a device by MAC address. |
| `ManualScan` | Disable the initial scan and explicitly request non-blocking scans with `scanNow()`. |
| `Diagnostics` | Inspect scan counters, ARP statistics, memory placement, and task-stack diagnostics. |
| `MultiInterface` | Inspect devices observed through multiple eligible ESP-NETIF interfaces. |

Start with:

```txt
examples/Basic
```

## Testing

Scout includes host-side regression tests for platform-independent discovery logic. The suite covers IPv4 subnet target generation and bounds, MAC helpers, public configuration defaults, endpoint refresh behavior, multi-interface endpoint handling, bounded endpoint replacement, and interface-name truncation.

Run the host suite with:

```sh
bash tests/host/run.sh
```

CI runs the host suite with address and undefined-behavior sanitizers before the ESP32 example build matrix.

## Documentation

| Document | Description |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Responsibility boundaries, task ownership, identity, and coverage. |
| [`docs/discovery.md`](docs/discovery.md) | ARP scan flow and observation semantics. |
| [`docs/memory.md`](docs/memory.md) | Strata integration and external-memory policy. |

## Compatibility

| Item | Support |
| --- | --- |
| Framework | Arduino ESP32 |
| Platform | PIOArduino ESP32 platform `55.03.39` |
| Language | C++20 |
| Network layer | ESP-NETIF and public lwIP ARP APIs |
| Memory policy | `PreferExternal` by default for Scout-owned movable storage and task stack |
| Dependencies | Strata `v0.1.2` |
| Exceptions | Not used for Scout public error handling |
| Status | `0.1.0` |

## License

MIT - see [`LICENSE.md`](LICENSE.md).

## ZekStack

Part of the ZekStack ESP32 library stack.
