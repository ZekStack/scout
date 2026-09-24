# Scout

Scout is a continuous local-network discovery and observation library for ESP32.

Scout discovers devices on directly connected IPv4 networks, keeps a bounded MAC-keyed registry, enriches known devices through ICMP, mDNS/DNS-SD, SSDP/UPnP, optional NBNS/reverse DNS and application-provided OUI lookup, and exposes conservative physical-device identity relationships. Scout owns discovery and observation only; application-level online/offline policy belongs in the consuming application.

[![CI](https://github.com/ZekStack/scout/actions/workflows/ci.yml/badge.svg)](https://github.com/ZekStack/scout/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZekStack/scout?sort=semver)](https://github.com/ZekStack/scout/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Why use Scout?

* **Continuous discovery** - periodically scans eligible local IPv4 interfaces from a background FreeRTOS task.
* **Public lwIP path** - active ARP requests and lookups run through ESP-NETIF's TCP/IP-context bridge instead of touching private lwIP ARP structures.
* **MAC-first identity** - devices are keyed by MAC address while IPv4/IPv6 aliases are tracked as per-interface endpoints.
* **Rich enrichment** - learns friendly names, hostnames, services, manufacturer/model data and stable protocol identifiers.
* **Conservative physical identity** - strong evidence can group multiple MAC identities without destructively merging their network records.
* **Bounded registry lifetime** - stale observations expire after the configurable `deviceMaxAgeMs`, and endpoint ownership is deduplicated across devices.
* **Coverage-aware** - reports when Scout can or cannot observe an eligible ARP-capable interface.
* **Bounded work** - device capacity, subnet size, ARP batch size, response wait, and scan cadence are explicit.
* **PSRAM-first** - Scout-owned movable storage and the Scout task stack prefer external memory by default.
* **Application-neutral** - Scout does not define online/offline thresholds, persistence, automation semantics, or Hitec-specific behavior.
* **Strata-owned runtime** - memory placement, task ownership, and synchronization use Strata.

## Install

Scout `0.1.0` requires Strata `v0.1.2`, C++20, and Arduino ESP32 core `3.3.9`. PlatformIO builds use the pinned PIOArduino platform below.

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

Scout and Strata are not published to Arduino Library Manager yet. Install Arduino ESP32 core `3.3.9` through Boards Manager, then install both repositories into your Arduino libraries folder:

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

`memory.allocation` controls movable Scout-owned storage, including the compact device registry,
lazy rich-detail allocations, provider target tables, identity tables, UPnP scratch storage,
subnet target buffer, and ARP scratch buffers.

`memory.taskStack` controls the Scout background task stack.

The Scout runtime object itself is also created with `Strata::Placement::PreferExternal`. The shared deferred-cleanup task used for callback-safe destruction also has an external-preferred stack. `PreferExternal` uses external RAM when possible and falls back to internal memory according to Strata's placement contract. Safety-critical FreeRTOS control blocks remain internal when Strata requires it.

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

After ARP establishes MAC/IP/interface truth, independently scheduled providers add ICMP
confirmation, mDNS/DNS-SD names and services, SSDP/UPnP metadata, optional NBNS/reverse-DNS names,
IPv6 aliases, and OUI vendor information without changing higher-level presence policy. Provider
results are discarded if their captured `(interface, IPv4)` endpoint has since moved to another
MAC, and IP-only enrichment does not extend registry `lastSeenAtMs`. Bounded providers rotate
through targets/service types across runs instead of repeatedly starting from entry zero. Reverse
DNS uses Scout's bounded UDP PTR client against the DNS server configured on the endpoint's
ESP-NETIF; it does not rely on blocking `getnameinfo()`.

### Registry retention and deduplication

`deviceMaxAgeMs` controls registry retention, not presence state. The default is five minutes. A record expires when Scout has not observed it for that duration, based on `lastSeenAtMs`, and Scout emits `DeviceExpired` with the final device snapshot. For stable continuous discovery, configure the retention age to at least twice the normal scan interval; smaller values are valid but can intentionally produce expire/rediscover churn.

MAC address remains the device identity. Scout never merges two different MAC addresses merely because they used the same IPv4 address. Within the registry, a specific `(interface, IPv4)` endpoint has one current MAC owner; observing that endpoint on another MAC transfers the endpoint while retaining the older device record until its own retention period expires.

`lastConfirmedAtMs` remains separate from retention. Applications that need Online/Offline state should continue to apply their own presence policy above Scout.

## Coverage model

Coverage is separate from device observations.

Scout reports `CoverageLost` when no eligible interface is available or a scan of any eligible interface is skipped or fails. It reports `CoverageRestored` after every eligible interface completes a scan successfully. A skipped or failed interface gives the final `ScanCompleted` event a non-OK status. Every emitted `ScanStarted` has exactly one terminal `ScanCompleted` with the same `scanId`, including cancellation during shutdown.

A presence layer built on Scout should suppress offline inference while coverage is unavailable and revalidate known devices after coverage returns.

## Important notes

> [!IMPORTANT]
> Scout reports network observations, not application-level online/offline state.

* `scanNow()` schedules an immediate scan and returns; it does not block until the subnet sweep completes.
* Event callbacks run from the Scout task. Keep them short. Explicit `deinit()` from a callback returns `Busy`; destroying the `Scout` object from its callback is supported through deferred cleanup on a separate Strata-owned task.
* Scout never retains lwIP `struct netif` or ARP-table pointers outside the TCP/IP-context callback.
* Large directly connected networks are skipped when their usable host count exceeds `maxHostsPerSubnet`.
* A device can have more than one IPv4 endpoint when it is observed through multiple local interfaces.
* Scout performs no persistence, port scanning, or heuristic device-type classification. OUI lookup is supported through an application-provided resolver so Scout does not ship a stale vendor database.
* Rich `ScoutDeviceDetails` snapshots are intentionally large; Scout allocates them lazily per enriched device, and applications should keep reusable snapshot buffers in PSRAM rather than on a small task stack.
* Failure to allocate a rich detail record does not discard the compact MAC registry entry; `enrichmentAllocationFailures` reports that pressure.
* `PreferExternal` is deliberately different from `RequireExternal`; smaller/non-PSRAM systems can still use the compact registry, but applications should tune enabled enrichment providers and capacities to their available internal memory.

## API overview

`ScoutIpv4Address::value` uses lwIP network byte order. Public zero-allocation
`scoutFormatIpv4()`, `scoutFormatIpv6()`, and `scoutFormatMac()` helpers format Scout address
types into caller-owned buffers without Arduino `String` allocation. Observation timestamps
(`*AtMs`) are monotonic milliseconds since boot from `esp_timer_get_time()`, not Unix timestamps;
zero means no active confirmation where applicable. A valid MAC absent from the registry returns
`ScoutStatus::NotFound`.

```cpp
ScoutConfig config;
config.scanIntervalMs = 60'000;
config.deviceMaxAgeMs = 5 * 60'000ULL;
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
| `WiFiDiscovery` | Connect a Wi-Fi-capable ESP32 and perform a real discovery scan after setting credentials. |
| `Basic` | Initialize Scout with an interface already started by the application. |
| `Events` | Observe scan, device, coverage, and error events. |
| `Registry` | Enumerate the device registry, inspect endpoints, and look up a device by MAC address. |
| `ManualScan` | Disable the initial scan and explicitly request non-blocking scans with `scanNow()`. |
| `Diagnostics` | Inspect scan counters, ARP statistics, memory placement, and task-stack diagnostics. |
| `MultiInterface` | Inspect devices observed through multiple eligible ESP-NETIF interfaces. |
| `EnrichedDiscovery` | Inspect preferred names, vendor/manufacturer/model data and discovered services. |
| `IdentityGroups` | Inspect strong physical-device groups and their MAC-level members. |
| `NetworkDeviceManagerStyle` | Project Scout data into the simple fields a non-technical device UI would consume. |

For a first scan on a Wi-Fi-capable board, set the credentials in `examples/WiFiDiscovery/WiFiDiscovery.ino` and start with:

```txt
examples/WiFiDiscovery
```

The other sketches expect the application to start a Wi-Fi or Ethernet interface before Scout scans.

## Testing

Scout includes host-side regression tests for platform-independent discovery logic and runtime lifecycle behavior. The suite covers IPv4 target generation, registry aging and deduplication, endpoint reassignment, terminal scan events, callback destruction, public configuration defaults, and bounded endpoint handling.

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
| [`docs/enrichment.md`](docs/enrichment.md) | ICMP, mDNS, SSDP/UPnP, OUI, NBNS, DNS and metadata freshness. |
| [`docs/identity.md`](docs/identity.md) | Physical-device relations, confidence and non-destructive grouping. |

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
