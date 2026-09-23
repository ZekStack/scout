# Discovery

## ARP foundation

Scout v0.1 starts with active IPv4 ARP discovery.

For each eligible interface Scout:

1. reads the interface IPv4 address and netmask in the lwIP TCP/IP context;
2. calculates usable hosts in the local subnet;
3. rejects the subnet when it exceeds maxHostsPerSubnet;
4. processes hosts in small ARP-table-aware batches;
5. reads existing public ARP mappings;
6. sends etharp_request for the batch;
7. waits for arpResponseWaitMs;
8. reads the public mapping again with etharp_find_addr;
9. merges discovered MAC/IP/interface endpoints into the registry.

The batch size is clamped to the configured lwIP ARP-table size to avoid attempting an unbounded burst against a small cache.

## Cache versus confirmed observation

ARP has an important limitation: a stable mapping can already exist before Scout sends a request. Public etharp_find_addr exposes the mapping but not enough entry age/state detail to prove that the current request received a fresh reply.

Scout therefore distinguishes:

- ArpCache: the same stable mapping existed before the request;
- ArpProbe: the mapping was absent before the request, or changed during the probe window.

Only ArpProbe updates lastConfirmedAtMs in the current implementation.

This prevents Scout from pretending that an old ARP cache entry is a fresh liveness response.

## Continuous scanning

The default scan interval is 60 seconds. scanNow schedules an immediate scan and returns without waiting for the subnet sweep to complete.

A dedicated Scout task performs the scan. ARP batches use bounded waits, check the shutdown request between batches, and yield between batches. An interface with no ARP targets or a subnet larger than `maxHostsPerSubnet` emits `ScanSkipped`; an ARP operation failure emits `Error`. Every `ScanStarted` has exactly one terminal `ScanCompleted` with the same `scanId`. Shutdown interruption completes with `Cancelled`. The final status is otherwise non-OK if any interface was skipped or failed, and only fully successful sweeps increment `completedScanCount`. Coverage is updated after the sweep, so `CoverageRestored` follows the observations that established it.

## Registry retention

Before each scan, Scout normalizes duplicate registry state and removes records older than `deviceMaxAgeMs` according to `lastSeenAtMs`. Each removal emits `DeviceExpired` with the final snapshot. The default retention age is five minutes.

Expiry is deliberately not based on `lastConfirmedAtMs`: registry retention asks whether Scout has observed a device at all, while stronger presence semantics belong to the consumer.

MAC identity is never deduplicated using IPv4 alone. A reused `(interface, IPv4)` endpoint is transferred to the most recently observed MAC so stale address ownership cannot remain duplicated in the registry.

## Planned observation providers

The registry and source mask are designed to accept additional providers without redefining application-level presence:

- ICMP echo for stronger active liveness confirmation;
- mDNS/DNS-SD for hostnames and services;
- SSDP/UPnP discovery metadata;
- optional NBNS enrichment.

Port scanning and heuristic device-type classification are not part of the initial scope.
