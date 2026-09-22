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

A dedicated Scout task performs the scan. ARP batches use bounded waits, check the shutdown request between batches, and yield between batches.

## Planned observation providers

The registry and source mask are designed to accept additional providers without redefining application-level presence:

- ICMP echo for stronger active liveness confirmation;
- mDNS/DNS-SD for hostnames and services;
- SSDP/UPnP discovery metadata;
- optional NBNS enrichment.

Port scanning and heuristic device-type classification are not part of the initial scope.
