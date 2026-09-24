# Device enrichment

Scout keeps the MAC-address registry as the network truth and enriches those records with
information obtained from independent providers. Enrichment never changes the MAC key and
never turns a metadata observation into application-level online/offline state.

## Providers

The default provider set is intentionally useful on a PSRAM-equipped ESP32:

| Provider | Default | Purpose |
| --- | --- | --- |
| ARP | enabled | Discover directly connected IPv4 endpoints and their MAC addresses. |
| ICMP | enabled | Actively confirm already-known IPv4 endpoints. |
| mDNS / DNS-SD | enabled | Learn hostnames, friendly instance names, services, TXT metadata and IPv6 aliases. |
| SSDP / UPnP | enabled | Learn friendly names, manufacturer/model data and stable UDN identifiers. |
| OUI | enabled when a resolver is supplied | Resolve a globally administered MAC prefix to a vendor. |
| NBNS | disabled | Enrich legacy Windows/NAS devices with a NetBIOS name. |
| reverse DNS | disabled | Opportunistically learn a resolver-provided hostname. |

Providers have independent schedules. Bounded providers use persistent cursors so per-run work
budgets rotate across targets/service types instead of permanently favoring the first entries. A
large registry therefore does not imply that all network protocols are run during every ARP sweep.

For scalar details that multiple providers can report, Scout uses deterministic source precedence
instead of last-writer-wins updates. SSDP/UPnP outranks mDNS for manufacturer/model-style fields,
while observations from the same source continue to refresh or update their own values. mDNS
record retention also covers a complete bounded service-query rotation (with one scheduling
interval of headroom, bounded by `fallbackMaxAgeMs`) so short DNS-SD TTLs do not make names and
services flap merely because Scout intentionally rotates service types. This retention is metadata
only and never keeps a MAC identity online.

## PSRAM-first bounds

Scout deliberately exposes generous bounded snapshot capacities so a NetworkDeviceManager can
keep rich information without immediately having to tune every field. The compact MAC registry
is preallocated, while each large `ScoutDeviceDetails` record is allocated lazily only after a
device actually receives enrichment data:

- 128 MAC identities;
- 16 IPv4/interface endpoints per identity;
- 8 IPv6 aliases per endpoint;
- 16 names per device;
- 48 services per device;
- 96 metadata entries per device;
- 512 identity relations.

The device registry, lazily created rich detail records, provider target buffer, identity tables
and UPnP HTTP scratch buffer all use the configured Strata allocation placement. The default
remains `Strata::Placement::PreferExternal`. If a rich-details allocation fails, the MAC-level
registry remains valid and Scout records an enrichment allocation failure instead of failing the
whole runtime.

These are storage bounds, not work budgets. Providers separately limit work performed per
run so a large registry does not monopolize the Scout task.

## Rich details

`ScoutDeviceInfo` intentionally remains the compact observation snapshot used by events.
Large metadata lives in `ScoutDeviceDetails` and is queried explicitly:

```cpp
ScoutDeviceInfo info;
ScoutDeviceDetails details;

if (scout.deviceAt(index, info) && scout.deviceDetailsAt(index, details)) {
    // info: MAC, endpoints, timestamps, source masks
    // details: names, services, metadata, manufacturer/model and identity hints
}
```

`ScoutDeviceDetails` is intentionally large. Applications that keep a reusable details
buffer should place it in external RAM rather than on a small task stack.

## Preferred names

Scout stores multiple names with provenance instead of overwriting one protocol with another.
`preferredName()` applies the default display priority:

1. SSDP/UPnP friendly name;
2. mDNS service instance;
3. mDNS hostname;
4. NBNS name;
5. reverse-DNS name;
6. manufacturer + model;
7. vendor;
8. MAC-address fallback.

The consuming application can ignore this helper and choose its own display policy.

## mDNS ownership

The Espressif mDNS component is process-global. Scout never calls `mdns_free()`.

By default `ScoutMdnsConfig::initializeIfNeeded` is true. Calling `mdns_init()` after the
component is already initialized returns `ESP_ERR_INVALID_STATE`, which Scout treats as the
shared subsystem already being available.

Applications that own mDNS lifecycle themselves can set:

```cpp
config.providers.mdns.initializeIfNeeded = false;
```

When an Arduino application also advertises its own hostname through `MDNS.begin()`, start
that responder before Scout or disable Scout's automatic initialization.

## mDNS and IPv6

Scout correlates mDNS results to an existing MAC identity through a known IPv4 endpoint and
its ESP-NETIF. Provider results are accepted only while that exact `(interface, IPv4)` endpoint
still belongs to the target MAC; delayed results from a reassigned address are discarded and
counted in `staleProviderObservations`. IPv6 addresses returned in that same result are retained
as endpoint aliases.

This first IPv6 slice deliberately does not inspect private lwIP neighbour tables and does not
perform an active IPv6 neighbour sweep. IPv6-only discovery can be added later when there is
an acceptable public API path.

## SSDP and UPnP

SSDP discovery uses a normal UDP `M-SEARCH` on each local IPv4 interface. Scout records
`USN`, `SERVER`, `ST`, `LOCATION` and cache lifetime metadata.

When enabled, Scout fetches a bounded number of plain-HTTP UPnP device descriptions and
extracts only the fields useful to a user-facing device manager:

- friendly name;
- manufacturer;
- model name and number;
- serial number;
- UDN;
- device type.

The response body is bounded by `maxDescriptionBytes`; Scout does not retain arbitrary XML.
Description TCP sockets are bound to the same local IPv4 interface that received the SSDP
advertisement. Within one SSDP run, duplicate `LOCATION` values are deduplicated per interface,
so repeated advertisements from one device cannot consume the whole description-fetch budget
without collapsing identical private addresses that exist on different local networks.

## OUI vendor lookup

Scout does not ship a frozen IEEE database. Instead, applications can provide a generated
or application-owned table through one callback:

```cpp
scout.setOuiLookup([](const ScoutMacAddress &mac, ScoutVendorInfo &vendor) {
    // Look up mac.bytes[0..2] in an application-owned table.
    // Return true only for a known prefix.
    return false;
});
```

Scout automatically suppresses OUI lookup for multicast and locally administered/randomized
MAC addresses, where the prefix is not reliable vendor evidence.

## Metadata freshness

Names, services and generic metadata carry first-seen, last-seen and expiry timestamps.
Identity-bearing fields such as serial number, persistent device ID and UPnP UDN also retain
their provider source and expiry. mDNS uses TTL when available, SSDP uses
`CACHE-CONTROL: max-age`, and providers have fallback retention values.

Expiry removes only the stale enrichment item. It does not remove the underlying MAC record
and does not declare the device offline. Enrichment expiry is polled independently of the ARP
scan interval, so short DNS/mDNS/SSDP lifetimes do not remain valid until the next subnet sweep.
Expiring strong identity evidence immediately marks the identity graph dirty so stale
Strong/Certain groups are removed.

ARP observations alone advance registry-retention `lastSeenAtMs`. ICMP can advance
`lastConfirmedAtMs`, while mDNS, SSDP, NBNS and reverse DNS enrich the currently ARP-owned
endpoint without extending the MAC record's retention lifetime.

## Reverse DNS

Reverse DNS does not use libc `getnameinfo()`. Scout builds an IPv4 PTR query directly, selects
the DNS server configured for the endpoint's ESP-NETIF, binds the UDP socket to that interface's
local IPv4 address, and enforces `ScoutReverseDnsConfig::timeoutMs` through socket timeouts.

The DNS codec validates transaction IDs, response codes, record bounds and compressed DNS names.
PTR TTL controls the learned name lifetime; `maxAgeMs` is only a fallback when the response TTL
is zero. NXDOMAIN/no-PTR, timeout, malformed reply, server failure and network failure are counted
separately in provider diagnostics.

## Change events

`DeviceChanged` includes a `changes` mask with any combination of:

- `Endpoint`
- `Name`
- `Service`
- `Metadata`
- `Vendor`
- `Identity`
- `Confirmation`
- `Address`

A higher-level manager can therefore update only the user-facing fields that changed.
