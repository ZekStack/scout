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

Providers have independent schedules. A large PSRAM registry therefore does not imply that
all network protocols are run during every ARP sweep.

## PSRAM-first bounds

Scout deliberately starts with generous fixed capacities so a NetworkDeviceManager can keep
rich information without immediately having to tune every field:

- 128 MAC identities;
- 16 IPv4/interface endpoints per identity;
- 8 IPv6 aliases per endpoint;
- 16 names per device;
- 48 services per device;
- 96 metadata entries per device;
- 512 identity relations.

The device registry, rich detail records, provider target buffer, identity tables and UPnP
HTTP scratch buffer all use the configured Strata allocation placement. The default remains
`Strata::Placement::PreferExternal`.

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
its ESP-NETIF. IPv6 addresses returned in that same result are retained as endpoint aliases.

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
mDNS uses TTL when available, SSDP uses `CACHE-CONTROL: max-age`, and providers have
fallback retention values.

Expiry removes only the stale enrichment item. It does not remove the underlying MAC record
and does not declare the device offline.

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
