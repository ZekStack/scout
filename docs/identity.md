# Physical-device identity

Scout distinguishes a network identity from a physical device.

A MAC address remains one `ScoutDeviceInfo`. Ethernet and Wi-Fi adapters with different
MAC addresses are never destructively merged, even when Scout has evidence that they belong
to the same physical product.

## Relations

Scout evaluates pairs of MAC identities and exposes `ScoutIdentityRelation` evidence.

Evidence classes currently include:

- UPnP UDN;
- persistent device identifiers learned from trusted mDNS TXT keys;
- shared serial number from the same manufacturer;
- mDNS hostname;
- service fingerprint;
- manufacturer/model similarity.

Confidence is deliberately conservative:

| Evidence | Confidence | Automatic grouping |
| --- | --- | --- |
| same UPnP UDN | Certain | yes |
| same trusted, service-namespaced mDNS persistent ID | Strong | yes |
| same UPnP serial + manufacturer | Strong | yes |
| same mDNS hostname | Moderate | no |
| same service fingerprint | Moderate | no |
| same manufacturer + model | Weak | no |

A matching hostname by itself is useful context but not proof of one physical device.
Generic TXT keys such as `deviceid` are retained as metadata but are not promoted to Strong
identity evidence. Scout currently recognises protocol-specific `id` semantics for selected
services such as Google Cast and HAP, and records the DNS-SD service/protocol namespace alongside
the identifier. Equal identifier text from different namespaces therefore does not create a group.

## Contradictions

Strong identifiers also act as vetoes. For example, two identities are not related through
a shared hostname when they advertise different non-empty UDNs, different persistent device
IDs within the same identity namespace, or conflicting trusted UPnP serial numbers from the same
manufacturer.

Provider-derived strong identifiers are time-bounded evidence. Their source TTL/max-age is
retained with the field, and expiry removes the evidence and rebuilds the relation/group view.
A device therefore cannot remain in a Strong/Certain group indefinitely because of a stale
UPnP UDN, persistent mDNS ID, or serial observation.

This prevents friendly-name coincidences from corrupting physical-device identity.

## Groups

Only Strong or Certain relations participate in `ScoutIdentityGroup` construction.
Groups are additive views over the MAC registry:

```text
ScoutDeviceInfo (Wi-Fi MAC) -----+
                                 +--> ScoutIdentityGroup
ScoutDeviceInfo (Ethernet MAC) --+
```

The original records, endpoints and timestamps remain independently queryable.

`runtimeId` is stable only for the current runtime and current member set. Scout deliberately
does not persist groups to flash. Persistent user IDs, room assignment, custom names and
online/offline policy belong in the consuming NetworkDeviceManager or application layer.

## API

```cpp
for (size_t i = 0; i < scout.identityGroupCount(); ++i) {
    ScoutIdentityGroup group;
    if (!scout.identityGroupAt(i, group)) {
        continue;
    }

    // group.members[] contains the MAC-level Scout keys.
    // group.evidence[] explains why the group was formed.
}
```

Moderate and Weak evidence remains available independently:

```cpp
for (size_t i = 0; i < scout.identityRelationCount(); ++i) {
    ScoutIdentityRelation relation;
    scout.identityRelationAt(i, relation);
}
```

This allows a UI or diagnostics layer to explain likely relationships without Scout silently
merging uncertain identities.
