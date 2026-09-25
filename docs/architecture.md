# Architecture

Scout is a low-level discovery and observation service. It is intentionally not a presence engine.

The intended application stack is:

~~~text
ARP / ICMP / mDNS / SSDP / optional name providers
  -> Scout MAC registry + rich enrichment + identity evidence
NetworkDeviceManager / presence layer
  -> friendly presentation, persistent IDs, Unknown / Online / Offline
Signal/event bus
  -> automation triggers
Automation engine
~~~

Scout answers: what devices and endpoints have been observed, by which mechanism, and when?

The consuming application decides how many missed confirmations imply offline, how long a state must persist, whether startup/reconnect grace applies, and which events enter an automation system.

## Runtime ownership

Scout supports two execution modes with the same discovery and registry semantics.

In `ScoutExecutionMode::BackgroundTask`, Scout owns one long-lived scheduler task through
`Strata::FreeRTOS::Task`. That task performs scans, provider work, registry mutation and event
delivery.

In `ScoutExecutionMode::CallerDriven`, Scout creates no scheduler task. The application calls
`process()` from the task that should own discovery work, and Scout performs scans, provider work,
registry mutation and event delivery synchronously from that caller-owned task. `scanNow()` only
queues immediate work in both modes.

Runtime publication, teardown and public snapshot queries are protected with a Strata recursive
mutex. Callbacks are never invoked while the registry mutex is held.

Background-task shutdown is cooperative: `deinit()` requests stop, waits for the Scout task to
reach its external-deletion handoff, and then resets the Strata task from the caller context. In
caller-driven mode there is no Scout scheduler task to stop; `deinit()` waits for any active
`process()` call from another task to leave Scout before releasing runtime storage, and closes an
unfinished incremental scan as cancelled.

Explicit `deinit()` from Scout's currently active processing context is rejected with
`ScoutStatus::Busy`. If a `Scout` object is destroyed from its own callback in either execution
mode, ownership of the runtime is transferred to a shared Strata-owned cleanup task so storage is
not released while the callback/process frame is still active.

## Network threading

BSD sockets are generally safe from normal application tasks, but direct lwIP core APIs are not assumed to be thread-safe.

Scout therefore dispatches ARP operations through esp_netif_tcpip_exec. The callback runs in the TCP/IP context and uses public lwIP operations such as etharp_request and etharp_find_addr. Pointers returned by lwIP are copied inside that callback and never retained by Scout.

Scout also re-resolves the lwIP interface by index for each TCP/IP-context operation rather than retaining a struct netif pointer across task boundaries.

## Device identity

ARP discovery uses the MAC address as the stable registry key.

A device may expose several endpoints. Each endpoint contains IPv4, optional IPv6 aliases, lwIP interface index/name, the stable ESP-NETIF key, interface type, timestamps and source masks. This lets simultaneous Ethernet/Wi-Fi observation remain attributable to the correct network path.

The public identity enum already reserves ProvisionalIpv4 for future mechanisms that can discover an IP address before a MAC address is known.

Registry maintenance preserves three invariants:

- one device record per MAC address;
- no duplicate endpoint inside one device;
- one current MAC owner for each `(interface, IPv4)` endpoint across the registry.

If an endpoint is later observed on another MAC, ownership moves to the new observation but the
older device record remains until its retention age expires. Enrichment providers operate from
snapshots of these endpoints and revalidate ownership before applying a delayed result, so an
IP-only response cannot attach metadata to a MAC that no longer owns the address.

## Coverage

Scout treats scanner visibility as first-class state.

Scout emits CoverageLost when no up, link-up, ARP-capable IPv4 interface exists or when any eligible interface's scan is skipped or fails. It emits CoverageRestored after every eligible interface completes a scan successfully. Coverage is conservative across multiple interfaces so a presence layer does not infer absence on an unscanned network.

A higher-level presence implementation should suppress offline inference while coverage is unavailable and revalidate devices after coverage returns.

## Bounded resources

The v0.1 foundation uses bounded Strata-backed storage. The compact device registry, subnet
targets, provider/identity tables and ARP scratch buffers are allocated during init. Large
`ScoutDeviceDetails` records are allocated lazily per enriched device, which keeps the configured
MAC capacity independent from worst-case metadata storage.

A subnet larger than maxHostsPerSubnet is skipped instead of allowing an accidental /16 or /8 sweep.

Device records are also time-bounded. `deviceMaxAgeMs` removes records that have not been observed recently enough according to `lastSeenAtMs`. This is registry housekeeping only; it does not define application-level Online/Offline state.

## Enrichment and identity

Heavy names, services and metadata live outside the compact event snapshot in lazily created
`ScoutDeviceDetails`. Providers run on independent schedules and feed normalized observations
back through Scout's synchronized registry path. Bounded providers rotate persistent cursors
across their work sets so a per-run budget cannot permanently starve later targets. Continuations
carry the registry-topology generation that created them; endpoint/device changes invalidate and
restart positional runs rather than resuming an old cursor against reordered data.

Strong identifiers such as a shared UPnP UDN can create a `ScoutIdentityGroup`; moderate
evidence such as a matching mDNS hostname is retained only as a relation. Provider-derived
identity fields retain their source lifetime, and expiry runs independently from the ARP scan
cadence before rebuilding the identity graph so stale evidence cannot preserve a physical-device
group. Strong mDNS identifiers are service-namespaced; generic TXT coincidences remain metadata or
moderate evidence. MAC records are never merged solely to make a friendlier physical-device view.

See [`enrichment.md`](enrichment.md) and [`identity.md`](identity.md) for the detailed contracts.
