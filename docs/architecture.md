# Architecture

Scout is a low-level discovery and observation service. It is intentionally not a presence engine.

The intended application stack is:

~~~text
Scout
  -> raw network observations
Presence/application layer
  -> Unknown / Online / Offline and stateSince
Signal/event bus
  -> automation triggers
Automation engine
~~~

Scout answers: what devices and endpoints have been observed, by which mechanism, and when?

The consuming application decides how many missed confirmations imply offline, how long a state must persist, whether startup/reconnect grace applies, and which events enter an automation system.

## Runtime ownership

Scout owns one long-lived FreeRTOS task through Strata::FreeRTOS::Task.

The task owns scanning and registry mutation. Public snapshot queries are protected with a Strata recursive mutex. Shutdown is cooperative: deinit requests stop, waits for the Scout task to reach its external-deletion handoff, and then resets the Strata task from the caller context.

Callbacks are never invoked while the Scout registry mutex is held.

## Network threading

BSD sockets are generally safe from normal application tasks, but direct lwIP core APIs are not assumed to be thread-safe.

Scout therefore dispatches ARP operations through esp_netif_tcpip_exec. The callback runs in the TCP/IP context and uses public lwIP operations such as etharp_request and etharp_find_addr. Pointers returned by lwIP are copied inside that callback and never retained by Scout.

Scout also re-resolves the lwIP interface by index for each TCP/IP-context operation rather than retaining a struct netif pointer across task boundaries.

## Device identity

ARP discovery uses the MAC address as the stable registry key.

A device may expose several endpoints. Each endpoint contains an IPv4 address and lwIP interface index/name. This lets an ESP32 with simultaneous Ethernet and Wi-Fi observe the same MAC from more than one interface without duplicating the device record.

The public identity enum already reserves ProvisionalIpv4 for future mechanisms that can discover an IP address before a MAC address is known.

## Coverage

Scout treats scanner visibility as first-class state.

If no up, link-up, ARP-capable IPv4 interface exists, Scout emits CoverageLost. When such an interface becomes available again, it emits CoverageRestored.

A higher-level presence implementation should suppress offline inference while coverage is unavailable and revalidate devices after coverage returns.

## Bounded resources

The v0.1 foundation uses fixed-capacity Strata-backed buffers allocated during init:

- device registry;
- subnet target buffer;
- ARP-before scratch buffer;
- ARP-after scratch buffer.

A subnet larger than maxHostsPerSubnet is skipped instead of allowing an accidental /16 or /8 sweep.
