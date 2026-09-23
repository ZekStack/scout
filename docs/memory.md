# Memory and Strata

Scout follows the shared ZekStack Strata memory-policy contract.

## Defaults

Scout defaults both policy categories to external-preferred placement:

~~~cpp
Strata::MemoryPolicy memory{
    .allocation = Strata::Placement::PreferExternal,
    .taskStack = Strata::Placement::PreferExternal,
};
~~~

The runtime object itself is also created with PreferExternal.

## allocation

The allocation policy is used for Scout-owned movable storage:

- device registry;
- subnet target buffer;
- ARP lookup scratch buffers.

These buffers are allocated once during init and reused by subsequent scans.

## taskStack

The Scout task stack uses memory.taskStack and therefore prefers external RAM by default.

## Safety constraints

Strata's safety constraints remain authoritative. FreeRTOS task control blocks and synchronization control blocks may remain internal even when Scout requests external-preferred storage.

PreferExternal is a preference, not a hard requirement. It falls back to internal memory if external memory is unavailable. Applications that require PSRAM can explicitly choose RequireExternal through ScoutConfig.

## Diagnostics

ScoutDiagnostics separates requested placement from observed region:

- allocationPlacement;
- taskStackPlacement;
- registryRegion;
- targetBufferRegion;
- taskStackRegion;
- taskStackHighWaterMarkBytes.
