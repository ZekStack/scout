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

- compact device registry;
- lazily allocated rich `ScoutDeviceDetails` records;
- provider target and identity tables;
- UPnP HTTP scratch storage (configured body limit plus a bounded 4 KiB header allowance);
- subnet target buffer;
- ARP lookup scratch buffers.

The compact registry and shared scratch/table buffers are allocated during init and reused by
subsequent scans. Large rich-detail records are allocated only when a device first receives
enrichment data, so `maxDevices` does not reserve the worst-case rich payload for every slot.

## taskStack

`memory.taskStack` applies only to `ScoutExecutionMode::BackgroundTask`, where Scout owns a
scheduler task. That task stack follows the configured placement policy and therefore prefers
external RAM by default.

`ScoutExecutionMode::CallerDriven` creates no Scout scheduler task, so `memory.taskStack` does
not control the application-owned task stack that calls `process()`.

Scout also has one process-lifetime deferred-cleanup task shared by all Scout instances. Its stack
is fixed to `PreferExternal` because it only exists to reclaim a Scout runtime that is destroyed
from its own callback context. Its FreeRTOS control block follows Strata's normal internal-memory
safety rule. If allocation or startup of that cleanup service fails while destruction is already
running inside Scout's callback/process frame, Scout deliberately retains the runtime for process
lifetime rather than releasing storage that is still in use.

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
- taskStackHighWaterMarkBytes;
- enrichmentAllocationFailures.

A rich-details allocation failure does not invalidate the MAC registry. Scout keeps the compact
network record and reports the failed enrichment allocation through diagnostics.
