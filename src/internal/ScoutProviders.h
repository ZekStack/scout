#pragma once

#include "../Scout.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace scout_internal {

constexpr size_t ProviderObservationMetadataCapacity = 16;

struct ProviderTarget {
	ScoutMacAddress mac{};
	ScoutIpv4Address ipv4{};
	uint8_t interfaceIndex = 0;
	char interfaceKey[SCOUT_INTERFACE_KEY_SIZE] = {};
};

struct EnrichmentObservation {
	ScoutObservationSource source = ScoutObservationSource::None;
	ScoutIpv4Address ipv4{};
	uint8_t interfaceIndex = 0;
	char interfaceKey[SCOUT_INTERFACE_KEY_SIZE] = {};
	bool confirmed = false;

	ScoutDeviceName names[2]{};
	size_t nameCount = 0;

	bool hasService = false;
	ScoutServiceInfo service{};

	ScoutMetadataEntry metadata[ProviderObservationMetadataCapacity]{};
	size_t metadataCount = 0;

	ScoutIpv6Address ipv6[SCOUT_MAX_IPV6_PER_ENDPOINT]{};
	size_t ipv6Count = 0;

	char manufacturer[SCOUT_MANUFACTURER_SIZE] = {};
	char modelName[SCOUT_MODEL_SIZE] = {};
	char modelNumber[SCOUT_MODEL_SIZE] = {};
	char serialNumber[SCOUT_SERIAL_SIZE] = {};
	char persistentDeviceId[SCOUT_PERSISTENT_ID_SIZE] = {};
	char persistentDeviceNamespace[SCOUT_PERSISTENT_NAMESPACE_SIZE] = {};
	char upnpUdn[SCOUT_UPNP_UDN_SIZE] = {};
	uint64_t identityExpiresAtMs = 0;
};

struct ProviderRunStats {
	uint64_t observations = 0;
	uint64_t errors = 0;
	uint64_t transportErrors = 0;
	uint64_t descriptionErrors = 0;
	uint64_t timeouts = 0;
	uint64_t noRecords = 0;
	uint64_t malformedResponses = 0;
	uint64_t serverErrors = 0;
	uint64_t dropped = 0;
	size_t plannedUnits = 0;
	size_t workUnits = 0;
	bool budgetYielded = false;
	bool cancelled = false;
};

using EnrichmentSink =
    void (*)(const ScoutMacAddress &mac, const EnrichmentObservation &observation, void *context);

struct ProviderRunControl {
	const std::atomic<bool> *stopRequested = nullptr;
	uint64_t deadlineMs = UINT64_MAX;
};

struct SsdpProviderState {
	size_t interfaceCursor = 0;
	size_t remainingInterfaces = 0;
};

struct NbnsProviderState {
	size_t targetCursor = 0;
	size_t runStartCursor = 0;
	size_t targetLimit = 0;
	size_t interfaceCursor = 0;
	size_t targetOffset = 0;
	bool active = false;
};

ProviderRunStats runIcmpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutIcmpConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control = nullptr
);

ProviderRunStats runMdnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &serviceCursor,
    const ScoutMdnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control = nullptr
);

ProviderRunStats runSsdpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    SsdpProviderState &state,
    const ScoutSsdpConfig &config,
    char *httpScratch,
    size_t httpScratchCapacity,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control = nullptr
);

ProviderRunStats runNbnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    NbnsProviderState &state,
    const ScoutNbnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control = nullptr
);

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutReverseDnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control = nullptr
);

} // namespace scout_internal
