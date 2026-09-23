#pragma once

#include "../Scout.h"

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
	char upnpUdn[SCOUT_UPNP_UDN_SIZE] = {};
};

struct ProviderRunStats {
	uint64_t observations = 0;
	uint64_t errors = 0;
	uint64_t timeouts = 0;
	uint64_t dropped = 0;
};

using EnrichmentSink =
    void (*)(const ScoutMacAddress &mac, const EnrichmentObservation &observation, void *context);

ProviderRunStats runIcmpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutIcmpConfig &config,
    EnrichmentSink sink,
    void *context
);

ProviderRunStats runMdnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    const ScoutMdnsConfig &config,
    EnrichmentSink sink,
    void *context
);

ProviderRunStats runSsdpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    const ScoutSsdpConfig &config,
    char *httpScratch,
    size_t httpScratchCapacity,
    EnrichmentSink sink,
    void *context
);

ProviderRunStats runNbnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    const ScoutNbnsConfig &config,
    EnrichmentSink sink,
    void *context
);

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutReverseDnsConfig &config,
    EnrichmentSink sink,
    void *context
);

} // namespace scout_internal
