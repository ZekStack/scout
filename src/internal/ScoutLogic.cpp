#include "ScoutLogic.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace scout_internal {
namespace {

void copyBounded(char *destination, size_t capacity, const char *source) {
	if (destination == nullptr || capacity == 0) {
		return;
	}
	destination[0] = '\0';
	if (source == nullptr) {
		return;
	}
	std::strncpy(destination, source, capacity - 1);
	destination[capacity - 1] = '\0';
}

bool mergeIpv6(ScoutEndpoint &target, const ScoutIpv6Address &address) {
	if (!address.valid()) {
		return false;
	}
	for (size_t i = 0; i < target.ipv6Count; ++i) {
		if (target.ipv6[i] == address) {
			return false;
		}
	}
	if (target.ipv6Count >= SCOUT_MAX_IPV6_PER_ENDPOINT) {
		return false;
	}
	target.ipv6[target.ipv6Count++] = address;
	return true;
}

ScoutEndpoint *findEndpoint(ScoutDeviceInfo &device, uint8_t interfaceIndex, uint32_t ipv4) {
	for (size_t i = 0; i < device.endpointCount; ++i) {
		if (device.endpoints[i].interfaceIndex == interfaceIndex &&
		    device.endpoints[i].ipv4.value == ipv4) {
			return &device.endpoints[i];
		}
	}
	return nullptr;
}

} // namespace

Ipv4TargetResult buildIpv4Targets(
    uint32_t ipv4HostOrder,
    uint32_t netmaskHostOrder,
    size_t maxHostsPerSubnet,
    uint32_t *out,
    size_t capacity
) {
	if (maxHostsPerSubnet == 0) {
		return {Ipv4TargetStatus::InvalidArgument, 0};
	}

	const uint32_t network = ipv4HostOrder & netmaskHostOrder;
	const uint32_t broadcast = network | ~netmaskHostOrder;
	const uint64_t span = static_cast<uint64_t>(broadcast) - static_cast<uint64_t>(network);

	if (span <= 1ULL) {
		return {Ipv4TargetStatus::Ok, 0};
	}

	const uint64_t hostCount = span - 1ULL;
	if (hostCount > maxHostsPerSubnet || hostCount > capacity) {
		return {Ipv4TargetStatus::TooLarge, 0};
	}
	if (out == nullptr) {
		return {Ipv4TargetStatus::InvalidArgument, 0};
	}

	size_t count = 0;
	for (uint32_t current = network + 1U; current < broadcast; ++current) {
		if (current == ipv4HostOrder) {
			continue;
		}
		out[count++] = current;
	}

	return {Ipv4TargetStatus::Ok, count};
}

bool macEquals(const uint8_t *left, const uint8_t *right) {
	return left != nullptr && right != nullptr && std::memcmp(left, right, 6) == 0;
}

bool macEquals(const ScoutMacAddress &left, const uint8_t *right) {
	return right != nullptr && std::memcmp(left.bytes, right, sizeof(left.bytes)) == 0;
}

ScoutMacAddress macFromBytes(const uint8_t *bytes) {
	ScoutMacAddress mac;
	if (bytes != nullptr) {
		std::memcpy(mac.bytes, bytes, sizeof(mac.bytes));
	}
	return mac;
}

bool upsertEndpoint(
    ScoutDeviceInfo &device,
    uint8_t interfaceIndex,
    const char *interfaceName,
    const char *interfaceKey,
    ScoutInterfaceType interfaceType,
    uint32_t ipv4,
    uint64_t observedAt,
    ScoutObservationSource source,
    bool confirmed,
    bool *replaced
) {
	if (replaced != nullptr) {
		*replaced = false;
	}
	for (size_t i = 0; i < device.endpointCount; ++i) {
		auto &endpoint = device.endpoints[i];
		if (endpoint.interfaceIndex != interfaceIndex || endpoint.ipv4.value != ipv4) {
			continue;
		}

		const bool metadataChanged =
		    endpoint.interfaceType != interfaceType ||
		    (interfaceName != nullptr &&
		     std::strncmp(endpoint.interfaceName, interfaceName, sizeof(endpoint.interfaceName)) !=
		         0) ||
		    (interfaceKey != nullptr &&
		     std::strncmp(endpoint.interfaceKey, interfaceKey, sizeof(endpoint.interfaceKey)) != 0);
		endpoint.lastSeenAtMs = std::max(endpoint.lastSeenAtMs, observedAt);
		if (endpoint.firstSeenAtMs == 0) {
			endpoint.firstSeenAtMs = observedAt;
		}
		if (confirmed) {
			endpoint.lastConfirmedAtMs = std::max(endpoint.lastConfirmedAtMs, observedAt);
		}
		endpoint.observationSources |= scoutObservationMask(source);
		endpoint.interfaceType = interfaceType;
		copyBounded(endpoint.interfaceName, sizeof(endpoint.interfaceName), interfaceName);
		copyBounded(endpoint.interfaceKey, sizeof(endpoint.interfaceKey), interfaceKey);
		return metadataChanged;
	}

	size_t targetIndex = device.endpointCount;
	if (targetIndex >= SCOUT_MAX_ENDPOINTS_PER_DEVICE) {
		if (replaced != nullptr) {
			*replaced = true;
		}
		targetIndex = 0;
		for (size_t i = 1; i < device.endpointCount; ++i) {
			if (device.endpoints[i].lastSeenAtMs < device.endpoints[targetIndex].lastSeenAtMs) {
				targetIndex = i;
			}
		}
	} else {
		device.endpointCount++;
	}

	auto &endpoint = device.endpoints[targetIndex];
	endpoint = {};
	endpoint.ipv4.value = ipv4;
	endpoint.interfaceIndex = interfaceIndex;
	endpoint.interfaceType = interfaceType;
	endpoint.firstSeenAtMs = observedAt;
	endpoint.lastSeenAtMs = observedAt;
	endpoint.lastConfirmedAtMs = confirmed ? observedAt : 0;
	endpoint.observationSources = scoutObservationMask(source);
	copyBounded(endpoint.interfaceName, sizeof(endpoint.interfaceName), interfaceName);
	copyBounded(endpoint.interfaceKey, sizeof(endpoint.interfaceKey), interfaceKey);
	return true;
}

bool removeEndpoint(ScoutDeviceInfo &device, uint8_t interfaceIndex, uint32_t ipv4) {
	for (size_t i = 0; i < device.endpointCount; ++i) {
		const auto &endpoint = device.endpoints[i];
		if (endpoint.interfaceIndex != interfaceIndex || endpoint.ipv4.value != ipv4) {
			continue;
		}

		for (size_t j = i + 1; j < device.endpointCount; ++j) {
			device.endpoints[j - 1] = device.endpoints[j];
		}
		device.endpointCount--;
		device.endpoints[device.endpointCount] = {};
		return true;
	}
	return false;
}

bool deviceExpired(const ScoutDeviceInfo &device, uint64_t now, uint64_t maxAgeMs) {
	return maxAgeMs > 0 && now >= device.lastSeenAtMs && now - device.lastSeenAtMs >= maxAgeMs;
}

void mergeDeviceInfo(ScoutDeviceInfo &target, const ScoutDeviceInfo &source) {
	if (target.firstSeenAtMs == 0 ||
	    (source.firstSeenAtMs != 0 && source.firstSeenAtMs < target.firstSeenAtMs)) {
		target.firstSeenAtMs = source.firstSeenAtMs;
	}
	target.lastSeenAtMs = std::max(target.lastSeenAtMs, source.lastSeenAtMs);
	target.lastConfirmedAtMs = std::max(target.lastConfirmedAtMs, source.lastConfirmedAtMs);
	target.observationSources |= source.observationSources;

	const uint32_t remaining = std::numeric_limits<uint32_t>::max() - target.observationCount;
	target.observationCount += std::min(remaining, source.observationCount);

	for (size_t i = 0; i < source.endpointCount; ++i) {
		const auto &sourceEndpoint = source.endpoints[i];
		(void)upsertEndpoint(
		    target,
		    sourceEndpoint.interfaceIndex,
		    sourceEndpoint.interfaceName,
		    sourceEndpoint.interfaceKey,
		    sourceEndpoint.interfaceType,
		    sourceEndpoint.ipv4.value,
		    sourceEndpoint.lastSeenAtMs,
		    static_cast<ScoutObservationSource>(sourceEndpoint.observationSources),
		    false
		);
		auto *targetEndpoint =
		    findEndpoint(target, sourceEndpoint.interfaceIndex, sourceEndpoint.ipv4.value);
		if (targetEndpoint == nullptr) {
			continue;
		}
		if (targetEndpoint->firstSeenAtMs == 0 ||
		    (sourceEndpoint.firstSeenAtMs != 0 &&
		     sourceEndpoint.firstSeenAtMs < targetEndpoint->firstSeenAtMs)) {
			targetEndpoint->firstSeenAtMs = sourceEndpoint.firstSeenAtMs;
		}
		targetEndpoint->lastSeenAtMs =
		    std::max(targetEndpoint->lastSeenAtMs, sourceEndpoint.lastSeenAtMs);
		targetEndpoint->lastConfirmedAtMs =
		    std::max(targetEndpoint->lastConfirmedAtMs, sourceEndpoint.lastConfirmedAtMs);
		targetEndpoint->observationSources |= sourceEndpoint.observationSources;
		for (size_t ipv6Index = 0; ipv6Index < sourceEndpoint.ipv6Count; ++ipv6Index) {
			mergeIpv6(*targetEndpoint, sourceEndpoint.ipv6[ipv6Index]);
		}
	}
}

} // namespace scout_internal
