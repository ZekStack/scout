#include "ScoutLogic.h"

#include <cstring>

namespace scout_internal {

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
	const uint64_t span =
	    static_cast<uint64_t>(broadcast) - static_cast<uint64_t>(network);

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
	return right != nullptr &&
	       std::memcmp(left.bytes, right, sizeof(left.bytes)) == 0;
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
    uint32_t ipv4,
    uint64_t observedAt
) {
	for (size_t i = 0; i < device.endpointCount; ++i) {
		auto &endpoint = device.endpoints[i];
		if (endpoint.interfaceIndex == interfaceIndex && endpoint.ipv4.value == ipv4) {
			endpoint.lastSeenAtMs = observedAt;
			return false;
		}
	}

	size_t targetIndex = device.endpointCount;
	if (targetIndex >= SCOUT_MAX_ENDPOINTS_PER_DEVICE) {
		targetIndex = 0;
		for (size_t i = 1; i < device.endpointCount; ++i) {
			if (device.endpoints[i].lastSeenAtMs <
			    device.endpoints[targetIndex].lastSeenAtMs) {
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
	endpoint.lastSeenAtMs = observedAt;
	if (interfaceName != nullptr) {
		std::strncpy(
		    endpoint.interfaceName,
		    interfaceName,
		    sizeof(endpoint.interfaceName) - 1
		);
		endpoint.interfaceName[sizeof(endpoint.interfaceName) - 1] = '\0';
	}

	return true;
}

} // namespace scout_internal
