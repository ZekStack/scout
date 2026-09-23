#pragma once

#include "../Scout.h"

#include <cstddef>
#include <cstdint>

namespace scout_internal {

enum class Ipv4TargetStatus : uint8_t {
	Ok,
	TooLarge,
	InvalidArgument,
};

struct Ipv4TargetResult {
	Ipv4TargetStatus status = Ipv4TargetStatus::Ok;
	size_t count = 0;
};

Ipv4TargetResult buildIpv4Targets(
    uint32_t ipv4HostOrder,
    uint32_t netmaskHostOrder,
    size_t maxHostsPerSubnet,
    uint32_t *out,
    size_t capacity
);

bool macEquals(const uint8_t *left, const uint8_t *right);
bool macEquals(const ScoutMacAddress &left, const uint8_t *right);
ScoutMacAddress macFromBytes(const uint8_t *bytes);

bool upsertEndpoint(
    ScoutDeviceInfo &device,
    uint8_t interfaceIndex,
    const char *interfaceName,
    uint32_t ipv4,
    uint64_t observedAt
);

bool removeEndpoint(ScoutDeviceInfo &device, uint8_t interfaceIndex, uint32_t ipv4);

bool deviceExpired(const ScoutDeviceInfo &device, uint64_t now, uint64_t maxAgeMs);

void mergeDeviceInfo(ScoutDeviceInfo &target, const ScoutDeviceInfo &source);

} // namespace scout_internal
