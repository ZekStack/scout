#pragma once

#include <cstddef>
#include <cstdint>

#include <esp_err.h>

namespace scout_internal {

constexpr size_t MaxInterfaces = 8;
constexpr size_t InterfaceNameSize = 8;

struct InterfaceSnapshot {
	uint8_t index = 0;
	char name[InterfaceNameSize] = {0};
	uint32_t ipv4 = 0;
	uint32_t netmask = 0;
};

struct ArpMapping {
	bool found = false;
	uint8_t mac[6] = {0, 0, 0, 0, 0, 0};
};

struct ArpRequestStats {
	size_t sent = 0;
	size_t failed = 0;
};

esp_err_t collectInterfaces(
    InterfaceSnapshot *out,
    size_t capacity,
    size_t &count
);

esp_err_t lookupArpMappings(
    uint8_t interfaceIndex,
    const uint32_t *ipv4Addresses,
    size_t count,
    ArpMapping *out
);

esp_err_t requestArp(
    uint8_t interfaceIndex,
    const uint32_t *ipv4Addresses,
    size_t count,
    ArpRequestStats &stats
);

size_t recommendedArpBatchSize(size_t requested);

} // namespace scout_internal
