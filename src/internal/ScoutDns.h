#pragma once

#include <cstddef>
#include <cstdint>

namespace scout_internal {

enum class DnsParseStatus : uint8_t {
	Ok,
	NoRecord,
	Timeout,
	NetworkError,
	ResolverUnavailable,
	Malformed,
	ServerError,
};

struct DnsPtrAnswer {
	DnsParseStatus status = DnsParseStatus::Malformed;
	char hostname[96] = {};
	uint32_t ttlSeconds = 0;
};

constexpr size_t DnsMaxARecords = 4;

struct DnsAAnswer {
	DnsParseStatus status = DnsParseStatus::Malformed;
	uint32_t addresses[DnsMaxARecords] = {};
	size_t addressCount = 0;
	uint32_t ttlSeconds = 0;
};

size_t buildAQuery(
    uint16_t transactionId, const char *hostname, uint8_t *out, size_t capacity
);
DnsAAnswer parseAResponse(
    const uint8_t *data,
    size_t length,
    uint16_t transactionId,
    const char *expectedHostname
);

size_t buildPtrQuery(uint16_t transactionId, const uint8_t ipv4[4], uint8_t *out, size_t capacity);

DnsPtrAnswer parsePtrResponse(
    const uint8_t *data,
    size_t length,
    uint16_t transactionId,
    const uint8_t expectedIpv4[4] = nullptr
);

} // namespace scout_internal
