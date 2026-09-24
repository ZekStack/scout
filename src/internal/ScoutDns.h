#pragma once

#include <cstddef>
#include <cstdint>

namespace scout_internal {

enum class DnsParseStatus : uint8_t {
	Ok,
	NoRecord,
	Timeout,
	NetworkError,
	Malformed,
	ServerError,
};

struct DnsPtrAnswer {
	DnsParseStatus status = DnsParseStatus::Malformed;
	char hostname[96] = {};
	uint32_t ttlSeconds = 0;
};

size_t buildPtrQuery(uint16_t transactionId, const uint8_t ipv4[4], uint8_t *out, size_t capacity);

DnsPtrAnswer parsePtrResponse(const uint8_t *data, size_t length, uint16_t transactionId);

} // namespace scout_internal
