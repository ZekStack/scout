#include "ScoutDns.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <strings.h>

namespace scout_internal {
namespace {

uint16_t read16(const uint8_t *p) {
	return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) | p[1]);
}

uint32_t read32(const uint8_t *p) {
	return (static_cast<uint32_t>(p[0]) << 24U) | (static_cast<uint32_t>(p[1]) << 16U) |
	       (static_cast<uint32_t>(p[2]) << 8U) | static_cast<uint32_t>(p[3]);
}

bool appendLabel(uint8_t *out, size_t capacity, size_t &offset, const char *label) {
	const size_t length = std::strlen(label);
	if (length == 0 || length > 63 || offset + 1 + length > capacity) {
		return false;
	}
	out[offset++] = static_cast<uint8_t>(length);
	std::memcpy(out + offset, label, length);
	offset += length;
	return true;
}

bool decodeName(
    const uint8_t *data,
    size_t length,
    size_t start,
    char *out,
    size_t outCapacity,
    size_t &consumed,
    size_t encodedEnd
) {
	if (data == nullptr || out == nullptr || outCapacity == 0 || start >= length ||
	    encodedEnd > length || start >= encodedEnd) {
		return false;
	}
	out[0] = '\0';
	consumed = 0;
	size_t cursor = start;
	size_t output = 0;
	bool jumped = false;
	size_t jumps = 0;

	for (;;) {
		if (cursor >= length || (!jumped && cursor >= encodedEnd) || jumps > 16) {
			return false;
		}
		const uint8_t label = data[cursor];
		if ((label & 0xC0U) == 0xC0U) {
			if (cursor + 1 >= length || (!jumped && cursor + 1 >= encodedEnd)) {
				return false;
			}
			const size_t pointer = (static_cast<size_t>(label & 0x3FU) << 8U) | data[cursor + 1];
			if (pointer >= length || pointer == cursor) {
				return false;
			}
			if (!jumped) {
				consumed += 2;
			}
			cursor = pointer;
			jumped = true;
			jumps++;
			continue;
		}
		if ((label & 0xC0U) != 0) {
			return false;
		}
		cursor++;
		if (!jumped) {
			consumed++;
		}
		if (label == 0) {
			break;
		}
		if (label > 63 || cursor + label > length || (!jumped && cursor + label > encodedEnd)) {
			return false;
		}
		if (output != 0) {
			if (output + 1 >= outCapacity) {
				return false;
			}
			out[output++] = '.';
		}
		if (output + label >= outCapacity) {
			return false;
		}
		std::memcpy(out + output, data + cursor, label);
		output += label;
		cursor += label;
		if (!jumped) {
			consumed += label;
		}
	}
	out[output] = '\0';
	return true;
}

} // namespace

size_t buildAQuery(
    uint16_t transactionId, const char *hostname, uint8_t *out, size_t capacity
) {
	if (hostname == nullptr || hostname[0] == '\0' || out == nullptr || capacity < 18) {
		return 0;
	}
	std::memset(out, 0, capacity);
	out[0] = static_cast<uint8_t>(transactionId >> 8U);
	out[1] = static_cast<uint8_t>(transactionId & 0xFFU);
	out[2] = 0x01;
	out[5] = 0x01;

	size_t offset = 12;
	const char *labelStart = hostname;
	for (const char *cursor = hostname;; ++cursor) {
		if (*cursor != '.' && *cursor != '\0') {
			continue;
		}
		const size_t labelLength = static_cast<size_t>(cursor - labelStart);
		if (labelLength == 0 || labelLength > 63 || offset + 1 + labelLength + 5 > capacity) {
			return 0;
		}
		char label[64]{};
		std::memcpy(label, labelStart, labelLength);
		if (!appendLabel(out, capacity, offset, label)) {
			return 0;
		}
		if (*cursor == '\0') {
			break;
		}
		labelStart = cursor + 1;
	}
	out[offset++] = 0;
	out[offset++] = 0;
	out[offset++] = 1;
	out[offset++] = 0;
	out[offset++] = 1;
	return offset;
}

DnsAAnswer parseAResponse(
    const uint8_t *data,
    size_t length,
    uint16_t transactionId,
    const char *expectedHostname
) {
	DnsAAnswer result{};
	if (data == nullptr || length < 12 || expectedHostname == nullptr ||
	    read16(data) != transactionId) {
		return result;
	}
	const uint16_t flags = read16(data + 2);
	if ((flags & 0x8000U) == 0 || (flags & 0x7800U) != 0 || (flags & 0x0200U) != 0) {
		return result;
	}
	const uint8_t rcode = static_cast<uint8_t>(flags & 0x0FU);
	if (rcode == 3) {
		result.status = DnsParseStatus::NoRecord;
		return result;
	}
	if (rcode != 0) {
		result.status = DnsParseStatus::ServerError;
		return result;
	}
	if (read16(data + 4) != 1) {
		return result;
	}

	size_t offset = 12;
	char name[256]{};
	size_t consumed = 0;
	if (!decodeName(data, length, offset, name, sizeof(name), consumed, length) ||
	    offset + consumed + 4 > length || strcasecmp(name, expectedHostname) != 0) {
		return result;
	}
	if (read16(data + offset + consumed) != 1 || read16(data + offset + consumed + 2) != 1) {
		return result;
	}
	offset += consumed + 4;

	const uint16_t answers = read16(data + 6);
	uint32_t minTtl = UINT32_MAX;
	for (uint16_t i = 0; i < answers; ++i) {
		consumed = 0;
		if (!decodeName(data, length, offset, name, sizeof(name), consumed, length) ||
		    offset + consumed + 10 > length) {
			return DnsAAnswer{};
		}
		offset += consumed;
		const uint16_t type = read16(data + offset);
		const uint16_t klass = read16(data + offset + 2);
		const uint32_t ttl = read32(data + offset + 4);
		const uint16_t rdLength = read16(data + offset + 8);
		offset += 10;
		if (offset + rdLength > length) {
			return DnsAAnswer{};
		}
		if (type == 1 && klass == 1 && rdLength == 4 && result.addressCount < DnsMaxARecords) {
			uint32_t address = 0;
			std::memcpy(&address, data + offset, sizeof(address));
			result.addresses[result.addressCount++] = address;
			minTtl = std::min(minTtl, ttl);
		}
		offset += rdLength;
	}
	if (result.addressCount == 0) {
		result.status = DnsParseStatus::NoRecord;
		return result;
	}
	result.status = DnsParseStatus::Ok;
	result.ttlSeconds = minTtl == UINT32_MAX ? 0 : minTtl;
	return result;
}

size_t buildPtrQuery(uint16_t transactionId, const uint8_t ipv4[4], uint8_t *out, size_t capacity) {
	if (ipv4 == nullptr || out == nullptr || capacity < 32) {
		return 0;
	}
	std::memset(out, 0, capacity);
	out[0] = static_cast<uint8_t>(transactionId >> 8U);
	out[1] = static_cast<uint8_t>(transactionId & 0xFFU);
	out[2] = 0x01; // recursion desired
	out[5] = 0x01; // QDCOUNT

	size_t offset = 12;
	char label[4] = {};
	for (int i = 3; i >= 0; --i) {
		std::snprintf(label, sizeof(label), "%u", static_cast<unsigned>(ipv4[i]));
		if (!appendLabel(out, capacity, offset, label)) {
			return 0;
		}
	}
	if (!appendLabel(out, capacity, offset, "in-addr") ||
	    !appendLabel(out, capacity, offset, "arpa") || offset + 5 > capacity) {
		return 0;
	}
	out[offset++] = 0;
	out[offset++] = 0;
	out[offset++] = 12; // PTR
	out[offset++] = 0;
	out[offset++] = 1; // IN
	return offset;
}

DnsPtrAnswer parsePtrResponse(
    const uint8_t *data, size_t length, uint16_t transactionId, const uint8_t expectedIpv4[4]
) {
	DnsPtrAnswer result{};
	if (data == nullptr || length < 12 || read16(data) != transactionId) {
		return result;
	}
	const uint16_t flags = read16(data + 2);
	if ((flags & 0x8000U) == 0) {
		return result;
	}
	if ((flags & 0x7800U) != 0 || (flags & 0x0200U) != 0) {
		return result;
	}
	const uint8_t rcode = static_cast<uint8_t>(flags & 0x0FU);
	if (rcode == 3) {
		result.status = DnsParseStatus::NoRecord;
		return result;
	}
	if (rcode != 0) {
		result.status = DnsParseStatus::ServerError;
		return result;
	}

	const uint16_t questions = read16(data + 4);
	const uint16_t answers = read16(data + 6);
	if (questions != 1) {
		return result;
	}

	size_t offset = 12;
	char scratch[256] = {};
	size_t questionConsumed = 0;
	if (!decodeName(data, length, offset, scratch, sizeof(scratch), questionConsumed, length) ||
	    offset + questionConsumed + 4 > length) {
		return result;
	}
	const uint16_t questionType = read16(data + offset + questionConsumed);
	const uint16_t questionClass = read16(data + offset + questionConsumed + 2);
	if (questionType != 12 || questionClass != 1) {
		return result;
	}
	if (expectedIpv4 != nullptr) {
		char expected[64]{};
		std::snprintf(
		    expected,
		    sizeof(expected),
		    "%u.%u.%u.%u.in-addr.arpa",
		    static_cast<unsigned>(expectedIpv4[3]),
		    static_cast<unsigned>(expectedIpv4[2]),
		    static_cast<unsigned>(expectedIpv4[1]),
		    static_cast<unsigned>(expectedIpv4[0])
		);
		if (strcasecmp(scratch, expected) != 0) {
			return result;
		}
	}
	offset += questionConsumed + 4;

	for (uint16_t i = 0; i < answers; ++i) {
		size_t consumed = 0;
		if (!decodeName(data, length, offset, scratch, sizeof(scratch), consumed, length) ||
		    offset + consumed + 10 > length) {
			return result;
		}
		offset += consumed;
		const uint16_t type = read16(data + offset);
		const uint16_t klass = read16(data + offset + 2);
		const uint32_t ttl = read32(data + offset + 4);
		const uint16_t rdLength = read16(data + offset + 8);
		offset += 10;
		if (offset + rdLength > length) {
			return result;
		}
		if (type == 12 && klass == 1) {
			size_t ignored = 0;
			if (!decodeName(
			        data,
			        length,
			        offset,
			        result.hostname,
			        sizeof(result.hostname),
			        ignored,
			        offset + rdLength
			    ) ||
			    ignored > rdLength || result.hostname[0] == '\0') {
				return DnsPtrAnswer{};
			}
			result.status = DnsParseStatus::Ok;
			result.ttlSeconds = ttl;
			return result;
		}
		offset += rdLength;
	}
	result.status = DnsParseStatus::NoRecord;
	return result;
}

} // namespace scout_internal
