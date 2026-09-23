#pragma once
#include <cstdint>
inline uint32_t lwip_htonl(uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(value);
#else
	return value;
#endif
}
inline uint32_t lwip_ntohl(uint32_t value) { return lwip_htonl(value); }
