#pragma once

#include <cstdint>

using UBaseType_t = unsigned int;
using BaseType_t = int;
using StackType_t = std::uint32_t;
using TickType_t = std::uint32_t;

inline constexpr BaseType_t tskNO_AFFINITY = -1;
inline constexpr TickType_t portMAX_DELAY = UINT32_MAX;
inline constexpr int pdTRUE = 1;

inline constexpr TickType_t pdMS_TO_TICKS(std::uint32_t ms) {
	return ms;
}
