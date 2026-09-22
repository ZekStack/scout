#pragma once

#include <cstdint>
#include <memory>

namespace Strata {

enum class Placement : std::uint8_t {
	Default,
	Internal,
	PreferExternal,
	RequireExternal,
};

enum class Region : std::uint8_t {
	Unknown,
	Internal,
	External,
};

struct MemoryPolicy {
	Placement allocation{Placement::Default};
	Placement taskStack{Placement::Internal};
};

template <typename T>
using UniquePtr = std::unique_ptr<T>;

} // namespace Strata
