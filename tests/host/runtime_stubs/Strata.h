#pragma once
#include <cstddef>
#include <functional>
#include <memory>
#include <new>

namespace Strata {
enum class Placement { Internal, PreferExternal };
enum class Region { Unknown, Internal };
struct MemoryPolicy {
	Placement allocation = Placement::PreferExternal;
	Placement taskStack = Placement::PreferExternal;
};
inline bool validPlacement(Placement) { return true; }
inline Region regionOf(const void *pointer) {
	return pointer == nullptr ? Region::Unknown : Region::Internal;
}
namespace TestHooks {
inline std::function<void()> allocation;
inline std::function<void()> resetTask;
}
template <typename T> T *allocateArray(size_t count, Placement) {
	if (TestHooks::allocation) {
		TestHooks::allocation();
	}
	return static_cast<T *>(::operator new(sizeof(T) * count, std::nothrow));
}
template <typename T> void free(T *pointer) { ::operator delete(pointer); }
template <typename T> using UniquePtr = std::unique_ptr<T>;
template <typename T> UniquePtr<T> makeUnique(Placement) {
	return UniquePtr<T>(new (std::nothrow) T());
}
} // namespace Strata
