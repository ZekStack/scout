#pragma once
#include <memory>
#include <mutex>
namespace Strata::FreeRTOS {
class RecursiveMutex {
  public:
	static RecursiveMutex create() { return RecursiveMutex(); }
	bool lock() { state_->lock(); return true; }
	void unlock() { state_->unlock(); }
	explicit operator bool() const { return static_cast<bool>(state_); }
  private:
	std::shared_ptr<std::recursive_mutex> state_ = std::make_shared<std::recursive_mutex>();
};
} // namespace Strata::FreeRTOS
