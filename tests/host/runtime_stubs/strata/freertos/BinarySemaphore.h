#pragma once
#include <Arduino.h>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
namespace Strata::FreeRTOS {
class BinarySemaphore {
	struct State {
		std::mutex mutex;
		std::condition_variable condition;
		bool signalled = false;
	};
  public:
	static BinarySemaphore create() { return BinarySemaphore(); }
	bool take(TickType_t timeout) {
		std::unique_lock lock(state_->mutex);
		const auto ready = [&] { return state_->signalled; };
		if (timeout == portMAX_DELAY) {
			state_->condition.wait(lock, ready);
		} else if (!state_->condition.wait_for(lock, std::chrono::milliseconds(timeout), ready)) {
			return false;
		}
		state_->signalled = false;
		return true;
	}
	bool give() {
		{
			std::lock_guard lock(state_->mutex);
			state_->signalled = true;
		}
		state_->condition.notify_one();
		return true;
	}
	explicit operator bool() const { return static_cast<bool>(state_); }
  private:
	std::shared_ptr<State> state_ = std::make_shared<State>();
};
} // namespace Strata::FreeRTOS
