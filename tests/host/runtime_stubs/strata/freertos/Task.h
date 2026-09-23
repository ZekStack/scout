#pragma once
#include <Arduino.h>
#include <Strata.h>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace Strata::FreeRTOS {
struct TaskConfig {
	const char *name = nullptr;
	uint32_t stackBytes = 0;
	Strata::Placement stackPlacement = Strata::Placement::PreferExternal;
	UBaseType_t priority = 0;
	BaseType_t affinity = tskNO_AFFINITY;
};
struct FakeTaskState {
	std::mutex mutex;
	std::condition_variable condition;
	bool notified = false;
};
using TaskHandle = FakeTaskState *;
inline thread_local TaskHandle currentTask = nullptr;
struct TaskSuspended {};
class Task {
  public:
	Task() = default;
	Task(const Task &) = delete;
	Task &operator=(const Task &) = delete;
	Task(Task &&) = default;
	Task &operator=(Task &&) = default;
	~Task() { reset(); }
	static Task create(void (*entry)(void *), void *context, const TaskConfig &) {
		Task task;
		task.state_ = std::make_shared<FakeTaskState>();
		const auto state = task.state_;
		task.thread_ = std::thread([entry, context, state] {
			currentTask = state.get();
			try { entry(context); } catch (const TaskSuspended &) {}
			currentTask = nullptr;
		});
		return task;
	}
	void reset() {
		if (!state_) { return; }
		if (Strata::TestHooks::resetTask) { Strata::TestHooks::resetTask(); }
		if (thread_.joinable()) { thread_.join(); }
		state_.reset();
	}
	TaskHandle handle() const { return state_.get(); }
	Strata::Region stackRegion() const {
		return state_ ? Strata::Region::Internal : Strata::Region::Unknown;
	}
	size_t stackHighWaterMarkBytes() const { return 1024; }
	explicit operator bool() const { return static_cast<bool>(state_); }
  private:
	std::shared_ptr<FakeTaskState> state_;
	std::thread thread_;
};
} // namespace Strata::FreeRTOS

inline Strata::FreeRTOS::TaskHandle xTaskGetCurrentTaskHandle() {
	return Strata::FreeRTOS::currentTask;
}
inline void xTaskNotifyGive(Strata::FreeRTOS::TaskHandle handle) {
	if (handle == nullptr) { return; }
	{
		std::lock_guard lock(handle->mutex);
		handle->notified = true;
	}
	handle->condition.notify_one();
}
inline uint32_t ulTaskNotifyTake(int, TickType_t timeout) {
	auto *handle = xTaskGetCurrentTaskHandle();
	if (handle == nullptr) {
		std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
		return 0;
	}
	std::unique_lock lock(handle->mutex);
	const auto notified = [&] { return handle->notified; };
	if (timeout == portMAX_DELAY) {
		handle->condition.wait(lock, notified);
	} else {
		handle->condition.wait_for(lock, std::chrono::milliseconds(timeout), notified);
	}
	const bool received = handle->notified;
	handle->notified = false;
	return received ? 1U : 0U;
}
inline void vTaskDelay(TickType_t ticks) {
	std::this_thread::sleep_for(std::chrono::milliseconds(ticks));
}
[[noreturn]] inline void vTaskSuspend(Strata::FreeRTOS::TaskHandle) {
	throw Strata::FreeRTOS::TaskSuspended{};
}
