#include "../../src/Scout.cpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

namespace {
struct Gate {
	std::mutex mutex;
	std::condition_variable condition;
	bool entered = false;
	bool open = false;

	void pause() {
		std::unique_lock lock(mutex);
		entered = true;
		condition.notify_all();
		condition.wait(lock, [&] { return open; });
	}
	void waitUntilEntered() {
		std::unique_lock lock(mutex);
		condition.wait(lock, [&] { return entered; });
	}
	void release() {
		{
			std::lock_guard lock(mutex);
			open = true;
		}
		condition.notify_all();
	}
};

enum class NetworkMode { None, SmallSubnet, LargeSubnet, PartialRequestFailure };
std::atomic<NetworkMode> networkMode{NetworkMode::None};

void waitUntilStarted(const std::atomic<bool> &started) {
	while (!started.load()) {
		std::this_thread::yield();
	}
}

void testLifecycleSnapshots() {
	Scout scout;
	ScoutConfig config;
	config.scanOnInit = false;
	Gate allocationGate;
	std::atomic<int> allocations{0};
	Strata::TestHooks::allocation = [&] {
		if (allocations.fetch_add(1) == 0) {
			allocationGate.pause();
		}
	};

	ScoutResult initResult;
	std::thread initializer([&] { initResult = scout.init(config); });
	allocationGate.waitUntilEntered();

	std::atomic<bool> readerStarted{false};
	std::atomic<bool> readerDone{false};
	ScoutDiagnostics initializedSnapshot;
	std::thread reader([&] {
		readerStarted.store(true);
		initializedSnapshot = scout.diagnostics();
		readerDone.store(true);
	});
	waitUntilStarted(readerStarted);
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	assert(!readerDone.load() && "diagnostics read partial initialization");
	allocationGate.release();
	initializer.join();
	reader.join();
	Strata::TestHooks::allocation = {};
	assert(initResult.status == ScoutStatus::Ok);
	assert(initializedSnapshot.registryRegion != Strata::Region::Unknown);
	assert(initializedSnapshot.targetBufferRegion != Strata::Region::Unknown);

	ScoutDeviceInfo device;
	const ScoutMacAddress absent{{1, 2, 3, 4, 5, 6}};
	assert(scout.findByMac(absent, device).status == ScoutStatus::NotFound);
	assert(scout.deviceAt(0, device).status == ScoutStatus::NotFound);
	assert(scout.findByMac({}, device).status == ScoutStatus::InvalidConfig);
	assert(std::strcmp(scout.statusToString(ScoutStatus::NotFound), "not_found") == 0);

	Gate resetGate;
	Strata::TestHooks::resetTask = [&] { resetGate.pause(); };
	ScoutResult deinitResult;
	std::thread deinitializer([&] { deinitResult = scout.deinit(); });
	resetGate.waitUntilEntered();

	readerStarted.store(false);
	readerDone.store(false);
	ScoutDiagnostics stoppedSnapshot;
	std::thread stoppingReader([&] {
		readerStarted.store(true);
		stoppedSnapshot = scout.diagnostics();
		readerDone.store(true);
	});
	waitUntilStarted(readerStarted);
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	assert(!readerDone.load() && "diagnostics read during task reset");
	resetGate.release();
	deinitializer.join();
	stoppingReader.join();
	Strata::TestHooks::resetTask = {};
	assert(deinitResult.status == ScoutStatus::Ok);
	assert(stoppedSnapshot.state == ScoutState::Stopped);
	assert(stoppedSnapshot.registryRegion == Strata::Region::Unknown);
	assert(stoppedSnapshot.targetBufferRegion == Strata::Region::Unknown);
	assert(stoppedSnapshot.taskStackRegion == Strata::Region::Unknown);
}

void testScanStatusAndCoverage() {
	ScoutImpl runtime;
	runtime.config.arpResponseWaitMs = 1;
	runtime.config.interBatchDelayMs = 0;
	assert(runtime.allocateBuffers(runtime.config));

	std::vector<ScoutEvent> events;
	runtime.callback = [&](const ScoutEvent &event) { events.push_back(event); };
	const auto hasEvent = [&](ScoutEventType type, ScoutStatus status) {
		for (const auto &event : events) {
			if (event.type == type && event.status == status) { return true; }
		}
		return false;
	};

	networkMode.store(NetworkMode::LargeSubnet);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanSkipped, ScoutStatus::InvalidConfig));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InvalidConfig));
	assert(!runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 0);
	events.clear();

	networkMode.store(NetworkMode::SmallSubnet);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::Ok));
	assert(runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 1);
	events.clear();

	networkMode.store(NetworkMode::PartialRequestFailure);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InternalError));
	assert(!runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 1);
	assert(runtime.diag.arpRequestFailures > 0);
	runtime.releaseBuffers();
}
} // namespace

namespace scout_internal {
esp_err_t collectInterfaces(InterfaceSnapshot *out, size_t capacity, size_t &count) {
	const auto mode = networkMode.load();
	count = mode == NetworkMode::None ? 0 : 1;
	if (count == 0) { return ESP_OK; }
	assert(capacity >= 1);
	out[0].index = 1;
	std::strcpy(out[0].name, "test");
	out[0].ipv4 = lwip_htonl(0xC0A80101U);
	out[0].netmask = lwip_htonl(mode == NetworkMode::LargeSubnet ? 0xFFFF0000U : 0xFFFFFF00U);
	return ESP_OK;
}
esp_err_t lookupArpMappings(uint8_t, const uint32_t *, size_t count, ArpMapping *out) {
	for (size_t i = 0; i < count; ++i) { out[i] = {}; }
	return ESP_OK;
}
esp_err_t requestArp(uint8_t, const uint32_t *, size_t count, ArpRequestStats &stats) {
	stats.sent = count;
	stats.failed = networkMode.load() == NetworkMode::PartialRequestFailure ? 1 : 0;
	return ESP_OK;
}
size_t recommendedArpBatchSize(size_t requested) { return requested; }
} // namespace scout_internal

int main() {
	testLifecycleSnapshots();
	testScanStatusAndCoverage();
	std::cout << "Scout runtime host tests passed\n";
}
