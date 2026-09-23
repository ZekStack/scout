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

enum class NetworkMode {
	None,
	InterfaceError,
	SmallSubnet,
	LargeSubnet,
	PartialRequestFailure,
};
std::atomic<NetworkMode> networkMode{NetworkMode::None};

void waitUntilStarted(const std::atomic<bool> &started) {
	while (!started.load()) {
		std::this_thread::yield();
	}
}

template <typename Predicate>
void waitUntil(Predicate predicate) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	while (!predicate()) {
		assert(std::chrono::steady_clock::now() < deadline && "timed out waiting for condition");
		std::this_thread::yield();
	}
}

void assertTerminalScanPair(const std::vector<ScoutEvent> &events) {
	const ScoutEvent *started = nullptr;
	const ScoutEvent *completed = nullptr;
	size_t startedCount = 0;
	size_t completedCount = 0;
	for (const auto &event : events) {
		if (event.type == ScoutEventType::ScanStarted) {
			started = &event;
			startedCount++;
		}
		if (event.type == ScoutEventType::ScanCompleted) {
			completed = &event;
			completedCount++;
		}
	}
	assert(startedCount == 1);
	assert(completedCount == 1);
	assert(started != nullptr && completed != nullptr);
	assert(started->scanId == completed->scanId);
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
			if (event.type == type && event.status == status) {
				return true;
			}
		}
		return false;
	};

	networkMode.store(NetworkMode::None);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanSkipped, ScoutStatus::NetworkUnavailable));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::NetworkUnavailable));
	assertTerminalScanPair(events);
	events.clear();

	networkMode.store(NetworkMode::InterfaceError);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::Error, ScoutStatus::InternalError));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InternalError));
	assertTerminalScanPair(events);
	events.clear();

	networkMode.store(NetworkMode::LargeSubnet);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanSkipped, ScoutStatus::InvalidConfig));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InvalidConfig));
	assertTerminalScanPair(events);
	assert(!runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 0);
	events.clear();

	networkMode.store(NetworkMode::SmallSubnet);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::Ok));
	assertTerminalScanPair(events);
	assert(runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 1);
	events.clear();

	networkMode.store(NetworkMode::PartialRequestFailure);
	runtime.performScan();
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InternalError));
	assertTerminalScanPair(events);
	assert(!runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 1);
	assert(runtime.diag.arpRequestFailures > 0);
	runtime.releaseBuffers();
}

void testRegistryAgingAndDeduplication() {
	ScoutImpl runtime;
	runtime.config.deviceMaxAgeMs = 1000;
	assert(runtime.allocateBuffers(runtime.config));

	std::vector<ScoutEvent> events;
	runtime.callback = [&](const ScoutEvent &event) { events.push_back(event); };

	scout_internal::InterfaceSnapshot interfaceSnapshot;
	interfaceSnapshot.index = 1;
	std::strcpy(interfaceSnapshot.name, "test");

	const uint8_t firstMac[6] = {0x02, 1, 2, 3, 4, 5};
	const uint8_t secondMac[6] = {0x02, 1, 2, 3, 4, 6};
	const uint32_t address = lwip_htonl(0xC0A80120U);

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    firstMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    1
	);
	runtime.observe(
	    interfaceSnapshot,
	    address,
	    firstMac,
	    ScoutObservationSource::ArpCache,
	    false,
	    1
	);
	assert(runtime.deviceCount == 1);
	assert(runtime.devices[0].info.endpointCount == 1);

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    secondMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    1
	);
	assert(runtime.deviceCount == 2);
	const size_t firstIndex = runtime.findDeviceByMac(firstMac);
	const size_t secondIndex = runtime.findDeviceByMac(secondMac);
	assert(firstIndex != SIZE_MAX && secondIndex != SIZE_MAX);
	assert(runtime.devices[firstIndex].info.endpointCount == 0);
	assert(runtime.devices[secondIndex].info.endpointCount == 1);
	assert(runtime.diag.endpointReassignmentCount == 1);

	runtime.devices[runtime.deviceCount].info = runtime.devices[secondIndex].info;
	runtime.deviceCount++;
	runtime.diag.deviceCount = runtime.deviceCount;
	runtime.maintainRegistry(2);
	assert(runtime.deviceCount == 2);
	assert(runtime.diag.deduplicatedDeviceCount == 1);

	const size_t staleIndex = runtime.findDeviceByMac(firstMac);
	assert(staleIndex != SIZE_MAX);
	runtime.devices[staleIndex].info.lastSeenAtMs = nowMs() - 2000;
	events.clear();
	runtime.maintainRegistry(3);
	assert(runtime.findDeviceByMac(firstMac) == SIZE_MAX);
	assert(runtime.deviceCount == 1);
	assert(runtime.diag.expiredDeviceCount == 1);

	bool expiredEvent = false;
	for (const auto &event : events) {
		if (event.type == ScoutEventType::DeviceExpired && event.hasDevice &&
		    event.device.mac == scout_internal::macFromBytes(firstMac)) {
			expiredEvent = true;
		}
	}
	assert(expiredEvent);
	runtime.releaseBuffers();
}

void testDestructionFromCallback() {
	networkMode.store(NetworkMode::None);
	std::atomic<Scout *> scout{new Scout()};
	std::atomic<bool> allowDestroy{false};
	std::atomic<bool> destroyed{false};
	std::atomic<int> taskResets{0};

	Scout *instance = scout.load();
	instance->onEvent([&](const ScoutEvent &event) {
		if (event.type != ScoutEventType::ScanStarted || destroyed.load()) {
			return;
		}
		while (!allowDestroy.load()) {
			std::this_thread::yield();
		}
		Scout *doomed = scout.exchange(nullptr);
		assert(doomed != nullptr);
		delete doomed;
		destroyed.store(true);
	});

	ScoutConfig config;
	config.scanOnInit = true;
	config.arpResponseWaitMs = 1;
	config.interBatchDelayMs = 0;
	const ScoutResult initResult = instance->init(config);
	assert(initResult.status == ScoutStatus::Ok);

	Strata::TestHooks::resetTask = [&] { taskResets.fetch_add(1); };
	allowDestroy.store(true);
	waitUntil([&] { return destroyed.load(); });
	waitUntil([&] { return taskResets.load() > 0; });
	Strata::TestHooks::resetTask = {};
	assert(scout.load() == nullptr);
}
} // namespace

namespace scout_internal {
esp_err_t collectInterfaces(InterfaceSnapshot *out, size_t capacity, size_t &count) {
	const auto mode = networkMode.load();
	if (mode == NetworkMode::InterfaceError) {
		count = 0;
		return ESP_FAIL;
	}
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
	testRegistryAgingAndDeduplication();
	testDestructionFromCallback();
	std::cout << "Scout runtime host tests passed\n";
}
