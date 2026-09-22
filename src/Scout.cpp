#include "Scout.h"

#include "internal/ScoutNetwork.h"

#include <strata/freertos/BinarySemaphore.h>
#include <strata/freertos/Mutex.h>
#include <strata/freertos/Task.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstring>
#include <memory>
#include <utility>

#include <esp_timer.h>
#include <lwip/def.h>

namespace {

constexpr const char *TaskName = "scout";
constexpr uint32_t StopPollMs = 20;
constexpr uint32_t MinScanIntervalMs = 1000;
constexpr uint32_t MinTaskStackBytes = 4096;

uint64_t nowMs() {
	return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
}

bool validStackSize(size_t stackBytes) {
	return stackBytes >= MinTaskStackBytes && (stackBytes % sizeof(StackType_t)) == 0;
}

TickType_t timeoutTicks(uint32_t timeoutMs) {
	return timeoutMs == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeoutMs);
}

class ScoutLock {
  public:
	explicit ScoutLock(Strata::FreeRTOS::RecursiveMutex &mutex)
	    : _mutex(mutex), _locked(mutex.lock()) {
	}

	~ScoutLock() {
		if (_locked) {
			_mutex.unlock();
		}
	}

	ScoutLock(const ScoutLock &) = delete;
	ScoutLock &operator=(const ScoutLock &) = delete;

	explicit operator bool() const {
		return _locked;
	}

  private:
	Strata::FreeRTOS::RecursiveMutex &_mutex;
	bool _locked = false;
};

[[noreturn]] void suspendForever() {
	vTaskSuspend(nullptr);
	for (;;) {
		vTaskDelay(portMAX_DELAY);
	}
}

bool sameMac(const uint8_t *left, const uint8_t *right) {
	return std::memcmp(left, right, 6) == 0;
}

bool sameMac(const ScoutMacAddress &left, const uint8_t *right) {
	return std::memcmp(left.bytes, right, sizeof(left.bytes)) == 0;
}

ScoutMacAddress makeMac(const uint8_t *bytes) {
	ScoutMacAddress mac;
	std::memcpy(mac.bytes, bytes, sizeof(mac.bytes));
	return mac;
}

} // namespace

struct ScoutDeviceRecord {
	ScoutDeviceInfo info{};
};

struct ScoutImpl {
	ScoutImpl() noexcept
	    : mutex(Strata::FreeRTOS::RecursiveMutex::create()),
	      stopped(Strata::FreeRTOS::BinarySemaphore::create()) {
	}

	~ScoutImpl() noexcept {
		releaseBuffers();
	}

	ScoutConfig config{};
	Strata::FreeRTOS::RecursiveMutex mutex;
	Strata::FreeRTOS::BinarySemaphore stopped;
	Strata::FreeRTOS::Task task;

	ScoutDeviceRecord *devices = nullptr;
	uint32_t *targets = nullptr;
	scout_internal::ArpMapping *beforeMappings = nullptr;
	scout_internal::ArpMapping *afterMappings = nullptr;
	size_t deviceCapacity = 0;
	size_t deviceCount = 0;
	size_t mappingCapacity = 0;

	ScoutEventCallback callback;

	std::atomic<bool> stopRequested{false};
	std::atomic<bool> scanRequested{false};
	std::atomic<bool> readyForDelete{false};

	ScoutState state = ScoutState::Stopped;
	bool initialized = false;
	bool coverageKnown = false;
	bool coverageAvailable = false;

	uint64_t nextScanId = 1;
	ScoutDiagnostics diag{};

	void releaseBuffers() noexcept {
		if (devices != nullptr) {
			for (size_t i = 0; i < deviceCapacity; ++i) {
				std::destroy_at(&devices[i]);
			}
			Strata::free(devices);
			devices = nullptr;
		}
		Strata::free(targets);
		targets = nullptr;
		Strata::free(beforeMappings);
		beforeMappings = nullptr;
		Strata::free(afterMappings);
		afterMappings = nullptr;
		deviceCapacity = 0;
		deviceCount = 0;
		mappingCapacity = 0;
	}

	bool allocateBuffers(const ScoutConfig &incoming) {
		releaseBuffers();

		devices = Strata::allocateArray<ScoutDeviceRecord>(
		    incoming.maxDevices,
		    incoming.memory.allocation
		);
		if (devices == nullptr) {
			return false;
		}
		deviceCapacity = incoming.maxDevices;
		for (size_t i = 0; i < deviceCapacity; ++i) {
			std::construct_at(&devices[i]);
		}

		targets = Strata::allocateArray<uint32_t>(
		    incoming.maxHostsPerSubnet,
		    incoming.memory.allocation
		);
		if (targets == nullptr) {
			releaseBuffers();
			return false;
		}

		mappingCapacity = scout_internal::recommendedArpBatchSize(incoming.arpBatchSize);
		beforeMappings = Strata::allocateArray<scout_internal::ArpMapping>(
		    mappingCapacity,
		    incoming.memory.allocation
		);
		afterMappings = Strata::allocateArray<scout_internal::ArpMapping>(
		    mappingCapacity,
		    incoming.memory.allocation
		);
		if (beforeMappings == nullptr || afterMappings == nullptr) {
			releaseBuffers();
			return false;
		}

		return true;
	}

	ScoutEventCallback callbackSnapshot() {
		ScoutLock lock(mutex);
		if (!lock) {
			return {};
		}
		return callback;
	}

	void emit(ScoutEvent event) {
		ScoutEventCallback current = callbackSnapshot();
		if (current) {
			current(event);
		}
	}

	void emitSimple(
	    ScoutEventType type,
	    ScoutStatus status,
	    uint64_t scanId,
	    const char *message
	) {
		emit(ScoutEvent{
		    .type = type,
		    .status = status,
		    .scanId = scanId,
		    .message = message,
		});
	}

	void updateCoverage(bool available, size_t interfaceCount, uint64_t scanId) {
		ScoutEvent event;
		bool shouldEmit = false;
		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}
			diag.activeInterfaceCount = interfaceCount;
			diag.coverageAvailable = available;

			if (!coverageKnown || coverageAvailable != available) {
				coverageKnown = true;
				coverageAvailable = available;
				event.type = available ? ScoutEventType::CoverageRestored
				                       : ScoutEventType::CoverageLost;
				event.status = available ? ScoutStatus::Ok : ScoutStatus::NetworkUnavailable;
				event.scanId = scanId;
				event.message = available ? "network coverage available"
				                          : "no eligible ARP-capable interface";
				shouldEmit = true;
			}
		}
		if (shouldEmit) {
			emit(event);
		}
	}

	bool waitInterruptible(uint32_t durationMs) {
		const uint64_t startedAt = nowMs();
		while (!stopRequested.load()) {
			const uint64_t elapsed = nowMs() - startedAt;
			if (elapsed >= durationMs) {
				return true;
			}
			const uint32_t remaining =
			    static_cast<uint32_t>(std::min<uint64_t>(durationMs - elapsed, StopPollMs));
			(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(std::max<uint32_t>(remaining, 1)));
		}
		return false;
	}

	void recordNetworkError(uint64_t scanId, const char *message) {
		emitSimple(ScoutEventType::Error, ScoutStatus::InternalError, scanId, message);
	}

	size_t buildTargets(const scout_internal::InterfaceSnapshot &interfaceSnapshot) {
		const uint32_t ip = lwip_ntohl(interfaceSnapshot.ipv4);
		const uint32_t mask = lwip_ntohl(interfaceSnapshot.netmask);
		const uint32_t network = ip & mask;
		const uint32_t broadcast = network | ~mask;

		if (broadcast <= network + 1U) {
			return 0;
		}

		const uint64_t hostCount =
		    static_cast<uint64_t>(broadcast) - static_cast<uint64_t>(network) - 1ULL;
		if (hostCount > config.maxHostsPerSubnet) {
			return SIZE_MAX;
		}

		size_t count = 0;
		for (uint32_t current = network + 1U; current < broadcast; ++current) {
			if (current == ip) {
				continue;
			}
			targets[count++] = lwip_htonl(current);
		}
		return count;
	}

	size_t findDeviceByMac(const uint8_t *mac) const {
		for (size_t i = 0; i < deviceCount; ++i) {
			if (sameMac(devices[i].info.mac, mac)) {
				return i;
			}
		}
		return SIZE_MAX;
	}

	bool upsertEndpoint(
	    ScoutDeviceInfo &device,
	    const scout_internal::InterfaceSnapshot &interfaceSnapshot,
	    uint32_t ipv4,
	    uint64_t observedAt
	) {
		for (size_t i = 0; i < device.endpointCount; ++i) {
			auto &endpoint = device.endpoints[i];
			if (endpoint.interfaceIndex == interfaceSnapshot.index &&
			    endpoint.ipv4.value == ipv4) {
				endpoint.lastSeenAtMs = observedAt;
				return false;
			}
		}

		size_t targetIndex = device.endpointCount;
		if (targetIndex >= SCOUT_MAX_ENDPOINTS_PER_DEVICE) {
			targetIndex = 0;
			for (size_t i = 1; i < device.endpointCount; ++i) {
				if (device.endpoints[i].lastSeenAtMs <
				    device.endpoints[targetIndex].lastSeenAtMs) {
					targetIndex = i;
				}
			}
		} else {
			device.endpointCount++;
		}

		auto &endpoint = device.endpoints[targetIndex];
		endpoint = {};
		endpoint.ipv4.value = ipv4;
		endpoint.interfaceIndex = interfaceSnapshot.index;
		endpoint.lastSeenAtMs = observedAt;
		std::strncpy(
		    endpoint.interfaceName,
		    interfaceSnapshot.name,
		    sizeof(endpoint.interfaceName) - 1
		);
		endpoint.interfaceName[sizeof(endpoint.interfaceName) - 1] = '\0';
		return true;
	}

	void observe(
	    const scout_internal::InterfaceSnapshot &interfaceSnapshot,
	    uint32_t ipv4,
	    const uint8_t *mac,
	    ScoutObservationSource source,
	    bool confirmed,
	    uint64_t scanId
	) {
		ScoutEvent event;
		bool shouldEmit = false;
		const uint64_t observedAt = nowMs();

		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}

			size_t index = findDeviceByMac(mac);
			if (index == SIZE_MAX) {
				if (deviceCount >= deviceCapacity) {
					diag.deviceLimitDrops++;
					event.type = ScoutEventType::Error;
					event.status = ScoutStatus::DeviceLimitReached;
					event.scanId = scanId;
					event.source = source;
					event.message = "device registry limit reached";
					shouldEmit = true;
				} else {
					index = deviceCount++;
					auto &info = devices[index].info;
					info = {};
					info.key.kind = ScoutIdentityKind::Mac;
					info.key.mac = makeMac(mac);
					info.mac = info.key.mac;
					info.firstSeenAtMs = observedAt;
					info.lastSeenAtMs = observedAt;
					info.lastConfirmedAtMs = confirmed ? observedAt : 0;
					info.observationSources = scoutObservationMask(source);
					info.observationCount = 1;
					(void)upsertEndpoint(info, interfaceSnapshot, ipv4, observedAt);

					diag.deviceCount = deviceCount;
					diag.peakDeviceCount = std::max(diag.peakDeviceCount, deviceCount);

					event.type = ScoutEventType::DeviceDiscovered;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = info;
					event.message = confirmed ? "device discovered by active ARP"
					                          : "device discovered from ARP cache";
					shouldEmit = true;
				}
			} else {
				auto &info = devices[index].info;
				info.lastSeenAtMs = observedAt;
				if (confirmed) {
					info.lastConfirmedAtMs = observedAt;
				}
				info.observationSources |= scoutObservationMask(source);
				info.observationCount++;
				const bool endpointChanged =
				    upsertEndpoint(info, interfaceSnapshot, ipv4, observedAt);

				if (endpointChanged || confirmed) {
					event.type = endpointChanged ? ScoutEventType::DeviceChanged
					                            : ScoutEventType::DeviceObserved;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = info;
					event.message = endpointChanged ? "device endpoint changed"
					                                : "device actively observed";
					shouldEmit = true;
				}
			}
		}

		if (shouldEmit) {
			emit(event);
		}
	}

	void scanInterface(
	    const scout_internal::InterfaceSnapshot &interfaceSnapshot,
	    uint64_t scanId
	) {
		const size_t targetCount = buildTargets(interfaceSnapshot);
		if (targetCount == SIZE_MAX) {
			{
				ScoutLock lock(mutex);
				if (lock) {
					diag.skippedScanCount++;
				}
			}
			emitSimple(
			    ScoutEventType::ScanSkipped,
			    ScoutStatus::InvalidConfig,
			    scanId,
			    "subnet exceeds maxHostsPerSubnet"
			);
			return;
		}
		if (targetCount == 0) {
			return;
		}

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.hostsConsidered += targetCount;
			}
		}

		const size_t batchSize = mappingCapacity;
		for (size_t offset = 0; offset < targetCount && !stopRequested.load();
		     offset += batchSize) {
			const size_t count = std::min(batchSize, targetCount - offset);
			const uint32_t *batch = targets + offset;

			const esp_err_t beforeResult = scout_internal::lookupArpMappings(
			    interfaceSnapshot.index,
			    batch,
			    count,
			    beforeMappings
			);
			if (beforeResult != ESP_OK && beforeResult != ESP_ERR_NOT_FOUND) {
				recordNetworkError(scanId, "failed to inspect ARP cache");
				return;
			}

			scout_internal::ArpRequestStats requestStats;
			const esp_err_t requestResult = scout_internal::requestArp(
			    interfaceSnapshot.index,
			    batch,
			    count,
			    requestStats
			);
			{
				ScoutLock lock(mutex);
				if (lock) {
					diag.arpRequestsSent += requestStats.sent;
					diag.arpRequestFailures += requestStats.failed;
				}
			}
			if (requestResult != ESP_OK) {
				recordNetworkError(scanId, "failed to send ARP requests");
				return;
			}

			if (!waitInterruptible(config.arpResponseWaitMs)) {
				return;
			}

			const esp_err_t afterResult = scout_internal::lookupArpMappings(
			    interfaceSnapshot.index,
			    batch,
			    count,
			    afterMappings
			);
			if (afterResult != ESP_OK) {
				recordNetworkError(scanId, "failed to read ARP results");
				return;
			}

			for (size_t i = 0; i < count; ++i) {
				if (!afterMappings[i].found) {
					continue;
				}

				const bool wasCached = beforeMappings[i].found &&
				                       sameMac(beforeMappings[i].mac, afterMappings[i].mac);
				const bool confirmed = !wasCached;
				const ScoutObservationSource source =
				    confirmed ? ScoutObservationSource::ArpProbe
				              : ScoutObservationSource::ArpCache;

				{
					ScoutLock lock(mutex);
					if (lock) {
						diag.arpCacheHits++;
						if (confirmed) {
							diag.arpProbeDiscoveries++;
						}
					}
				}

				observe(
				    interfaceSnapshot,
				    batch[i],
				    afterMappings[i].mac,
				    source,
				    confirmed,
				    scanId
				);
			}

			if (config.interBatchDelayMs > 0 &&
			    !waitInterruptible(config.interBatchDelayMs)) {
				return;
			}
		}
	}

	void performScan() {
		const uint64_t scanId = nextScanId++;
		const uint64_t startedAt = nowMs();

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.scanCount++;
			}
		}
		emitSimple(ScoutEventType::ScanStarted, ScoutStatus::Ok, scanId, "scan started");

		scout_internal::InterfaceSnapshot interfaces[scout_internal::MaxInterfaces]{};
		size_t interfaceCount = 0;
		const esp_err_t interfaceResult = scout_internal::collectInterfaces(
		    interfaces,
		    scout_internal::MaxInterfaces,
		    interfaceCount
		);
		if (interfaceResult != ESP_OK) {
			updateCoverage(false, 0, scanId);
			{
				ScoutLock lock(mutex);
				if (lock) {
					diag.skippedScanCount++;
					diag.lastScanDurationMs = nowMs() - startedAt;
				}
			}
			recordNetworkError(scanId, "failed to enumerate network interfaces");
			return;
		}

		updateCoverage(interfaceCount > 0, interfaceCount, scanId);
		if (interfaceCount == 0) {
			{
				ScoutLock lock(mutex);
				if (lock) {
					diag.skippedScanCount++;
					diag.lastScanDurationMs = nowMs() - startedAt;
				}
			}
			emitSimple(
			    ScoutEventType::ScanSkipped,
			    ScoutStatus::NetworkUnavailable,
			    scanId,
			    "no eligible ARP-capable interface"
			);
			return;
		}

		for (size_t i = 0; i < interfaceCount && !stopRequested.load(); ++i) {
			scanInterface(interfaces[i], scanId);
		}

		if (stopRequested.load()) {
			return;
		}

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.completedScanCount++;
				diag.lastScanDurationMs = nowMs() - startedAt;
			}
		}
		emitSimple(ScoutEventType::ScanCompleted, ScoutStatus::Ok, scanId, "scan completed");
	}

	void run() {
		{
			ScoutLock lock(mutex);
			if (lock) {
				state = ScoutState::Running;
				diag.state = state;
			}
		}

		uint64_t nextScanAt =
		    scanRequested.load() ? nowMs() : nowMs() + config.scanIntervalMs;

		while (!stopRequested.load()) {
			const uint64_t current = nowMs();
			const bool requested = scanRequested.exchange(false);
			if (requested || current >= nextScanAt) {
				performScan();
				nextScanAt = nowMs() + config.scanIntervalMs;
				continue;
			}

			const uint64_t remaining = nextScanAt - current;
			const uint32_t waitMs =
			    static_cast<uint32_t>(std::min<uint64_t>(remaining, 1000));
			(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(std::max<uint32_t>(waitMs, 1)));
		}

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.taskStackHighWaterMarkBytes = task.stackHighWaterMarkBytes();
			}
		}
		readyForDelete.store(true);
		(void)stopped.give();
		suspendForever();
	}

	static void taskEntry(void *context) {
		auto *self = static_cast<ScoutImpl *>(context);
		if (self == nullptr) {
			suspendForever();
		}
		self->run();
	}

	ScoutResult init(const ScoutConfig &incoming) {
		if (!mutex || !stopped) {
			return ScoutResult::failure(ScoutStatus::NoMemory, "failed to create synchronization");
		}
		if (!Strata::validPlacement(incoming.memory.allocation) ||
		    !Strata::validPlacement(incoming.memory.taskStack) ||
		    incoming.scanIntervalMs < MinScanIntervalMs ||
		    incoming.arpResponseWaitMs == 0 ||
		    incoming.maxDevices == 0 ||
		    incoming.maxHostsPerSubnet == 0 ||
		    incoming.arpBatchSize == 0 ||
		    !validStackSize(incoming.taskStackBytes)) {
			return ScoutResult::failure(ScoutStatus::InvalidConfig, "invalid Scout configuration");
		}

		{
			ScoutLock lock(mutex);
			if (!lock) {
				return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
			}
			if (initialized) {
				return ScoutResult::failure(
				    ScoutStatus::AlreadyInitialized,
				    "Scout is already initialized"
				);
			}
			config = incoming;
			state = ScoutState::Starting;
			diag = {};
			diag.state = state;
			diag.allocationPlacement = config.memory.allocation;
			diag.taskStackPlacement = config.memory.taskStack;
			coverageKnown = false;
			coverageAvailable = false;
			nextScanId = 1;
		}

		if (!allocateBuffers(incoming)) {
			ScoutLock lock(mutex);
			if (lock) {
				state = ScoutState::Stopped;
				diag.state = state;
			}
			return ScoutResult::failure(ScoutStatus::NoMemory, "failed to allocate Scout buffers");
		}

		stopRequested.store(false);
		scanRequested.store(incoming.scanOnInit);
		readyForDelete.store(false);

		task = Strata::FreeRTOS::Task::create(
		    &ScoutImpl::taskEntry,
		    this,
		    Strata::FreeRTOS::TaskConfig{
		        .name = TaskName,
		        .stackBytes = incoming.taskStackBytes,
		        .stackPlacement = incoming.memory.taskStack,
		        .priority = incoming.taskPriority,
		        .affinity = incoming.taskCore,
		    }
		);
		if (!task) {
			releaseBuffers();
			ScoutLock lock(mutex);
			if (lock) {
				state = ScoutState::Stopped;
				diag.state = state;
			}
			return ScoutResult::failure(ScoutStatus::TaskCreateFailed, "failed to create Scout task");
		}

		{
			ScoutLock lock(mutex);
			if (!lock) {
				return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
			}
			initialized = true;
			diag.registryRegion = Strata::regionOf(devices);
			diag.targetBufferRegion = Strata::regionOf(targets);
			diag.taskStackRegion = task.stackRegion();
		}

		return ScoutResult::success("Scout initialized");
	}

	ScoutResult deinit(uint32_t timeoutMs) {
		{
			ScoutLock lock(mutex);
			if (!lock) {
				return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
			}
			if (!initialized) {
				return ScoutResult::failure(
				    ScoutStatus::NotInitialized,
				    "Scout is not initialized"
				);
			}
			if (task.handle() == xTaskGetCurrentTaskHandle()) {
				return ScoutResult::failure(
				    ScoutStatus::Busy,
				    "Scout cannot deinitialize from its own task"
				);
			}
			state = ScoutState::Stopping;
			diag.state = state;
			stopRequested.store(true);
		}

		if (task.handle() != nullptr) {
			xTaskNotifyGive(task.handle());
		}

		if (!readyForDelete.load() && !stopped.take(timeoutTicks(timeoutMs))) {
			return ScoutResult::failure(ScoutStatus::Timeout, "Scout shutdown timed out");
		}

		{
			ScoutLock lock(mutex);
			if (lock && task) {
				diag.taskStackHighWaterMarkBytes = task.stackHighWaterMarkBytes();
				diag.taskStackRegion = task.stackRegion();
			}
		}
		task.reset();

		{
			ScoutLock lock(mutex);
			if (!lock) {
				return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
			}
			releaseBuffers();
			initialized = false;
			state = ScoutState::Stopped;
			diag.state = state;
			diag.deviceCount = 0;
			diag.registryRegion = Strata::Region::Unknown;
			diag.targetBufferRegion = Strata::Region::Unknown;
			diag.taskStackRegion = Strata::Region::Unknown;
		}

		return ScoutResult::success("Scout deinitialized");
	}
};

ScoutResult ScoutResult::success(const char *message) {
	return {ScoutStatus::Ok, message};
}

ScoutResult ScoutResult::failure(ScoutStatus status, const char *message) {
	return {status, message};
}

Scout::Scout()
    : _impl(Strata::makeUnique<ScoutImpl>(Strata::Placement::PreferExternal)) {
}

Scout::~Scout() {
	if (_impl && _impl->initialized) {
		(void)_impl->deinit(UINT32_MAX);
	}
}

ScoutResult Scout::init(const ScoutConfig &config) {
	if (!_impl) {
		return ScoutResult::failure(ScoutStatus::NoMemory, "failed to allocate Scout runtime");
	}
	return _impl->init(config);
}

ScoutResult Scout::deinit(uint32_t timeoutMs) {
	if (!_impl) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}
	return _impl->deinit(timeoutMs);
}

ScoutResult Scout::scanNow() {
	if (!_impl) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}

	ScoutLock lock(_impl->mutex);
	if (!lock) {
		return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
	}
	if (!_impl->initialized) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}
	if (_impl->state == ScoutState::Stopping) {
		return ScoutResult::failure(ScoutStatus::Busy, "Scout is stopping");
	}

	_impl->scanRequested.store(true);
	if (_impl->task.handle() != nullptr) {
		xTaskNotifyGive(_impl->task.handle());
	}
	return ScoutResult::success("scan requested");
}

bool Scout::isInitialized() const {
	if (!_impl) {
		return false;
	}
	ScoutLock lock(_impl->mutex);
	return lock && _impl->initialized;
}

bool Scout::running() const {
	return state() == ScoutState::Running;
}

ScoutState Scout::state() const {
	if (!_impl) {
		return ScoutState::Stopped;
	}
	ScoutLock lock(_impl->mutex);
	return lock ? _impl->state : ScoutState::Stopped;
}

size_t Scout::deviceCount() const {
	if (!_impl) {
		return 0;
	}
	ScoutLock lock(_impl->mutex);
	return lock ? _impl->deviceCount : 0;
}

ScoutResult Scout::deviceAt(size_t index, ScoutDeviceInfo &out) const {
	if (!_impl) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}
	ScoutLock lock(_impl->mutex);
	if (!lock) {
		return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
	}
	if (!_impl->initialized) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}
	if (index >= _impl->deviceCount) {
		return ScoutResult::failure(ScoutStatus::InvalidConfig, "device index is out of range");
	}
	out = _impl->devices[index].info;
	return ScoutResult::success();
}

ScoutResult Scout::findByMac(const ScoutMacAddress &mac, ScoutDeviceInfo &out) const {
	if (!mac.valid()) {
		return ScoutResult::failure(ScoutStatus::InvalidConfig, "MAC address is invalid");
	}
	if (!_impl) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}

	ScoutLock lock(_impl->mutex);
	if (!lock) {
		return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
	}
	if (!_impl->initialized) {
		return ScoutResult::failure(ScoutStatus::NotInitialized, "Scout is not initialized");
	}

	const size_t index = _impl->findDeviceByMac(mac.bytes);
	if (index == SIZE_MAX) {
		return ScoutResult::failure(ScoutStatus::InvalidConfig, "device not found");
	}
	out = _impl->devices[index].info;
	return ScoutResult::success();
}

ScoutDiagnostics Scout::diagnostics() const {
	if (!_impl) {
		return {};
	}
	ScoutLock lock(_impl->mutex);
	if (!lock) {
		return {};
	}

	ScoutDiagnostics snapshot = _impl->diag;
	snapshot.state = _impl->state;
	snapshot.coverageAvailable = _impl->coverageAvailable;
	snapshot.deviceCount = _impl->deviceCount;
	snapshot.registryRegion = Strata::regionOf(_impl->devices);
	snapshot.targetBufferRegion = Strata::regionOf(_impl->targets);
	if (_impl->task) {
		snapshot.taskStackRegion = _impl->task.stackRegion();
		snapshot.taskStackHighWaterMarkBytes = _impl->task.stackHighWaterMarkBytes();
	}
	return snapshot;
}

void Scout::onEvent(ScoutEventCallback callback) {
	if (!_impl) {
		return;
	}
	ScoutLock lock(_impl->mutex);
	if (lock) {
		_impl->callback = std::move(callback);
	}
}

const char *Scout::statusToString(ScoutStatus status) const {
	switch (status) {
	case ScoutStatus::Ok:
		return "ok";
	case ScoutStatus::NotInitialized:
		return "not_initialized";
	case ScoutStatus::AlreadyInitialized:
		return "already_initialized";
	case ScoutStatus::InvalidConfig:
		return "invalid_config";
	case ScoutStatus::NoMemory:
		return "no_memory";
	case ScoutStatus::TaskCreateFailed:
		return "task_create_failed";
	case ScoutStatus::Busy:
		return "busy";
	case ScoutStatus::Timeout:
		return "timeout";
	case ScoutStatus::NetworkUnavailable:
		return "network_unavailable";
	case ScoutStatus::DeviceLimitReached:
		return "device_limit_reached";
	case ScoutStatus::InternalError:
		return "internal_error";
	}
	return "unknown";
}

const char *Scout::stateToString(ScoutState state) const {
	switch (state) {
	case ScoutState::Stopped:
		return "stopped";
	case ScoutState::Starting:
		return "starting";
	case ScoutState::Running:
		return "running";
	case ScoutState::Stopping:
		return "stopping";
	}
	return "unknown";
}

const char *Scout::eventTypeToString(ScoutEventType type) const {
	switch (type) {
	case ScoutEventType::ScanStarted:
		return "scan_started";
	case ScoutEventType::ScanCompleted:
		return "scan_completed";
	case ScoutEventType::ScanSkipped:
		return "scan_skipped";
	case ScoutEventType::DeviceDiscovered:
		return "device_discovered";
	case ScoutEventType::DeviceObserved:
		return "device_observed";
	case ScoutEventType::DeviceChanged:
		return "device_changed";
	case ScoutEventType::CoverageLost:
		return "coverage_lost";
	case ScoutEventType::CoverageRestored:
		return "coverage_restored";
	case ScoutEventType::Error:
		return "error";
	}
	return "unknown";
}
