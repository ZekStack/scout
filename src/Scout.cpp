#include "Scout.h"

#include "internal/ScoutLogic.h"
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
constexpr const char *CleanupTaskName = "scout_cleanup";
constexpr uint32_t StopPollMs = 20;
constexpr uint32_t MinScanIntervalMs = 1000;
constexpr uint32_t MinTaskStackBytes = 4096;
constexpr uint32_t CleanupTaskStackBytes = 4096;

uint64_t nowMs() {
	return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
}

bool validStackSize(size_t stackBytes) {
	return stackBytes >= MinTaskStackBytes && (stackBytes % sizeof(StackType_t)) == 0;
}

TickType_t timeoutTicks(uint32_t timeoutMs) {
	return timeoutMs == UINT32_MAX ? portMAX_DELAY : pdMS_TO_TICKS(timeoutMs);
}

class DeferredCleanupService {
  public:
	bool ensureStarted();
	void enqueue(ScoutImpl *impl);

  private:
	static void taskEntry(void *context);
	void run();

	std::atomic_flag startLock = ATOMIC_FLAG_INIT;
	std::atomic<ScoutImpl *> pending{nullptr};
	Strata::FreeRTOS::Task task;
};

DeferredCleanupService *cleanupService();

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
	std::atomic<bool> startReady{false};

	ScoutImpl *deferredNext = nullptr;

	ScoutState state = ScoutState::Stopped;
	bool initialized = false;
	bool shutdownInProgress = false;
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
		const scout_internal::Ipv4TargetResult result = scout_internal::buildIpv4Targets(
		    lwip_ntohl(interfaceSnapshot.ipv4),
		    lwip_ntohl(interfaceSnapshot.netmask),
		    config.maxHostsPerSubnet,
		    targets,
		    config.maxHostsPerSubnet
		);

		if (result.status == scout_internal::Ipv4TargetStatus::TooLarge) {
			return SIZE_MAX;
		}
		if (result.status != scout_internal::Ipv4TargetStatus::Ok) {
			return 0;
		}

		for (size_t i = 0; i < result.count; ++i) {
			targets[i] = lwip_htonl(targets[i]);
		}
		return result.count;
	}

	size_t findDeviceByMac(const uint8_t *mac) const {
		for (size_t i = 0; i < deviceCount; ++i) {
			if (scout_internal::macEquals(devices[i].info.mac, mac)) {
				return i;
			}
		}
		return SIZE_MAX;
	}

	size_t findEndpointOwner(
	    uint8_t interfaceIndex,
	    uint32_t ipv4,
	    size_t excludedIndex
	) const {
		for (size_t i = 0; i < deviceCount; ++i) {
			if (i == excludedIndex) {
				continue;
			}
			const auto &info = devices[i].info;
			for (size_t endpointIndex = 0; endpointIndex < info.endpointCount;
			     ++endpointIndex) {
				const auto &endpoint = info.endpoints[endpointIndex];
				if (endpoint.interfaceIndex == interfaceIndex &&
				    endpoint.ipv4.value == ipv4) {
					return i;
				}
			}
		}
		return SIZE_MAX;
	}

	void removeDeviceAtLocked(size_t index) {
		if (index >= deviceCount) {
			return;
		}
		const size_t lastIndex = deviceCount - 1;
		if (index != lastIndex) {
			devices[index] = devices[lastIndex];
		}
		devices[lastIndex].info = {};
		deviceCount--;
		diag.deviceCount = deviceCount;
	}

	void deduplicateRegistryLocked() {
		for (size_t i = 0; i < deviceCount; ++i) {
			size_t j = i + 1;
			while (j < deviceCount) {
				if (!scout_internal::macEquals(
				        devices[i].info.mac,
				        devices[j].info.mac.bytes
				    )) {
					j++;
					continue;
				}

				scout_internal::mergeDeviceInfo(devices[i].info, devices[j].info);
				removeDeviceAtLocked(j);
				diag.deduplicatedDeviceCount++;
			}
		}

		bool changed = true;
		while (changed) {
			changed = false;
			for (size_t i = 0; i < deviceCount && !changed; ++i) {
				for (size_t leftIndex = 0;
				     leftIndex < devices[i].info.endpointCount && !changed;
				     ++leftIndex) {
					const auto left = devices[i].info.endpoints[leftIndex];
					for (size_t j = i + 1; j < deviceCount && !changed; ++j) {
						for (size_t rightIndex = 0;
						     rightIndex < devices[j].info.endpointCount;
						     ++rightIndex) {
							const auto right = devices[j].info.endpoints[rightIndex];
							if (left.interfaceIndex != right.interfaceIndex ||
							    left.ipv4 != right.ipv4) {
								continue;
							}

							const bool keepLeft =
							    left.lastSeenAtMs > right.lastSeenAtMs ||
							    (left.lastSeenAtMs == right.lastSeenAtMs &&
							     devices[i].info.lastSeenAtMs >=
							         devices[j].info.lastSeenAtMs);
							auto &loser = keepLeft ? devices[j].info : devices[i].info;
							(void)scout_internal::removeEndpoint(
							    loser,
							    left.interfaceIndex,
							    left.ipv4.value
							);
							diag.endpointReassignmentCount++;
							changed = true;
							break;
						}
					}
				}
		}
	}

	void expireStaleDevices(uint64_t scanId, uint64_t currentTime) {
		size_t index = 0;
		while (!stopRequested.load()) {
			ScoutEvent event;
			bool foundExpired = false;
			{
				ScoutLock lock(mutex);
				if (!lock) {
					return;
				}
				while (index < deviceCount &&
				       !scout_internal::deviceExpired(
				           devices[index].info,
				           currentTime,
				           config.deviceMaxAgeMs
				       )) {
					index++;
				}
				if (index < deviceCount) {
					event.type = ScoutEventType::DeviceExpired;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.hasDevice = true;
					event.device = devices[index].info;
					event.message = "device registry entry expired";
					removeDeviceAtLocked(index);
					diag.expiredDeviceCount++;
					foundExpired = true;
				}
			}

			if (!foundExpired) {
				break;
			}
			emit(event);
		}
	}

	void maintainRegistry(uint64_t scanId) {
		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}
			deduplicateRegistryLocked();
		}
		expireStaleDevices(scanId, nowMs());
	}

	void observe(
	    const scout_internal::InterfaceSnapshot &interfaceSnapshot,
	    uint32_t ipv4,
	    const uint8_t *mac,
	    ScoutObservationSource source,
	    bool confirmed,
	    uint64_t scanId
	) {
		ScoutEvent events[2]{};
		size_t eventCount = 0;
		const uint64_t observedAt = nowMs();

		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}

			size_t index = findDeviceByMac(mac);
			bool discovered = false;
			if (index == SIZE_MAX) {
				if (deviceCount >= deviceCapacity) {
					diag.deviceLimitDrops++;
					auto &event = events[eventCount++];
					event.type = ScoutEventType::Error;
					event.status = ScoutStatus::DeviceLimitReached;
					event.scanId = scanId;
					event.source = source;
					event.message = "device registry limit reached";
				} else {
					index = deviceCount++;
					discovered = true;
					auto &info = devices[index].info;
					info = {};
					info.key.kind = ScoutIdentityKind::Mac;
					info.key.mac = scout_internal::macFromBytes(mac);
					info.mac = info.key.mac;
					info.firstSeenAtMs = observedAt;
					info.lastSeenAtMs = observedAt;
					info.lastConfirmedAtMs = confirmed ? observedAt : 0;
					info.observationSources = scoutObservationMask(source);
					info.observationCount = 1;

					diag.deviceCount = deviceCount;
					diag.peakDeviceCount = std::max(diag.peakDeviceCount, deviceCount);
				}
			} else {
				auto &info = devices[index].info;
				info.lastSeenAtMs = observedAt;
				if (confirmed) {
					info.lastConfirmedAtMs = observedAt;
				}
				info.observationSources |= scoutObservationMask(source);
				if (info.observationCount != UINT32_MAX) {
					info.observationCount++;
				}
			}

			if (index != SIZE_MAX) {
				const size_t previousOwner =
				    findEndpointOwner(interfaceSnapshot.index, ipv4, index);
				if (previousOwner != SIZE_MAX &&
				    scout_internal::removeEndpoint(
				        devices[previousOwner].info,
				        interfaceSnapshot.index,
				        ipv4
				    )) {
					diag.endpointReassignmentCount++;
					auto &event = events[eventCount++];
					event.type = ScoutEventType::DeviceChanged;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = devices[previousOwner].info;
					event.message = "device endpoint reassigned";
				}

				auto &info = devices[index].info;
				const bool endpointChanged = scout_internal::upsertEndpoint(
				    info,
				    interfaceSnapshot.index,
				    interfaceSnapshot.name,
				    ipv4,
				    observedAt
				);

				if (discovered) {
					auto &event = events[eventCount++];
					event.type = ScoutEventType::DeviceDiscovered;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = info;
					event.message = confirmed ? "device discovered by active ARP"
					                          : "device discovered from ARP cache";
				} else if (endpointChanged || confirmed) {
					auto &event = events[eventCount++];
					event.type = endpointChanged ? ScoutEventType::DeviceChanged
					                            : ScoutEventType::DeviceObserved;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = info;
					event.message = endpointChanged ? "device endpoint changed"
					                                : "device actively observed";
				}
			}
		}

		for (size_t i = 0; i < eventCount; ++i) {
			emit(events[i]);
			if (stopRequested.load()) {
				break;
			}
		}
	}

	ScoutStatus scanInterface(
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
			return ScoutStatus::InvalidConfig;
		}
		if (targetCount == 0) {
			{
				ScoutLock lock(mutex);
				if (lock) {
					diag.skippedScanCount++;
				}
			}
			emitSimple(
			    ScoutEventType::ScanSkipped,
			    ScoutStatus::NetworkUnavailable,
			    scanId,
			    "subnet has no ARP targets"
			);
			return ScoutStatus::NetworkUnavailable;
		}

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.hostsConsidered += targetCount;
			}
		}

		const size_t batchSize = mappingCapacity;
		bool hadRequestFailures = false;
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
			if (beforeResult != ESP_OK) {
				recordNetworkError(scanId, "failed to inspect ARP cache");
				return ScoutStatus::InternalError;
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
			hadRequestFailures |= requestStats.failed > 0;
			if (requestResult != ESP_OK) {
				recordNetworkError(scanId, "failed to send ARP requests");
				return ScoutStatus::InternalError;
			}

			if (!waitInterruptible(config.arpResponseWaitMs)) {
				return ScoutStatus::Busy;
			}

			const esp_err_t afterResult = scout_internal::lookupArpMappings(
			    interfaceSnapshot.index,
			    batch,
			    count,
			    afterMappings
			);
			if (afterResult != ESP_OK) {
				recordNetworkError(scanId, "failed to read ARP results");
				return ScoutStatus::InternalError;
			}

			for (size_t i = 0; i < count; ++i) {
				if (!afterMappings[i].found) {
					continue;
				}

				const bool wasCached = beforeMappings[i].found &&
				                       scout_internal::macEquals(beforeMappings[i].mac, afterMappings[i].mac);
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
				return ScoutStatus::Busy;
			}
		}
		if (hadRequestFailures) {
			recordNetworkError(scanId, "one or more ARP requests failed");
			return ScoutStatus::InternalError;
		}
		return ScoutStatus::Ok;
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

		if (interfaceCount == 0) {
			updateCoverage(false, 0, scanId);
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

		ScoutStatus scanStatus = ScoutStatus::Ok;
		for (size_t i = 0; i < interfaceCount && !stopRequested.load(); ++i) {
			const ScoutStatus interfaceStatus = scanInterface(interfaces[i], scanId);
			if (interfaceStatus == ScoutStatus::InternalError ||
			    (scanStatus == ScoutStatus::Ok && interfaceStatus != ScoutStatus::Ok)) {
				scanStatus = interfaceStatus;
			}
		}

		if (stopRequested.load()) {
			return;
		}

		// A partial or failed sweep cannot support absence inference.
		updateCoverage(scanStatus == ScoutStatus::Ok, interfaceCount, scanId);

		{
			ScoutLock lock(mutex);
			if (lock) {
				if (scanStatus == ScoutStatus::Ok) {
					diag.completedScanCount++;
				}
				diag.lastScanDurationMs = nowMs() - startedAt;
			}
		}
		emitSimple(
		    ScoutEventType::ScanCompleted,
		    scanStatus,
		    scanId,
		    scanStatus == ScoutStatus::Ok ? "scan completed"
		                                  : "scan completed with skipped or failed interfaces"
		);
	}

	void run() {
		while (!startReady.load(std::memory_order_acquire)) {
			vTaskDelay(1);
		}

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
		if (state != ScoutState::Stopped) {
			return ScoutResult::failure(
			    ScoutStatus::Busy,
			    "Scout is starting or stopping"
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

		// Keep buffer and task publication under the same lock used by snapshot readers.
		if (!allocateBuffers(incoming)) {
			state = ScoutState::Stopped;
			diag.state = state;
			return ScoutResult::failure(ScoutStatus::NoMemory, "failed to allocate Scout buffers");
		}

		stopRequested.store(false);
		scanRequested.store(incoming.scanOnInit);
		startReady.store(false, std::memory_order_release);
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
			state = ScoutState::Stopped;
			diag.state = state;
			return ScoutResult::failure(ScoutStatus::TaskCreateFailed, "failed to create Scout task");
		}

		initialized = true;
		diag.registryRegion = Strata::regionOf(devices);
		diag.targetBufferRegion = Strata::regionOf(targets);
		diag.taskStackRegion = task.stackRegion();
		startReady.store(true, std::memory_order_release);
		return ScoutResult::success("Scout initialized");
	}

	ScoutResult deinit(uint32_t timeoutMs) {
		Strata::FreeRTOS::TaskHandle taskHandle = nullptr;
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
			taskHandle = task.handle();
			if (taskHandle == xTaskGetCurrentTaskHandle()) {
				return ScoutResult::failure(
				    ScoutStatus::Busy,
				    "Scout cannot deinitialize from its own task"
				);
			}
			if (shutdownInProgress) {
				return ScoutResult::failure(ScoutStatus::Busy, "Scout shutdown is in progress");
			}
			shutdownInProgress = true;
			state = ScoutState::Stopping;
			diag.state = state;
			stopRequested.store(true);
		}

		if (taskHandle != nullptr) {
			xTaskNotifyGive(taskHandle);
		}

		if (!stopped.take(timeoutTicks(timeoutMs))) {
			ScoutLock lock(mutex);
			if (lock) {
				shutdownInProgress = false;
			}
			return ScoutResult::failure(ScoutStatus::Timeout, "Scout shutdown timed out");
		}

		ScoutLock lock(mutex);
		if (!lock) {
			return ScoutResult::failure(ScoutStatus::InternalError, "failed to lock Scout");
		}
		if (task) {
			diag.taskStackHighWaterMarkBytes = task.stackHighWaterMarkBytes();
			diag.taskStackRegion = task.stackRegion();
		}
		task.reset();
		releaseBuffers();
		initialized = false;
		shutdownInProgress = false;
		state = ScoutState::Stopped;
		diag.state = state;
		diag.deviceCount = 0;
		diag.registryRegion = Strata::Region::Unknown;
		diag.targetBufferRegion = Strata::Region::Unknown;
		diag.taskStackRegion = Strata::Region::Unknown;
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
		return ScoutResult::failure(ScoutStatus::NotFound, "device index is out of range");
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
		return ScoutResult::failure(ScoutStatus::NotFound, "device not found");
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
	case ScoutStatus::NotFound:
		return "not_found";
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
