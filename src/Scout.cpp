#include "Scout.h"

#include "internal/ScoutEnrichment.h"
#include "internal/ScoutLogic.h"
#include "internal/ScoutNetwork.h"
#include "internal/ScoutProviders.h"

#include <strata/freertos/BinarySemaphore.h>
#include <strata/freertos/Mutex.h>
#include <strata/freertos/Task.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <cstdio>
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
	Strata::UniquePtr<ScoutDeviceDetails> details;
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
	scout_internal::ProviderTarget *providerTargets = nullptr;
	ScoutIdentityGroup *identityGroups = nullptr;
	ScoutIdentityRelation *identityRelations = nullptr;
	size_t *identityParents = nullptr;
	char *httpScratch = nullptr;

	size_t deviceCapacity = 0;
	size_t deviceCount = 0;
	size_t mappingCapacity = 0;
	size_t providerTargetCapacity = 0;
	size_t identityGroupCountValue = 0;
	size_t identityRelationCountValue = 0;
	size_t identityRelationCapacity = 0;
	size_t httpScratchCapacity = 0;

	ScoutEventCallback callback;
	ScoutOuiLookupCallback ouiLookup;
	size_t icmpCursor = 0;
	size_t reverseDnsCursor = 0;
	size_t nbnsCursor = 0;
	size_t mdnsServiceCursor = 0;

	std::atomic<bool> stopRequested{false};
	std::atomic<bool> scanRequested{false};
	std::atomic<bool> startReady{false};

	ScoutImpl *deferredNext = nullptr;

	ScoutState state = ScoutState::Stopped;
	bool initialized = false;
	bool shutdownInProgress = false;
	bool coverageKnown = false;
	bool coverageAvailable = false;
	bool identityDirty = false;

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
		Strata::free(providerTargets);
		providerTargets = nullptr;
		Strata::free(identityGroups);
		identityGroups = nullptr;
		Strata::free(identityRelations);
		identityRelations = nullptr;
		Strata::free(identityParents);
		identityParents = nullptr;
		Strata::free(httpScratch);
		httpScratch = nullptr;
		deviceCapacity = 0;
		deviceCount = 0;
		mappingCapacity = 0;
		providerTargetCapacity = 0;
		identityGroupCountValue = 0;
		identityRelationCountValue = 0;
		identityRelationCapacity = 0;
		httpScratchCapacity = 0;
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

		targets =
		    Strata::allocateArray<uint32_t>(incoming.maxHostsPerSubnet, incoming.memory.allocation);
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

		providerTargetCapacity = incoming.maxDevices * SCOUT_MAX_ENDPOINTS_PER_DEVICE;
		providerTargets = Strata::allocateArray<scout_internal::ProviderTarget>(
		    providerTargetCapacity,
		    incoming.memory.allocation
		);
		identityGroups = Strata::allocateArray<ScoutIdentityGroup>(
		    incoming.maxDevices,
		    incoming.memory.allocation
		);
		identityRelations = Strata::allocateArray<ScoutIdentityRelation>(
		    incoming.maxIdentityRelations,
		    incoming.memory.allocation
		);
		identityParents =
		    Strata::allocateArray<size_t>(incoming.maxDevices, incoming.memory.allocation);
		identityRelationCapacity = incoming.maxIdentityRelations;

		if (providerTargets == nullptr || identityGroups == nullptr ||
		    identityRelations == nullptr || identityParents == nullptr) {
			releaseBuffers();
			return false;
		}

		if (incoming.providers.ssdp.enabled && incoming.providers.ssdp.fetchDeviceDescription &&
		    incoming.providers.ssdp.maxDescriptionBytes > 0) {
			httpScratchCapacity = incoming.providers.ssdp.maxDescriptionBytes;
			httpScratch =
			    Strata::allocateArray<char>(httpScratchCapacity, incoming.memory.allocation);
			if (httpScratch == nullptr) {
				releaseBuffers();
				return false;
			}
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

	void emitSimple(ScoutEventType type, ScoutStatus status, uint64_t scanId, const char *message) {
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
				event.type =
				    available ? ScoutEventType::CoverageRestored : ScoutEventType::CoverageLost;
				event.status = available ? ScoutStatus::Ok : ScoutStatus::NetworkUnavailable;
				event.scanId = scanId;
				event.message =
				    available ? "network coverage available" : "no eligible ARP-capable interface";
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

	ScoutDeviceDetails *ensureDetailsLocked(size_t index) {
		if (index >= deviceCount) {
			return nullptr;
		}
		if (!devices[index].details) {
			devices[index].details =
			    Strata::makeUnique<ScoutDeviceDetails>(config.memory.allocation);
			if (!devices[index].details) {
				diag.enrichmentAllocationFailures++;
				return nullptr;
			}
			devices[index].details->locallyAdministeredMac =
			    scout_internal::macIsLocallyAdministered(devices[index].info.mac);
			devices[index].details->multicastMac =
			    scout_internal::macIsMulticast(devices[index].info.mac);
		}
		return devices[index].details.get();
	}

	size_t findEndpointOwner(uint8_t interfaceIndex, uint32_t ipv4, size_t excludedIndex) const {
		for (size_t i = 0; i < deviceCount; ++i) {
			if (i == excludedIndex) {
				continue;
			}
			const auto &info = devices[i].info;
			for (size_t endpointIndex = 0; endpointIndex < info.endpointCount; ++endpointIndex) {
				const auto &endpoint = info.endpoints[endpointIndex];
				if (endpoint.interfaceIndex == interfaceIndex && endpoint.ipv4.value == ipv4) {
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
			devices[index].info = devices[lastIndex].info;
			devices[index].details = std::move(devices[lastIndex].details);
		}
		devices[lastIndex].info = {};
		devices[lastIndex].details.reset();
		deviceCount--;
		diag.deviceCount = deviceCount;
		identityDirty = true;
	}

	void deduplicateRegistryLocked() {
		for (size_t i = 0; i < deviceCount; ++i) {
			size_t j = i + 1;
			while (j < deviceCount) {
				if (!scout_internal::macEquals(devices[i].info.mac, devices[j].info.mac.bytes)) {
					j++;
					continue;
				}

				scout_internal::mergeDeviceInfo(devices[i].info, devices[j].info);
				if (devices[j].details) {
					auto *targetDetails = ensureDetailsLocked(i);
					if (targetDetails != nullptr) {
						scout_internal::mergeDeviceDetails(*targetDetails, *devices[j].details);
					}
				}
				removeDeviceAtLocked(j);
				diag.deduplicatedDeviceCount++;
			}
		}

		bool changed = true;
		while (changed) {
			changed = false;
			for (size_t i = 0; i < deviceCount && !changed; ++i) {
				for (size_t leftIndex = 0; leftIndex < devices[i].info.endpointCount && !changed;
				     ++leftIndex) {
					const auto left = devices[i].info.endpoints[leftIndex];
					for (size_t j = i + 1; j < deviceCount && !changed; ++j) {
						for (size_t rightIndex = 0; rightIndex < devices[j].info.endpointCount;
						     ++rightIndex) {
							const auto right = devices[j].info.endpoints[rightIndex];
							if (left.interfaceIndex != right.interfaceIndex ||
							    left.ipv4 != right.ipv4) {
								continue;
							}

							const bool keepLeft =
							    left.lastSeenAtMs > right.lastSeenAtMs ||
							    (left.lastSeenAtMs == right.lastSeenAtMs &&
							     devices[i].info.lastSeenAtMs >= devices[j].info.lastSeenAtMs);
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
				while (index < deviceCount && !scout_internal::deviceExpired(
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
		flushIdentityIfDirty();
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
					devices[index].details.reset();
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
				if (previousOwner != SIZE_MAX && scout_internal::removeEndpoint(
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
					event.changes = scoutDeviceChangeMask(ScoutDeviceChange::Endpoint);
					event.message = "device endpoint reassigned";
				}

				auto &info = devices[index].info;
				const bool endpointChanged = scout_internal::upsertEndpoint(
				    info,
				    interfaceSnapshot.index,
				    interfaceSnapshot.name,
				    interfaceSnapshot.key,
				    interfaceSnapshot.type,
				    ipv4,
				    observedAt,
				    source,
				    confirmed
				);

				if (discovered) {
					auto &event = events[eventCount++];
					event.type = ScoutEventType::DeviceDiscovered;
					event.status = ScoutStatus::Ok;
					event.scanId = scanId;
					event.source = source;
					event.hasDevice = true;
					event.device = info;
					event.changes = scoutDeviceChangeMask(ScoutDeviceChange::Endpoint);
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
					event.changes = endpointChanged
					                    ? scoutDeviceChangeMask(ScoutDeviceChange::Endpoint)
					                    : scoutDeviceChangeMask(ScoutDeviceChange::Confirmation);
					event.message =
					    endpointChanged ? "device endpoint changed" : "device actively observed";
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

	ScoutEndpoint *findObservationEndpointLocked(
	    ScoutDeviceInfo &info, const scout_internal::EnrichmentObservation &observation
	) {
		for (size_t i = 0; i < info.endpointCount; ++i) {
			auto &endpoint = info.endpoints[i];
			if (endpoint.interfaceIndex != observation.interfaceIndex) {
				continue;
			}
			if (observation.ipv4.valid() && endpoint.ipv4 != observation.ipv4) {
				continue;
			}
			return &endpoint;
		}
		return nullptr;
	}

	void accumulateProviderStats(
	    ScoutProviderDiagnostics &target, const scout_internal::ProviderRunStats &run
	) {
		ScoutLock lock(mutex);
		if (!lock) {
			return;
		}
		target.runs++;
		target.observations += run.observations;
		target.errors += run.errors;
		target.timeouts += run.timeouts;
		target.droppedObservations += run.dropped;
	}

	size_t snapshotProviderTargets() {
		ScoutLock lock(mutex);
		if (!lock || providerTargets == nullptr) {
			return 0;
		}
		size_t count = 0;
		for (size_t deviceIndex = 0; deviceIndex < deviceCount; ++deviceIndex) {
			const auto &info = devices[deviceIndex].info;
			for (size_t endpointIndex = 0; endpointIndex < info.endpointCount; ++endpointIndex) {
				if (count >= providerTargetCapacity) {
					return count;
				}
				const auto &endpoint = info.endpoints[endpointIndex];
				if (!endpoint.ipv4.valid()) {
					continue;
				}
				auto &target = providerTargets[count++];
				target = {};
				target.mac = info.mac;
				target.ipv4 = endpoint.ipv4;
				target.interfaceIndex = endpoint.interfaceIndex;
				scout_internal::copyText(
				    target.interfaceKey,
				    sizeof(target.interfaceKey),
				    endpoint.interfaceKey
				);
			}
		}
		return count;
	}

	uint64_t identityStateHashLocked() const {
		constexpr uint64_t OffsetBasis = 1469598103934665603ULL;
		constexpr uint64_t Prime = 1099511628211ULL;
		uint64_t hash = OffsetBasis;
		auto mix = [&](uint8_t byte) {
			hash ^= byte;
			hash *= Prime;
		};
		for (size_t i = 0; i < identityGroupCountValue; ++i) {
			const auto &group = identityGroups[i];
			for (size_t byte = 0; byte < sizeof(group.runtimeId); ++byte) {
				mix(static_cast<uint8_t>(group.runtimeId >> (byte * 8U)));
			}
			mix(static_cast<uint8_t>(group.memberCount));
			mix(static_cast<uint8_t>(group.confidence));
		}
		for (size_t i = 0; i < identityRelationCountValue; ++i) {
			const auto &relation = identityRelations[i];
			for (uint8_t byte : relation.first.mac.bytes) {
				mix(byte);
			}
			for (uint8_t byte : relation.second.mac.bytes) {
				mix(byte);
			}
			mix(static_cast<uint8_t>(relation.evidence.type));
			mix(static_cast<uint8_t>(relation.evidence.confidence));
		}
		return hash;
	}

	size_t identityRoot(size_t index) {
		while (identityParents[index] != index) {
			identityParents[index] = identityParents[identityParents[index]];
			index = identityParents[index];
		}
		return index;
	}

	void unionIdentity(size_t left, size_t right) {
		const size_t leftRoot = identityRoot(left);
		const size_t rightRoot = identityRoot(right);
		if (leftRoot != rightRoot) {
			identityParents[rightRoot] = leftRoot;
		}
	}

	void rebuildIdentityState() {
		ScoutEvent event{};
		bool changed = false;
		{
			ScoutLock lock(mutex);
			if (!lock || identityGroups == nullptr || identityRelations == nullptr ||
			    identityParents == nullptr) {
				return;
			}
			const uint64_t oldHash = identityStateHashLocked();
			identityGroupCountValue = 0;
			identityRelationCountValue = 0;
			for (size_t i = 0; i < deviceCount; ++i) {
				identityParents[i] = i;
			}

			for (size_t left = 0; left < deviceCount; ++left) {
				if (!devices[left].details) {
					continue;
				}
				for (size_t right = left + 1; right < deviceCount; ++right) {
					if (!devices[right].details) {
						continue;
					}
					ScoutIdentityRelation relation{};
					if (!scout_internal::identityRelation(
					        devices[left].info,
					        *devices[left].details,
					        devices[right].info,
					        *devices[right].details,
					        relation
					    )) {
						continue;
					}
					if (identityRelationCountValue < identityRelationCapacity) {
						identityRelations[identityRelationCountValue++] = relation;
					} else {
						diag.identityRelationDrops++;
					}
					if (static_cast<uint8_t>(relation.evidence.confidence) >=
					    static_cast<uint8_t>(ScoutIdentityConfidence::Strong)) {
						unionIdentity(left, right);
					}
				}
			}

			for (size_t rootCandidate = 0; rootCandidate < deviceCount; ++rootCandidate) {
				if (identityRoot(rootCandidate) != rootCandidate) {
					continue;
				}
				ScoutIdentityGroup group{};
				for (size_t i = 0; i < deviceCount; ++i) {
					if (identityRoot(i) != rootCandidate) {
						continue;
					}
					if (group.memberCount < SCOUT_MAX_IDENTITY_GROUP_MEMBERS) {
						group.members[group.memberCount++] = devices[i].info.key;
					}
				}
				if (group.memberCount < 2) {
					continue;
				}
				std::sort(
				    group.members,
				    group.members + group.memberCount,
				    [](const ScoutDeviceKey &left, const ScoutDeviceKey &right) {
					    return std::memcmp(
					               left.mac.bytes,
					               right.mac.bytes,
					               sizeof(left.mac.bytes)
					           ) < 0;
				    }
				);
				group.runtimeId =
				    scout_internal::identityGroupRuntimeId(group.members, group.memberCount);
				group.confidence = ScoutIdentityConfidence::Strong;

				auto contains = [&](const ScoutDeviceKey &key) {
					for (size_t i = 0; i < group.memberCount; ++i) {
						if (group.members[i] == key) {
							return true;
						}
					}
					return false;
				};
				for (size_t relationIndex = 0; relationIndex < identityRelationCountValue &&
				                               group.evidenceCount < SCOUT_MAX_IDENTITY_EVIDENCE;
				     ++relationIndex) {
					const auto &relation = identityRelations[relationIndex];
					if (!contains(relation.first) || !contains(relation.second) ||
					    static_cast<uint8_t>(relation.evidence.confidence) <
					        static_cast<uint8_t>(ScoutIdentityConfidence::Strong)) {
						continue;
					}
					group.evidence[group.evidenceCount++] = relation.evidence;
					if (static_cast<uint8_t>(relation.evidence.confidence) >
					    static_cast<uint8_t>(group.confidence)) {
						group.confidence = relation.evidence.confidence;
					}
				}
				identityGroups[identityGroupCountValue++] = group;
			}

			diag.identityGroupCount = identityGroupCountValue;
			diag.identityRelationCount = identityRelationCountValue;
			const uint64_t newHash = identityStateHashLocked();
			changed = oldHash != newHash;
			identityDirty = false;
			if (changed) {
				diag.identityGroupChanges++;
				event.type = ScoutEventType::IdentityGroupChanged;
				event.status = ScoutStatus::Ok;
				event.changes = scoutDeviceChangeMask(ScoutDeviceChange::Identity);
				event.message = "device identity relationships changed";
			}
		}
		if (changed) {
			emit(event);
		}
	}

	void flushIdentityIfDirty() {
		bool dirty = false;
		{
			ScoutLock lock(mutex);
			dirty = lock && identityDirty;
		}
		if (dirty) {
			rebuildIdentityState();
		}
	}

	void applyEnrichmentObservation(
	    const ScoutMacAddress &mac, const scout_internal::EnrichmentObservation &observation
	) {
		ScoutEvent event{};
		bool shouldEmit = false;
		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}
			const size_t index = findDeviceByMac(mac.bytes);
			if (index == SIZE_MAX) {
				return;
			}

			auto &record = devices[index];
			auto &info = record.info;
			auto *detailsPtr = ensureDetailsLocked(index);
			if (detailsPtr == nullptr) {
				return;
			}
			auto &details = *detailsPtr;
			const uint64_t observedAt = nowMs();
			ScoutDeviceChange changes = ScoutDeviceChange::None;

			const bool directObservation = observation.source == ScoutObservationSource::Icmp ||
			                               observation.source == ScoutObservationSource::Mdns ||
			                               observation.source == ScoutObservationSource::Ssdp ||
			                               observation.source == ScoutObservationSource::Nbns;
			if (directObservation) {
				info.lastSeenAtMs = std::max(info.lastSeenAtMs, observedAt);
				info.observationSources |= scoutObservationMask(observation.source);
				if (info.observationCount != UINT32_MAX) {
					info.observationCount++;
				}
			}
			if (observation.confirmed) {
				info.lastConfirmedAtMs = std::max(info.lastConfirmedAtMs, observedAt);
				changes |= ScoutDeviceChange::Confirmation;
			}

			if (auto *endpoint = findObservationEndpointLocked(info, observation);
			    endpoint != nullptr) {
				if (directObservation) {
					endpoint->lastSeenAtMs = std::max(endpoint->lastSeenAtMs, observedAt);
					endpoint->observationSources |= scoutObservationMask(observation.source);
				}
				if (observation.confirmed) {
					endpoint->lastConfirmedAtMs = std::max(endpoint->lastConfirmedAtMs, observedAt);
				}
				for (size_t i = 0; i < observation.ipv6Count; ++i) {
					if (scout_internal::upsertIpv6(*endpoint, observation.ipv6[i])) {
						changes |= ScoutDeviceChange::Address;
					}
				}
			}

			for (size_t i = 0; i < observation.nameCount; ++i) {
				const auto result = scout_internal::upsertName(
				    details,
				    observation.names[i].source,
				    observation.names[i].value,
				    observation.names[i].lastSeenAtMs,
				    observation.names[i].expiresAtMs
				);
				if (result != scout_internal::EnrichmentUpsertResult::Unchanged) {
					changes |= ScoutDeviceChange::Name;
					if (result == scout_internal::EnrichmentUpsertResult::Replaced) {
						diag.nameLimitDrops++;
					}
				}
			}

			if (observation.hasService) {
				const auto result = scout_internal::upsertService(details, observation.service);
				if (result != scout_internal::EnrichmentUpsertResult::Unchanged) {
					changes |= ScoutDeviceChange::Service;
					if (result == scout_internal::EnrichmentUpsertResult::Replaced) {
						diag.serviceLimitDrops++;
					}
				}
			}

			for (size_t i = 0; i < observation.metadataCount; ++i) {
				const auto result =
				    scout_internal::upsertMetadata(details, observation.metadata[i]);
				if (result != scout_internal::EnrichmentUpsertResult::Unchanged) {
					changes |= ScoutDeviceChange::Metadata;
					if (result == scout_internal::EnrichmentUpsertResult::Replaced) {
						diag.metadataLimitDrops++;
					}
				}
			}

			auto updateText = [&](char *destination,
			                      size_t capacity,
			                      const char *source,
			                      ScoutObservationSource &fieldSource,
			                      uint64_t &expiresAtMs,
			                      ScoutDeviceChange change) {
				if (source == nullptr || source[0] == '\0') {
					return;
				}
				const bool changed = std::strncmp(destination, source, capacity) != 0;
				if (changed) {
					scout_internal::copyText(destination, capacity, source);
					changes |= change;
				}
				fieldSource = observation.source;
				expiresAtMs = observation.identityExpiresAtMs;
			};
			updateText(
			    details.manufacturer,
			    sizeof(details.manufacturer),
			    observation.manufacturer,
			    details.manufacturerSource,
			    details.manufacturerExpiresAtMs,
			    ScoutDeviceChange::Metadata
			);
			updateText(
			    details.modelName,
			    sizeof(details.modelName),
			    observation.modelName,
			    details.modelNameSource,
			    details.modelNameExpiresAtMs,
			    ScoutDeviceChange::Metadata
			);
			updateText(
			    details.modelNumber,
			    sizeof(details.modelNumber),
			    observation.modelNumber,
			    details.modelNumberSource,
			    details.modelNumberExpiresAtMs,
			    ScoutDeviceChange::Metadata
			);
			updateText(
			    details.serialNumber,
			    sizeof(details.serialNumber),
			    observation.serialNumber,
			    details.serialNumberSource,
			    details.serialNumberExpiresAtMs,
			    ScoutDeviceChange::Identity
			);
			updateText(
			    details.persistentDeviceId,
			    sizeof(details.persistentDeviceId),
			    observation.persistentDeviceId,
			    details.persistentDeviceIdSource,
			    details.persistentDeviceIdExpiresAtMs,
			    ScoutDeviceChange::Identity
			);
			updateText(
			    details.upnpUdn,
			    sizeof(details.upnpUdn),
			    observation.upnpUdn,
			    details.upnpUdnSource,
			    details.upnpUdnExpiresAtMs,
			    ScoutDeviceChange::Identity
			);

			if (observation.source == ScoutObservationSource::Ssdp &&
			    observation.manufacturer[0] != '\0' &&
			    (!details.vendor.known || details.vendor.source == ScoutVendorSource::Oui ||
			     details.vendor.source == ScoutVendorSource::Ssdp)) {
				const bool vendorChanged = !details.vendor.known || std::strncmp(
				                                                        details.vendor.name,
				                                                        observation.manufacturer,
				                                                        sizeof(details.vendor.name)
				                                                    ) != 0;
				details.vendor.known = true;
				details.vendor.source = ScoutVendorSource::Ssdp;
				details.vendor.observationSource = ScoutObservationSource::Ssdp;
				if (details.vendor.firstSeenAtMs == 0) {
					details.vendor.firstSeenAtMs = observedAt;
				}
				details.vendor.lastSeenAtMs = observedAt;
				details.vendor.expiresAtMs = observation.identityExpiresAtMs;
				scout_internal::copyText(
				    details.vendor.name,
				    sizeof(details.vendor.name),
				    observation.manufacturer
				);
				if (vendorChanged) {
					changes |= ScoutDeviceChange::Vendor;
				}
			}

			if (observation.source != ScoutObservationSource::None) {
				details.lastEnrichedAtMs = observedAt;
			}

			const uint32_t changeMask = scoutDeviceChangeMask(changes);
			const uint32_t identityRelevantMask =
			    scoutDeviceChangeMask(ScoutDeviceChange::Name) |
			    scoutDeviceChangeMask(ScoutDeviceChange::Service) |
			    scoutDeviceChangeMask(ScoutDeviceChange::Metadata) |
			    scoutDeviceChangeMask(ScoutDeviceChange::Vendor) |
			    scoutDeviceChangeMask(ScoutDeviceChange::Identity);
			if ((changeMask & identityRelevantMask) != 0) {
				identityDirty = true;
			}
			if (changeMask != 0) {
				event.type =
				    observation.confirmed &&
				            changeMask == scoutDeviceChangeMask(ScoutDeviceChange::Confirmation)
				        ? ScoutEventType::DeviceObserved
				        : ScoutEventType::DeviceChanged;
				event.status = ScoutStatus::Ok;
				event.source = observation.source;
				event.changes = changeMask;
				event.hasDevice = true;
				event.device = info;
				event.message = observation.confirmed ? "device actively confirmed"
				                                      : "device enrichment changed";
				shouldEmit = true;
			}
		}
		if (shouldEmit) {
			emit(event);
		}
	}

	static void providerSink(
	    const ScoutMacAddress &mac,
	    const scout_internal::EnrichmentObservation &observation,
	    void *context
	) {
		auto *self = static_cast<ScoutImpl *>(context);
		if (self != nullptr) {
			self->applyEnrichmentObservation(mac, observation);
		}
	}

	void expireEnrichmentRecords() {
		bool anyIdentityChange = false;
		for (size_t index = 0;; ++index) {
			ScoutEvent event{};
			bool emitChange = false;
			{
				ScoutLock lock(mutex);
				if (!lock || index >= deviceCount) {
					break;
				}
				if (!devices[index].details) {
					continue;
				}
				const ScoutDeviceChange changes =
				    scout_internal::expireEnrichment(*devices[index].details, nowMs());
				const uint32_t changeMask = scoutDeviceChangeMask(changes);
				if (changeMask != 0) {
					identityDirty = true;
					anyIdentityChange = true;
					event.type = ScoutEventType::DeviceChanged;
					event.status = ScoutStatus::Ok;
					event.changes = changeMask;
					event.hasDevice = true;
					event.device = devices[index].info;
					event.message = "device enrichment expired";
					emitChange = true;
				}
			}
			if (emitChange) {
				emit(event);
			}
		}
		if (anyIdentityChange) {
			flushIdentityIfDirty();
		}
	}

	void performIcmpProvider() {
		const size_t count = snapshotProviderTargets();
		const auto stats = scout_internal::runIcmpProvider(
		    providerTargets,
		    count,
		    icmpCursor,
		    config.providers.icmp,
		    &ScoutImpl::providerSink,
		    this
		);
		accumulateProviderStats(diag.icmp, stats);
		flushIdentityIfDirty();
	}

	void performMdnsProvider() {
		const size_t count = snapshotProviderTargets();
		const auto stats = scout_internal::runMdnsProvider(
		    providerTargets,
		    count,
		    mdnsServiceCursor,
		    config.providers.mdns,
		    &ScoutImpl::providerSink,
		    this
		);
		accumulateProviderStats(diag.mdns, stats);
		flushIdentityIfDirty();
	}

	void performSsdpProvider() {
		const size_t count = snapshotProviderTargets();
		const auto stats = scout_internal::runSsdpProvider(
		    providerTargets,
		    count,
		    config.providers.ssdp,
		    httpScratch,
		    httpScratchCapacity,
		    &ScoutImpl::providerSink,
		    this
		);
		accumulateProviderStats(diag.ssdp, stats);
		flushIdentityIfDirty();
	}

	void performNbnsProvider() {
		const size_t count = snapshotProviderTargets();
		const auto stats = scout_internal::runNbnsProvider(
		    providerTargets,
		    count,
		    nbnsCursor,
		    config.providers.nbns,
		    &ScoutImpl::providerSink,
		    this
		);
		accumulateProviderStats(diag.nbns, stats);
		flushIdentityIfDirty();
	}

	void performReverseDnsProvider() {
		const size_t count = snapshotProviderTargets();
		const auto stats = scout_internal::runReverseDnsProvider(
		    providerTargets,
		    count,
		    reverseDnsCursor,
		    config.providers.reverseDns,
		    &ScoutImpl::providerSink,
		    this
		);
		accumulateProviderStats(diag.reverseDns, stats);
		flushIdentityIfDirty();
	}

	void performOuiProvider() {
		if (!config.providers.oui) {
			return;
		}
		ScoutOuiLookupCallback resolver;
		{
			ScoutLock lock(mutex);
			if (!lock) {
				return;
			}
			resolver = ouiLookup;
		}
		if (!resolver) {
			return;
		}

		uint64_t observations = 0;
		for (size_t index = 0;; ++index) {
			ScoutMacAddress mac{};
			bool shouldLookup = false;
			{
				ScoutLock lock(mutex);
				if (!lock || index >= deviceCount) {
					break;
				}
				const auto &record = devices[index];
				mac = record.info.mac;
				const bool knownVendor = record.details && record.details->vendor.known;
				shouldLookup = !knownVendor && !scout_internal::macIsLocallyAdministered(mac) &&
				               !scout_internal::macIsMulticast(mac);
			}
			if (!shouldLookup) {
				continue;
			}

			ScoutVendorInfo vendor{};
			if (!resolver(mac, vendor) || (!vendor.known && vendor.name[0] == '\0')) {
				continue;
			}
			vendor.known = true;
			vendor.source = ScoutVendorSource::Oui;

			ScoutEvent event{};
			bool emitChange = false;
			{
				ScoutLock lock(mutex);
				if (!lock) {
					continue;
				}
				const size_t currentIndex = findDeviceByMac(mac.bytes);
				if (currentIndex == SIZE_MAX) {
					continue;
				}
				auto *details = ensureDetailsLocked(currentIndex);
				if (details == nullptr || details->vendor.known) {
					continue;
				}
				vendor.observationSource = ScoutObservationSource::Oui;
				vendor.firstSeenAtMs = nowMs();
				vendor.lastSeenAtMs = vendor.firstSeenAtMs;
				vendor.expiresAtMs = 0;
				details->vendor = vendor;
				details->lastEnrichedAtMs = vendor.firstSeenAtMs;
				identityDirty = true;
				event.type = ScoutEventType::DeviceChanged;
				event.status = ScoutStatus::Ok;
				event.source = ScoutObservationSource::Oui;
				event.changes = scoutDeviceChangeMask(ScoutDeviceChange::Vendor);
				event.hasDevice = true;
				event.device = devices[currentIndex].info;
				event.message = "device vendor enriched";
				emitChange = true;
				observations++;
			}
			if (emitChange) {
				emit(event);
			}
		}
		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.oui.runs++;
				diag.oui.observations += observations;
			}
		}
		flushIdentityIfDirty();
	}

	ScoutStatus
	scanInterface(const scout_internal::InterfaceSnapshot &interfaceSnapshot, uint64_t scanId) {
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
			const esp_err_t requestResult =
			    scout_internal::requestArp(interfaceSnapshot.index, batch, count, requestStats);
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
				return ScoutStatus::Cancelled;
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

				const bool wasCached =
				    beforeMappings[i].found &&
				    scout_internal::macEquals(beforeMappings[i].mac, afterMappings[i].mac);
				const bool confirmed = !wasCached;
				const ScoutObservationSource source =
				    confirmed ? ScoutObservationSource::ArpProbe : ScoutObservationSource::ArpCache;

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

			if (config.interBatchDelayMs > 0 && !waitInterruptible(config.interBatchDelayMs)) {
				return ScoutStatus::Cancelled;
			}
		}
		if (stopRequested.load()) {
			return ScoutStatus::Cancelled;
		}
		if (hadRequestFailures) {
			recordNetworkError(scanId, "one or more ARP requests failed");
			return ScoutStatus::InternalError;
		}
		return ScoutStatus::Ok;
	}

	void finishScan(uint64_t scanId, uint64_t startedAt, ScoutStatus status, const char *message) {
		{
			ScoutLock lock(mutex);
			if (lock) {
				if (status == ScoutStatus::Ok) {
					diag.completedScanCount++;
				}
				diag.lastScanDurationMs = nowMs() - startedAt;
			}
		}
		emitSimple(ScoutEventType::ScanCompleted, status, scanId, message);
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

		maintainRegistry(scanId);
		if (stopRequested.load()) {
			finishScan(scanId, startedAt, ScoutStatus::Cancelled, "scan cancelled");
			return;
		}

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
				}
			}
			recordNetworkError(scanId, "failed to enumerate network interfaces");
			finishScan(
			    scanId,
			    startedAt,
			    ScoutStatus::InternalError,
			    "scan failed while enumerating network interfaces"
			);
			return;
		}

		if (interfaceCount == 0) {
			updateCoverage(false, 0, scanId);
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
			    "no eligible ARP-capable interface"
			);
			finishScan(
			    scanId,
			    startedAt,
			    ScoutStatus::NetworkUnavailable,
			    "scan completed without an eligible interface"
			);
			return;
		}

		ScoutStatus scanStatus = ScoutStatus::Ok;
		for (size_t i = 0; i < interfaceCount; ++i) {
			if (stopRequested.load()) {
				scanStatus = ScoutStatus::Cancelled;
				break;
			}

			const ScoutStatus interfaceStatus = scanInterface(interfaces[i], scanId);
			if (interfaceStatus == ScoutStatus::Cancelled) {
				scanStatus = ScoutStatus::Cancelled;
				break;
			}
			if (interfaceStatus == ScoutStatus::InternalError ||
			    (scanStatus == ScoutStatus::Ok && interfaceStatus != ScoutStatus::Ok)) {
				scanStatus = interfaceStatus;
			}
		}

		if (stopRequested.load()) {
			scanStatus = ScoutStatus::Cancelled;
		}

		if (scanStatus != ScoutStatus::Cancelled) {
			// A partial or failed sweep cannot support absence inference.
			updateCoverage(scanStatus == ScoutStatus::Ok, interfaceCount, scanId);
		}

		finishScan(
		    scanId,
		    startedAt,
		    scanStatus,
		    scanStatus == ScoutStatus::Ok ? "scan completed"
		    : scanStatus == ScoutStatus::Cancelled
		        ? "scan cancelled"
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

		const uint64_t startedAt = nowMs();
		uint64_t nextScanAt = scanRequested.load() ? startedAt : startedAt + config.scanIntervalMs;
		uint64_t nextIcmpAt = config.providers.icmp.enabled ? startedAt : UINT64_MAX;
		uint64_t nextMdnsAt = config.providers.mdns.enabled ? startedAt : UINT64_MAX;
		uint64_t nextSsdpAt = config.providers.ssdp.enabled ? startedAt : UINT64_MAX;
		uint64_t nextNbnsAt = config.providers.nbns.enabled ? startedAt : UINT64_MAX;
		uint64_t nextReverseDnsAt = config.providers.reverseDns.enabled ? startedAt : UINT64_MAX;

		while (!stopRequested.load()) {
			const uint64_t current = nowMs();
			const bool requested = scanRequested.exchange(false);
			if (requested || current >= nextScanAt) {
				performScan();
				expireEnrichmentRecords();
				performOuiProvider();
				nextScanAt = nowMs() + config.scanIntervalMs;
				continue;
			}

			if (config.providers.icmp.enabled && current >= nextIcmpAt) {
				performIcmpProvider();
				nextIcmpAt = nowMs() + config.providers.icmp.intervalMs;
				continue;
			}
			if (config.providers.mdns.enabled && current >= nextMdnsAt) {
				performMdnsProvider();
				nextMdnsAt = nowMs() + config.providers.mdns.intervalMs;
				continue;
			}
			if (config.providers.ssdp.enabled && current >= nextSsdpAt) {
				performSsdpProvider();
				nextSsdpAt = nowMs() + config.providers.ssdp.intervalMs;
				continue;
			}
			if (config.providers.nbns.enabled && current >= nextNbnsAt) {
				performNbnsProvider();
				nextNbnsAt = nowMs() + config.providers.nbns.intervalMs;
				continue;
			}
			if (config.providers.reverseDns.enabled && current >= nextReverseDnsAt) {
				performReverseDnsProvider();
				nextReverseDnsAt = nowMs() + config.providers.reverseDns.intervalMs;
				continue;
			}

			const uint64_t nextWorkAt = std::min(
			    {nextScanAt, nextIcmpAt, nextMdnsAt, nextSsdpAt, nextNbnsAt, nextReverseDnsAt}
			);
			const uint64_t remaining = nextWorkAt > current ? nextWorkAt - current : 1;
			const uint32_t waitMs = static_cast<uint32_t>(std::min<uint64_t>(remaining, 1000));
			(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(std::max<uint32_t>(waitMs, 1)));
		}

		{
			ScoutLock lock(mutex);
			if (lock) {
				diag.taskStackHighWaterMarkBytes = task.stackHighWaterMarkBytes();
			}
		}
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
		const bool invalidProviderSchedule =
		    (incoming.providers.icmp.enabled &&
		     (incoming.providers.icmp.intervalMs < MinScanIntervalMs ||
		      incoming.providers.icmp.timeoutMs == 0 ||
		      incoming.providers.icmp.maxTargetsPerRun == 0)) ||
		    (incoming.providers.mdns.enabled &&
		     (incoming.providers.mdns.intervalMs < MinScanIntervalMs ||
		      incoming.providers.mdns.queryTimeoutMs == 0 ||
		      incoming.providers.mdns.maxResults == 0 ||
		      incoming.providers.mdns.maxServiceTypes == 0 ||
		      incoming.providers.mdns.maxServiceQueriesPerRun == 0)) ||
		    (incoming.providers.ssdp.enabled &&
		     (incoming.providers.ssdp.intervalMs < MinScanIntervalMs ||
		      incoming.providers.ssdp.responseWindowMs == 0 ||
		      incoming.providers.ssdp.maxDescriptionFetchesPerRun == 0)) ||
		    (incoming.providers.nbns.enabled &&
		     (incoming.providers.nbns.intervalMs < MinScanIntervalMs ||
		      incoming.providers.nbns.responseWindowMs == 0 ||
		      incoming.providers.nbns.maxTargetsPerRun == 0)) ||
		    (incoming.providers.reverseDns.enabled &&
		     (incoming.providers.reverseDns.intervalMs < MinScanIntervalMs ||
		      incoming.providers.reverseDns.timeoutMs == 0 ||
		      incoming.providers.reverseDns.maxTargetsPerRun == 0));

		if (!Strata::validPlacement(incoming.memory.allocation) ||
		    !Strata::validPlacement(incoming.memory.taskStack) ||
		    incoming.scanIntervalMs < MinScanIntervalMs || incoming.deviceMaxAgeMs == 0 ||
		    incoming.arpResponseWaitMs == 0 || incoming.maxDevices == 0 ||
		    incoming.maxHostsPerSubnet == 0 || incoming.arpBatchSize == 0 ||
		    incoming.maxIdentityRelations == 0 ||
		    incoming.maxDevices > SIZE_MAX / SCOUT_MAX_ENDPOINTS_PER_DEVICE ||
		    (incoming.providers.ssdp.enabled && incoming.providers.ssdp.fetchDeviceDescription &&
		     incoming.providers.ssdp.maxDescriptionBytes == 0) ||
		    invalidProviderSchedule || !validStackSize(incoming.taskStackBytes)) {
			return ScoutResult::failure(ScoutStatus::InvalidConfig, "invalid Scout configuration");
		}

		auto *cleanup = cleanupService();
		if (cleanup == nullptr) {
			return ScoutResult::failure(
			    ScoutStatus::NoMemory,
			    "failed to allocate Scout cleanup service"
			);
		}
		if (!cleanup->ensureStarted()) {
			return ScoutResult::failure(
			    ScoutStatus::TaskCreateFailed,
			    "failed to create Scout cleanup task"
			);
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
			return ScoutResult::failure(ScoutStatus::Busy, "Scout is starting or stopping");
		}

		config = incoming;
		state = ScoutState::Starting;
		diag = {};
		diag.state = state;
		diag.allocationPlacement = config.memory.allocation;
		diag.taskStackPlacement = config.memory.taskStack;
		coverageKnown = false;
		coverageAvailable = false;
		identityDirty = false;
		identityGroupCountValue = 0;
		identityRelationCountValue = 0;
		icmpCursor = 0;
		reverseDnsCursor = 0;
		nbnsCursor = 0;
		mdnsServiceCursor = 0;
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
			return ScoutResult::failure(
			    ScoutStatus::TaskCreateFailed,
			    "failed to create Scout task"
			);
		}

		initialized = true;
		diag.registryRegion = Strata::regionOf(devices);
		diag.targetBufferRegion = Strata::regionOf(targets);
		diag.enrichmentRegion = Strata::regionOf(providerTargets);
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
		diag.enrichmentRegion = Strata::Region::Unknown;
		diag.taskStackRegion = Strata::Region::Unknown;
		return ScoutResult::success("Scout deinitialized");
	}
};

namespace {

DeferredCleanupService *cleanupService() {
	static DeferredCleanupService *service =
	    Strata::create<DeferredCleanupService>(Strata::Placement::PreferExternal);
	return service;
}

bool DeferredCleanupService::ensureStarted() {
	while (startLock.test_and_set(std::memory_order_acquire)) {
		vTaskDelay(1);
	}

	if (!task) {
		task = Strata::FreeRTOS::Task::create(
		    &DeferredCleanupService::taskEntry,
		    this,
		    Strata::FreeRTOS::TaskConfig{
		        .name = CleanupTaskName,
		        .stackBytes = CleanupTaskStackBytes,
		        .stackPlacement = Strata::Placement::PreferExternal,
		        .priority = 1,
		        .affinity = tskNO_AFFINITY,
		    }
		);
	}

	const bool started = static_cast<bool>(task);
	startLock.clear(std::memory_order_release);
	return started;
}

void DeferredCleanupService::enqueue(ScoutImpl *impl) {
	if (impl == nullptr) {
		return;
	}

	ScoutImpl *head = pending.load(std::memory_order_relaxed);
	do {
		impl->deferredNext = head;
	} while (!pending.compare_exchange_weak(
	    head,
	    impl,
	    std::memory_order_release,
	    std::memory_order_relaxed
	));

	if (task.handle() != nullptr) {
		xTaskNotifyGive(task.handle());
	}
}

void DeferredCleanupService::run() {
	for (;;) {
		(void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
		ScoutImpl *list = pending.exchange(nullptr, std::memory_order_acquire);
		while (list != nullptr) {
			ScoutImpl *next = list->deferredNext;
			list->deferredNext = nullptr;
			Strata::UniquePtr<ScoutImpl> owned{list};
			if (owned->initialized) {
				(void)owned->deinit(UINT32_MAX);
			}
			list = next;
		}
	}
}

void DeferredCleanupService::taskEntry(void *context) {
	auto *self = static_cast<DeferredCleanupService *>(context);
	if (self == nullptr) {
		suspendForever();
	}
	self->run();
}

} // namespace

ScoutResult ScoutResult::success(const char *message) {
	return {ScoutStatus::Ok, message};
}

ScoutResult ScoutResult::failure(ScoutStatus status, const char *message) {
	return {status, message};
}

Scout::Scout() : _impl(Strata::makeUnique<ScoutImpl>(Strata::Placement::PreferExternal)) {
}

Scout::~Scout() {
	if (!_impl || !_impl->initialized) {
		return;
	}

	if (_impl->task.handle() == xTaskGetCurrentTaskHandle()) {
		auto *service = cleanupService();
		{
			ScoutLock lock(_impl->mutex);
			if (lock) {
				_impl->callback = {};
			}
		}
		ScoutImpl *deferred = _impl.release();
		deferred->stopRequested.store(true);
		deferred->scanRequested.store(false);
		if (service != nullptr) {
			service->enqueue(deferred);
		}
		return;
	}

	(void)_impl->deinit(UINT32_MAX);
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

ScoutResult Scout::deviceDetailsAt(size_t index, ScoutDeviceDetails &out) const {
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
	if (_impl->devices[index].details) {
		out = *_impl->devices[index].details;
	} else {
		out = {};
	}
	return ScoutResult::success();
}

ScoutResult Scout::findDetailsByMac(const ScoutMacAddress &mac, ScoutDeviceDetails &out) const {
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
	if (_impl->devices[index].details) {
		out = *_impl->devices[index].details;
	} else {
		out = {};
	}
	return ScoutResult::success();
}

ScoutResult Scout::preferredName(const ScoutMacAddress &mac, ScoutPreferredName &out) const {
	out = {};
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
	if (_impl->devices[index].details &&
	    scout_internal::selectPreferredName(*_impl->devices[index].details, out)) {
		return ScoutResult::success();
	}
	std::snprintf(
	    out.value,
	    sizeof(out.value),
	    "%02X:%02X:%02X:%02X:%02X:%02X",
	    static_cast<unsigned>(mac.bytes[0]),
	    static_cast<unsigned>(mac.bytes[1]),
	    static_cast<unsigned>(mac.bytes[2]),
	    static_cast<unsigned>(mac.bytes[3]),
	    static_cast<unsigned>(mac.bytes[4]),
	    static_cast<unsigned>(mac.bytes[5])
	);
	out.source = ScoutNameSource::None;
	return ScoutResult::success("MAC address fallback");
}

size_t Scout::identityGroupCount() const {
	if (!_impl) {
		return 0;
	}
	ScoutLock lock(_impl->mutex);
	return lock && _impl->initialized ? _impl->identityGroupCountValue : 0;
}

ScoutResult Scout::identityGroupAt(size_t index, ScoutIdentityGroup &out) const {
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
	if (index >= _impl->identityGroupCountValue) {
		return ScoutResult::failure(ScoutStatus::NotFound, "identity group index is out of range");
	}
	out = _impl->identityGroups[index];
	return ScoutResult::success();
}

size_t Scout::identityRelationCount() const {
	if (!_impl) {
		return 0;
	}
	ScoutLock lock(_impl->mutex);
	return lock && _impl->initialized ? _impl->identityRelationCountValue : 0;
}

ScoutResult Scout::identityRelationAt(size_t index, ScoutIdentityRelation &out) const {
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
	if (index >= _impl->identityRelationCountValue) {
		return ScoutResult::failure(
		    ScoutStatus::NotFound,
		    "identity relation index is out of range"
		);
	}
	out = _impl->identityRelations[index];
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
	snapshot.enrichmentRegion = Strata::regionOf(_impl->providerTargets);
	snapshot.identityGroupCount = _impl->identityGroupCountValue;
	snapshot.identityRelationCount = _impl->identityRelationCountValue;
	if (_impl->task) {
		snapshot.taskStackRegion = _impl->task.stackRegion();
		snapshot.taskStackHighWaterMarkBytes = _impl->task.stackHighWaterMarkBytes();
	}
	return snapshot;
}

void Scout::setOuiLookup(ScoutOuiLookupCallback callback) {
	if (!_impl) {
		return;
	}
	ScoutLock lock(_impl->mutex);
	if (lock) {
		_impl->ouiLookup = std::move(callback);
	}
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
	case ScoutStatus::Cancelled:
		return "cancelled";
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
	case ScoutEventType::DeviceExpired:
		return "device_expired";
	case ScoutEventType::IdentityGroupChanged:
		return "identity_group_changed";
	case ScoutEventType::CoverageLost:
		return "coverage_lost";
	case ScoutEventType::CoverageRestored:
		return "coverage_restored";
	case ScoutEventType::Error:
		return "error";
	}
	return "unknown";
}
