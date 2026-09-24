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
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
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
	assert(initializedSnapshot.enrichmentRegion != Strata::Region::Unknown);

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
	assert(stoppedSnapshot.enrichmentRegion == Strata::Region::Unknown);
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

void testLazyDetailsAllocation() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	scout_internal::InterfaceSnapshot interfaceSnapshot{};
	interfaceSnapshot.index = 1;
	std::strcpy(interfaceSnapshot.name, "test");
	std::strcpy(interfaceSnapshot.key, "TEST_1");
	const uint8_t deviceMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
	const uint32_t address = lwip_htonl(0xC0A80120U);

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    deviceMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    1
	);
	assert(runtime.deviceCount == 1);
	assert(!runtime.devices[0].details);

	scout_internal::EnrichmentObservation confirmation{};
	confirmation.source = ScoutObservationSource::Icmp;
	confirmation.ipv4.value = address;
	confirmation.interfaceIndex = 1;
	confirmation.confirmed = true;
	runtime.applyEnrichmentObservation(runtime.devices[0].info.mac, confirmation);
	assert(!runtime.devices[0].details);

	scout_internal::EnrichmentObservation reverseDns{};
	reverseDns.source = ScoutObservationSource::ReverseDns;
	reverseDns.ipv4.value = address;
	reverseDns.interfaceIndex = 1;
	reverseDns.nameCount = 1;
	reverseDns.names[0].source = ScoutNameSource::ReverseDns;
	std::strcpy(reverseDns.names[0].value, "device.example");
	reverseDns.names[0].lastSeenAtMs = nowMs();
	reverseDns.names[0].expiresAtMs = nowMs() + 1000;
	runtime.applyEnrichmentObservation(runtime.devices[0].info.mac, reverseDns);
	assert(runtime.devices[0].details);
	assert(runtime.devices[0].details->nameCount == 1);

	runtime.releaseBuffers();
}

void testStaleProviderObservationAndDiagnostics() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	scout_internal::InterfaceSnapshot interfaceSnapshot{};
	interfaceSnapshot.index = 1;
	std::strcpy(interfaceSnapshot.name, "test");
	std::strcpy(interfaceSnapshot.key, "TEST_1");

	const uint8_t firstMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x10};
	const uint8_t secondMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x20};
	const uint32_t address = lwip_htonl(0xC0A8012AU);

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    firstMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    1
	);
	const size_t firstIndex = runtime.findDeviceByMac(firstMac);
	assert(firstIndex != SIZE_MAX);
	const uint64_t firstSeen = runtime.devices[firstIndex].info.lastSeenAtMs;

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    secondMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    2
	);
	assert(runtime.devices[firstIndex].info.endpointCount == 0);

	scout_internal::EnrichmentObservation stale{};
	stale.source = ScoutObservationSource::ReverseDns;
	stale.ipv4.value = address;
	stale.interfaceIndex = 1;
	stale.nameCount = 1;
	stale.names[0].source = ScoutNameSource::ReverseDns;
	std::strcpy(stale.names[0].value, "stale.example");
	stale.names[0].lastSeenAtMs = nowMs();
	stale.names[0].expiresAtMs = nowMs() + 1000;
	runtime.applyEnrichmentObservation(runtime.devices[firstIndex].info.mac, stale);
	assert(runtime.diag.staleProviderObservations == 1);
	assert(runtime.devices[firstIndex].info.lastSeenAtMs == firstSeen);
	assert(!runtime.devices[firstIndex].details);

	const size_t secondIndex = runtime.findDeviceByMac(secondMac);
	assert(secondIndex != SIZE_MAX);
	runtime.devices[secondIndex].info.lastSeenAtMs = 123;
	runtime.devices[secondIndex].info.endpoints[0].lastSeenAtMs = 123;
	scout_internal::EnrichmentObservation confirmation{};
	confirmation.source = ScoutObservationSource::Icmp;
	confirmation.ipv4.value = address;
	confirmation.interfaceIndex = 1;
	confirmation.confirmed = true;
	runtime.applyEnrichmentObservation(runtime.devices[secondIndex].info.mac, confirmation);
	assert(runtime.devices[secondIndex].info.lastSeenAtMs == 123);
	assert(runtime.devices[secondIndex].info.endpoints[0].lastSeenAtMs == 123);
	assert(runtime.devices[secondIndex].info.lastConfirmedAtMs >= 123);

	scout_internal::ProviderRunStats stats{};
	stats.observations = 1;
	stats.errors = 2;
	stats.timeouts = 3;
	stats.noRecords = 4;
	stats.malformedResponses = 5;
	stats.serverErrors = 6;
	stats.dropped = 7;
	ScoutProviderDiagnostics diagnostics{};
	runtime.accumulateProviderStats(diagnostics, stats);
	assert(diagnostics.runs == 1);
	assert(diagnostics.observations == 1);
	assert(diagnostics.errors == 2);
	assert(diagnostics.timeouts == 3);
	assert(diagnostics.noRecords == 4);
	assert(diagnostics.malformedResponses == 5);
	assert(diagnostics.serverErrors == 6);
	assert(diagnostics.droppedObservations == 7);

	runtime.releaseBuffers();
}

void testFormattingHelpers() {
	char buffer[64]{};

	ScoutIpv4Address ipv4Address{};
	ipv4Address.value = lwip_htonl(0xC0A8012AU);
	assert(scoutFormatIpv4(ipv4Address, buffer, sizeof(buffer)));
	assert(std::strcmp(buffer, "192.168.1.42") == 0);

	ScoutMacAddress mac{{0x00, 0x11, 0x22, 0xAA, 0xBB, 0xCC}};
	assert(scoutFormatMac(mac, buffer, sizeof(buffer)));
	assert(std::strcmp(buffer, "00:11:22:AA:BB:CC") == 0);

	ScoutIpv6Address ipv6{};
	const uint8_t bytes[16] = {
	    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	};
	std::memcpy(ipv6.bytes, bytes, sizeof(bytes));
	assert(scoutFormatIpv6(ipv6, buffer, sizeof(buffer)));
	assert(std::strcmp(buffer, "2001:db8::1") == 0);

	ScoutIpv6Address zero{};
	assert(scoutFormatIpv6(zero, buffer, sizeof(buffer)));
	assert(std::strcmp(buffer, "::") == 0);

	char tiny[4]{};
	assert(!scoutFormatMac(mac, tiny, sizeof(tiny)));
	assert(tiny[0] == '\0');
}

void testInvalidSsdpHttpTimeout() {
	Scout scout;
	ScoutConfig config;
	config.scanOnInit = false;
	config.providers.ssdp.enabled = true;
	config.providers.ssdp.fetchDeviceDescription = true;
	config.providers.ssdp.httpTimeoutMs = 0;
	const ScoutResult result = scout.init(config);
	assert(result.status == ScoutStatus::InvalidConfig);
}

void testIdentityGroupingKeepsModerateRelationsSeparate() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	for (size_t i = 0; i < 3; ++i) {
		auto &record = runtime.devices[i];
		record = {};
		record.info.mac = ScoutMacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, static_cast<uint8_t>(i + 1)}};
		record.info.key.kind = ScoutIdentityKind::Mac;
		record.info.key.mac = record.info.mac;
	}
	runtime.deviceCount = 3;
	runtime.diag.deviceCount = 3;

	assert(!runtime.devices[0].details);
	assert(!runtime.devices[1].details);
	assert(!runtime.devices[2].details);
	auto *firstDetails = runtime.ensureDetailsLocked(0);
	auto *secondDetails = runtime.ensureDetailsLocked(1);
	auto *thirdDetails = runtime.ensureDetailsLocked(2);
	assert(firstDetails != nullptr && secondDetails != nullptr && thirdDetails != nullptr);
	std::strcpy(firstDetails->upnpUdn, "uuid:physical-device");
	std::strcpy(secondDetails->upnpUdn, "uuid:physical-device");
	scout_internal::upsertName(
	    *secondDetails,
	    ScoutNameSource::MdnsHostname,
	    "shared-host.local",
	    100,
	    0
	);
	scout_internal::upsertName(
	    *thirdDetails,
	    ScoutNameSource::MdnsHostname,
	    "shared-host.local",
	    100,
	    0
	);

	runtime.identityDirty = true;
	runtime.rebuildIdentityState();

	assert(runtime.identityRelationCountValue == 2);
	assert(runtime.identityGroupCountValue == 1);
	assert(runtime.identityGroups[0].memberCount == 2);
	assert(
	    static_cast<uint8_t>(runtime.identityGroups[0].confidence) >=
	    static_cast<uint8_t>(ScoutIdentityConfidence::Strong)
	);

	bool sawModerateHostname = false;
	for (size_t i = 0; i < runtime.identityRelationCountValue; ++i) {
		const auto &relation = runtime.identityRelations[i];
		if (relation.evidence.type == ScoutIdentityEvidenceType::MdnsHostname &&
		    relation.evidence.confidence == ScoutIdentityConfidence::Moderate) {
			sawModerateHostname = true;
		}
	}
	assert(sawModerateHostname);

	firstDetails->upnpUdnSource = ScoutObservationSource::Ssdp;
	secondDetails->upnpUdnSource = ScoutObservationSource::Ssdp;
	firstDetails->upnpUdnExpiresAtMs = 1;
	secondDetails->upnpUdnExpiresAtMs = 1;
	runtime.expireEnrichmentRecords();
	assert(runtime.identityGroupCountValue == 0);

	runtime.releaseBuffers();
}

void testDestructionFromCallback() {
	networkMode.store(NetworkMode::None);
	std::atomic<Scout *> scout{new Scout()};
	std::atomic<bool> allowDestroy{false};
	std::atomic<bool> destroyed{false};
	std::atomic<int> taskResets{0};
	std::atomic<int> callbackCount{0};

	Scout *instance = scout.load();
	instance->onEvent([&](const ScoutEvent &event) {
		callbackCount.fetch_add(1);
		if (event.type != ScoutEventType::CoverageLost || destroyed.load()) {
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
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
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
	assert(callbackCount.load() == 2);
}
} // namespace

namespace scout_internal {
ProviderRunStats runIcmpProvider(
    const ProviderTarget *,
    size_t,
    size_t &,
    const ScoutIcmpConfig &,
    EnrichmentSink,
    void *
) {
	return {};
}

ProviderRunStats runMdnsProvider(
    const ProviderTarget *,
    size_t,
    size_t &,
    const ScoutMdnsConfig &,
    EnrichmentSink,
    void *
) {
	return {};
}

ProviderRunStats runSsdpProvider(
    const ProviderTarget *,
    size_t,
    const ScoutSsdpConfig &,
    char *,
    size_t,
    EnrichmentSink,
    void *
) {
	return {};
}

ProviderRunStats runNbnsProvider(
    const ProviderTarget *,
    size_t,
    size_t &,
    const ScoutNbnsConfig &,
    EnrichmentSink,
    void *
) {
	return {};
}

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *,
    size_t,
    size_t &,
    const ScoutReverseDnsConfig &,
    EnrichmentSink,
    void *
) {
	return {};
}

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
	testLazyDetailsAllocation();
	testStaleProviderObservationAndDiagnostics();
	testFormattingHelpers();
	testInvalidSsdpHttpTimeout();
	testIdentityGroupingKeepsModerateRelationsSeparate();
	testDestructionFromCallback();
	std::cout << "Scout runtime host tests passed\n";
}
