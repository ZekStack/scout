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

namespace scout_internal {
std::atomic<int> testMdnsRuns{0};
std::atomic<int> testSsdpRuns{0};
std::atomic<int> testNbnsRuns{0};
std::atomic<bool> testMdnsYieldNext{false};
std::atomic<bool> testSsdpYieldNext{false};
std::atomic<bool> testNbnsYieldNext{false};
} // namespace scout_internal

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
	TruncatedInterfaces,
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

void testWorkerDoesNotRestartStoppingState() {
	ScoutImpl runtime;
	runtime.state = ScoutState::Stopping;
	runtime.diag.state = ScoutState::Stopping;
	runtime.stopRequested.store(true);
	runtime.startReady.store(true);
	bool suspended = false;
	try {
		runtime.run();
	} catch (const Strata::FreeRTOS::TaskSuspended &) {
		suspended = true;
	}
	assert(suspended);
	assert(runtime.state == ScoutState::Stopping);
	assert(runtime.diag.state == ScoutState::Stopping);
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
	const auto runScan = [&] {
		while (!runtime.processIncrementalScan(UINT64_MAX)) {
			std::this_thread::sleep_for(std::chrono::milliseconds(2));
		}
	};

	networkMode.store(NetworkMode::None);
	runScan();
	assert(hasEvent(ScoutEventType::ScanSkipped, ScoutStatus::NetworkUnavailable));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::NetworkUnavailable));
	assertTerminalScanPair(events);
	events.clear();

	networkMode.store(NetworkMode::InterfaceError);
	runScan();
	assert(hasEvent(ScoutEventType::Error, ScoutStatus::InternalError));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InternalError));
	assertTerminalScanPair(events);
	events.clear();

	networkMode.store(NetworkMode::LargeSubnet);
	runScan();
	assert(hasEvent(ScoutEventType::ScanSkipped, ScoutStatus::InvalidConfig));
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::InvalidConfig));
	assertTerminalScanPair(events);
	assert(!runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 0);
	events.clear();

	networkMode.store(NetworkMode::SmallSubnet);
	runScan();
	assert(hasEvent(ScoutEventType::ScanCompleted, ScoutStatus::Ok));
	assertTerminalScanPair(events);
	assert(runtime.diag.coverageAvailable);
	assert(runtime.diag.completedScanCount == 1);
	events.clear();

	networkMode.store(NetworkMode::PartialRequestFailure);
	runScan();
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

void testEndpointReplacementDiagnostics() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	scout_internal::InterfaceSnapshot interfaceSnapshot{};
	std::strcpy(interfaceSnapshot.name, "test");
	std::strcpy(interfaceSnapshot.key, "TEST_1");
	const uint8_t deviceMac[6] = {0x02, 0x31, 0x32, 0x33, 0x34, 0x35};

	for (size_t i = 0; i < SCOUT_MAX_ENDPOINTS_PER_DEVICE + 1; ++i) {
		interfaceSnapshot.index = static_cast<uint8_t>(i + 1);
		const uint32_t address = lwip_htonl(0xC0A80101U + static_cast<uint32_t>(i));
		runtime.observe(
		    interfaceSnapshot,
		    address,
		    deviceMac,
		    ScoutObservationSource::ArpCache,
		    false,
		    1
		);
	}
	assert(runtime.deviceCount == 1);
	assert(runtime.devices[0].info.endpointCount == SCOUT_MAX_ENDPOINTS_PER_DEVICE);
	assert(runtime.diag.endpointLimitReplacements == 1);
	runtime.releaseBuffers();
}

void testLazyDetailsAllocation() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	scout_internal::InterfaceSnapshot interfaceSnapshot{};
	interfaceSnapshot.index = 1;
	std::strcpy(interfaceSnapshot.name, "test");
	std::strcpy(interfaceSnapshot.key, "TEST_1");
	const uint8_t deviceMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x77};
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
	ScoutDeviceDetails derivedDetails{};
	runtime.snapshotDetailsLocked(0, derivedDetails);
	assert(derivedDetails.locallyAdministeredMac);
	assert(!derivedDetails.multicastMac);

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
	assert(runtime.devices[0].details->locallyAdministeredMac);

	runtime.releaseBuffers();
}

void testScalarEnrichmentSourcePrecedence() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	scout_internal::InterfaceSnapshot interfaceSnapshot{};
	interfaceSnapshot.index = 1;
	std::strcpy(interfaceSnapshot.name, "test");
	std::strcpy(interfaceSnapshot.key, "TEST_1");
	const uint8_t deviceMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x88};
	const uint32_t address = lwip_htonl(0xC0A80130U);

	runtime.observe(
	    interfaceSnapshot,
	    address,
	    deviceMac,
	    ScoutObservationSource::ArpProbe,
	    true,
	    1
	);
	const ScoutMacAddress mac = runtime.devices[0].info.mac;

	scout_internal::EnrichmentObservation ssdp{};
	ssdp.source = ScoutObservationSource::Ssdp;
	ssdp.ipv4.value = address;
	ssdp.interfaceIndex = 1;
	std::strcpy(ssdp.interfaceKey, "TEST_1");
	ssdp.identityExpiresAtMs = nowMs() + 60000;
	std::strcpy(ssdp.manufacturer, "IceWhale Technology");
	std::strcpy(ssdp.modelName, "ZimaCube");
	runtime.applyEnrichmentObservation(mac, ssdp);
	assert(runtime.devices[0].details);
	assert(std::strcmp(runtime.devices[0].details->modelName, "ZimaCube") == 0);
	assert(runtime.devices[0].details->modelNameSource == ScoutObservationSource::Ssdp);

	scout_internal::EnrichmentObservation mdns{};
	mdns.source = ScoutObservationSource::Mdns;
	mdns.ipv4.value = address;
	mdns.interfaceIndex = 1;
	std::strcpy(mdns.interfaceKey, "TEST_1");
	mdns.identityExpiresAtMs = nowMs() + 60000;
	std::strcpy(mdns.modelName, "TimeCapsule6,106");
	runtime.applyEnrichmentObservation(mac, mdns);
	assert(std::strcmp(runtime.devices[0].details->modelName, "ZimaCube") == 0);
	assert(runtime.devices[0].details->modelNameSource == ScoutObservationSource::Ssdp);

	std::strcpy(ssdp.modelName, "ZimaCube Pro");
	runtime.applyEnrichmentObservation(mac, ssdp);
	assert(std::strcmp(runtime.devices[0].details->modelName, "ZimaCube Pro") == 0);
	assert(runtime.devices[0].details->modelNameSource == ScoutObservationSource::Ssdp);

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
	stats.transportErrors = 8;
	stats.descriptionErrors = 9;
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
	assert(diagnostics.transportErrors == 8);
	assert(diagnostics.descriptionErrors == 9);
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

void testIdentityGroupConfidenceRequiresCertainConnectivity() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));
	runtime.deviceCount = 3;
	runtime.diag.deviceCount = 3;

	for (size_t i = 0; i < 3; ++i) {
		auto &record = runtime.devices[i];
		record = {};
		record.info.mac =
		    ScoutMacAddress{{0x00, 0x21, 0x22, 0x23, 0x24, static_cast<uint8_t>(i + 1)}};
		record.info.key.kind = ScoutIdentityKind::Mac;
		record.info.key.mac = record.info.mac;
		assert(runtime.ensureDetailsLocked(i) != nullptr);
	}
	auto &first = *runtime.devices[0].details;
	auto &second = *runtime.devices[1].details;
	auto &third = *runtime.devices[2].details;
	std::strcpy(first.upnpUdn, "uuid:certain-edge");
	std::strcpy(second.upnpUdn, "uuid:certain-edge");

	std::strcpy(second.manufacturer, "Example");
	std::strcpy(third.manufacturer, "Example");
	std::strcpy(second.serialNumber, "SERIAL-42");
	std::strcpy(third.serialNumber, "SERIAL-42");
	second.manufacturerSource = ScoutObservationSource::Ssdp;
	third.manufacturerSource = ScoutObservationSource::Ssdp;
	second.serialNumberSource = ScoutObservationSource::Ssdp;
	third.serialNumberSource = ScoutObservationSource::Ssdp;

	runtime.rebuildIdentityState();
	assert(runtime.identityGroupCountValue == 1);
	assert(runtime.identityGroups[0].memberCount == 3);
	assert(runtime.identityGroups[0].confidence == ScoutIdentityConfidence::Strong);

	runtime.releaseBuffers();
}

void testIdentityGroupRejectsTransitiveContradiction() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));
	runtime.deviceCount = 3;
	runtime.diag.deviceCount = 3;

	for (size_t i = 0; i < 3; ++i) {
		auto &record = runtime.devices[i];
		record = {};
		record.info.mac =
		    ScoutMacAddress{{0x00, 0x31, 0x32, 0x33, 0x34, static_cast<uint8_t>(i + 1)}};
		record.info.key.kind = ScoutIdentityKind::Mac;
		record.info.key.mac = record.info.mac;
		assert(runtime.ensureDetailsLocked(i) != nullptr);
	}
	auto &first = *runtime.devices[0].details;
	auto &second = *runtime.devices[1].details;
	auto &third = *runtime.devices[2].details;
	std::strcpy(first.upnpUdn, "uuid:bridge");
	std::strcpy(second.upnpUdn, "uuid:bridge");

	std::strcpy(second.manufacturer, "Example");
	std::strcpy(third.manufacturer, "Example");
	std::strcpy(second.serialNumber, "SERIAL-99");
	std::strcpy(third.serialNumber, "SERIAL-99");
	second.manufacturerSource = ScoutObservationSource::Ssdp;
	third.manufacturerSource = ScoutObservationSource::Ssdp;
	second.serialNumberSource = ScoutObservationSource::Ssdp;
	third.serialNumberSource = ScoutObservationSource::Ssdp;

	std::strcpy(first.persistentDeviceNamespace, "_hap._tcp");
	std::strcpy(third.persistentDeviceNamespace, "_hap._tcp");
	std::strcpy(first.persistentDeviceId, "id-a");
	std::strcpy(third.persistentDeviceId, "id-c");

	runtime.rebuildIdentityState();
	assert(runtime.identityRelationCountValue == 2);
	assert(runtime.identityGroupCountValue == 1);
	assert(runtime.identityGroups[0].memberCount == 2);
	assert(runtime.identityGroups[0].confidence == ScoutIdentityConfidence::Certain);
	assert(runtime.diag.identityContradictionBlocks == 1);

	runtime.releaseBuffers();
}

void testIdentityRelationCapacityDoesNotCreateUnbackedGroups() {
	ScoutImpl runtime;
	ScoutConfig config = runtime.config;
	config.maxIdentityRelations = 1;
	assert(runtime.allocateBuffers(config));
	runtime.deviceCount = 3;
	runtime.diag.deviceCount = 3;

	for (size_t i = 0; i < 3; ++i) {
		auto &record = runtime.devices[i];
		record = {};
		record.info.mac =
		    ScoutMacAddress{{0x00, 0x41, 0x42, 0x43, 0x44, static_cast<uint8_t>(i + 1)}};
		record.info.key.kind = ScoutIdentityKind::Mac;
		record.info.key.mac = record.info.mac;
		auto *details = runtime.ensureDetailsLocked(i);
		assert(details != nullptr);
		std::strcpy(details->persistentDeviceNamespace, "_hap._tcp");
		std::strcpy(details->persistentDeviceId, "shared-id");
	}
	runtime.rebuildIdentityState();
	assert(runtime.identityRelationCountValue == 1);
	assert(runtime.identityGroupCountValue == 1);
	assert(runtime.identityGroups[0].memberCount == 2);
	assert(runtime.diag.identityRelationDrops == 2);

	runtime.releaseBuffers();
}

void testIdentityGroupMemberLimitIsExplicit() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));

	constexpr size_t DeviceCount = SCOUT_MAX_IDENTITY_GROUP_MEMBERS + 1;
	runtime.deviceCount = DeviceCount;
	runtime.diag.deviceCount = DeviceCount;
	for (size_t i = 0; i < DeviceCount; ++i) {
		auto &record = runtime.devices[i];
		record = {};
		record.info.mac =
		    ScoutMacAddress{{0x00, 0x51, 0x52, 0x53, 0x54, static_cast<uint8_t>(i + 1)}};
		record.info.key.kind = ScoutIdentityKind::Mac;
		record.info.key.mac = record.info.mac;
		auto *details = runtime.ensureDetailsLocked(i);
		assert(details != nullptr);
		std::strcpy(details->upnpUdn, "uuid:large-physical-device");
	}
	runtime.rebuildIdentityState();
	assert(runtime.identityGroupCountValue == 1);
	assert(runtime.identityGroups[0].memberCount == SCOUT_MAX_IDENTITY_GROUP_MEMBERS);
	assert(runtime.diag.identityGroupMemberLimitDrops > 0);

	runtime.releaseBuffers();
}

void testCallerDrivenExecution() {
	networkMode.store(NetworkMode::SmallSubnet);
	Scout scout;
	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 25;
	config.scanOnInit = false;
	config.taskStackBytes = 1;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	config.arpResponseWaitMs = 1;
	config.interBatchDelayMs = 0;

	std::vector<ScoutEvent> events;
	scout.onEvent([&](const ScoutEvent &event) { events.push_back(event); });

	const ScoutResult initResult = scout.init(config);
	assert(initResult.status == ScoutStatus::Ok);
	assert(scout.executionMode() == ScoutExecutionMode::CallerDriven);
	assert(scout.running());

	const ScoutDiagnostics before = scout.diagnostics();
	assert(before.executionMode == ScoutExecutionMode::CallerDriven);
	assert(before.taskStackRegion == Strata::Region::Unknown);
	assert(before.processCalls == 0);
	assert(scout.timeUntilNextWork() > 0);

	assert(scout.scanNow().status == ScoutStatus::Ok);
	assert(scout.timeUntilNextWork() == 0);
	assert(events.empty());

	while (true) {
		const ScoutResult processResult = scout.process(25);
		assert(processResult.status == ScoutStatus::Ok);
		bool completed = false;
		for (const auto &event : events) {
			if (event.type == ScoutEventType::ScanCompleted) {
				completed = true;
				break;
			}
		}
		if (completed) {
			break;
		}
		const uint32_t waitMs = scout.timeUntilNextWork();
		if (waitMs != UINT32_MAX && waitMs > 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(waitMs));
		}
	}
	assertTerminalScanPair(events);
	assert(scout.timeUntilNextWork() > 0);

	const ScoutDiagnostics after = scout.diagnostics();
	assert(after.processCalls > 1);
	assert(after.scanCount == 1);
	assert(after.taskStackRegion == Strata::Region::Unknown);
	assert(scout.deinit().status == ScoutStatus::Ok);
}

void testMdnsBudgetContinuation() {
	networkMode.store(NetworkMode::None);
	scout_internal::testMdnsRuns.store(0);
	scout_internal::testMdnsYieldNext.store(true);

	Scout scout;
	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 25;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = true;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	assert(scout.init(config).status == ScoutStatus::Ok);

	assert(scout.process(25).status == ScoutStatus::Ok);
	assert(scout_internal::testMdnsRuns.load() == 1);
	assert(scout.timeUntilNextWork() == 0);
	assert(scout.process(25).status == ScoutStatus::Ok);
	assert(scout_internal::testMdnsRuns.load() == 2);
	assert(scout.timeUntilNextWork() > 0);
	assert(scout.diagnostics().mdns.budgetYields == 1);
	assert(scout.deinit().status == ScoutStatus::Ok);
}

void testOuiBudgetContinuation() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));
	runtime.deviceCount = 3;
	runtime.diag.deviceCount = 3;
	for (size_t i = 0; i < runtime.deviceCount; ++i) {
		auto &info = runtime.devices[i].info;
		info.mac = ScoutMacAddress{{0x00, 0x21, 0x22, 0x23, 0x24, static_cast<uint8_t>(i + 1)}};
		info.key.kind = ScoutIdentityKind::Mac;
		info.key.mac = info.mac;
	}
	std::atomic<int> lookups{0};
	runtime.ouiLookup = [&](const ScoutMacAddress &, ScoutVendorInfo &vendor) {
		lookups.fetch_add(1);
		std::this_thread::sleep_for(std::chrono::milliseconds(3));
		vendor.known = true;
		std::strcpy(vendor.name, "Example");
		return true;
	};

	const bool continuation = runtime.performOuiProvider(nowMs() + 1);
	assert(continuation);
	assert(runtime.ouiActive);
	assert(runtime.performOuiProvider(UINT64_MAX) == false);
	assert(lookups.load() == 3);
	for (size_t i = 0; i < runtime.deviceCount; ++i) {
		assert(runtime.devices[i].details);
		assert(runtime.devices[i].details->vendor.known);
	}
	runtime.releaseBuffers();
}

void testTopologyContinuationRestart() {
	ScoutImpl runtime;
	assert(runtime.allocateBuffers(runtime.config));
	runtime.registryTopologyGeneration = 2;
	runtime.ssdpState.active = true;
	runtime.ssdpState.topologyGeneration = 1;
	runtime.ssdpState.remainingInterfaces = 1;
	scout_internal::testSsdpRuns.store(0);
	(void)runtime.performSsdpProvider(UINT64_MAX);
	assert(runtime.diag.providerTopologyRestarts == 1);
	assert(scout_internal::testSsdpRuns.load() == 1);
	runtime.releaseBuffers();
}

void testIdentityRelationEvictsLowerConfidence() {
	ScoutImpl runtime;
	ScoutConfig config = runtime.config;
	config.maxIdentityRelations = 1;
	assert(runtime.allocateBuffers(config));

	ScoutIdentityRelation strong{};
	strong.first = ScoutDeviceKey{.kind = ScoutIdentityKind::Mac, .mac = ScoutMacAddress{{0, 1, 2, 3, 4, 1}}};
	strong.second = ScoutDeviceKey{.kind = ScoutIdentityKind::Mac, .mac = ScoutMacAddress{{0, 1, 2, 3, 4, 2}}};
	strong.evidence.confidence = ScoutIdentityConfidence::Strong;
	strong.evidence.type = ScoutIdentityEvidenceType::MdnsPersistentId;
	assert(runtime.storeIdentityRelation(strong));

	ScoutIdentityRelation certain = strong;
	certain.second.mac = ScoutMacAddress{{0, 1, 2, 3, 4, 3}};
	certain.evidence.confidence = ScoutIdentityConfidence::Certain;
	certain.evidence.type = ScoutIdentityEvidenceType::UpnpUdn;
	assert(runtime.storeIdentityRelation(certain));
	assert(runtime.identityRelationCountValue == 1);
	assert(runtime.identityRelations[0].evidence.confidence == ScoutIdentityConfidence::Certain);
	runtime.releaseBuffers();
}

void testTruncatedInterfacesDisableCoverage() {
	networkMode.store(NetworkMode::TruncatedInterfaces);
	Scout scout;
	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	config.arpResponseWaitMs = 1;
	config.interBatchDelayMs = 0;
	std::vector<ScoutEvent> events;
	scout.onEvent([&](const ScoutEvent &event) { events.push_back(event); });
	assert(scout.init(config).status == ScoutStatus::Ok);
	assert(scout.scanNow().status == ScoutStatus::Ok);
	while (true) {
		assert(scout.process(25).status == ScoutStatus::Ok);
		bool completed = false;
		for (const auto &event : events) {
			completed = completed || event.type == ScoutEventType::ScanCompleted;
		}
		if (completed) {
			break;
		}
		const uint32_t waitMs = scout.timeUntilNextWork();
		if (waitMs != UINT32_MAX && waitMs > 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(waitMs));
		}
	}
	const ScoutDiagnostics diagnostics = scout.diagnostics();
	assert(!diagnostics.coverageAvailable);
	assert(diagnostics.interfaceLimitDrops == 1);
	bool sawTruncation = false;
	for (const auto &event : events) {
		if (event.type == ScoutEventType::ScanSkipped &&
		    event.status == ScoutStatus::InvalidConfig) {
			sawTruncation = true;
		}
	}
	assert(sawTruncation);
	assert(scout.deinit().status == ScoutStatus::Ok);
	networkMode.store(NetworkMode::None);
}

void testProviderBudgetContinuation() {
	networkMode.store(NetworkMode::None);
	scout_internal::testSsdpRuns.store(0);
	scout_internal::testNbnsRuns.store(0);
	scout_internal::testSsdpYieldNext.store(true);
	scout_internal::testNbnsYieldNext.store(true);

	Scout scout;
	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 25;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = true;
	config.providers.nbns.enabled = true;
	config.providers.reverseDns.enabled = false;

	assert(scout.init(config).status == ScoutStatus::Ok);

	assert(scout.process(25).status == ScoutStatus::Ok);
	assert(scout_internal::testSsdpRuns.load() == 1);
	assert(scout_internal::testNbnsRuns.load() == 0);
	assert(scout.timeUntilNextWork() == 0);

	assert(scout.process(25).status == ScoutStatus::Ok);
	assert(scout_internal::testSsdpRuns.load() == 2);
	assert(scout_internal::testNbnsRuns.load() == 1);
	assert(scout.timeUntilNextWork() == 0);

	assert(scout.process(25).status == ScoutStatus::Ok);
	assert(scout_internal::testNbnsRuns.load() == 2);
	assert(scout.timeUntilNextWork() > 0);

	const ScoutDiagnostics diagnostics = scout.diagnostics();
	assert(diagnostics.ssdp.budgetYields == 1);
	assert(diagnostics.nbns.budgetYields == 1);
	assert(diagnostics.processBudgetYields >= 2);
	assert(scout.deinit().status == ScoutStatus::Ok);
}

void testCallerDrivenDeinitCompletesActiveScan() {
	networkMode.store(NetworkMode::SmallSubnet);
	Scout scout;
	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 25;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	config.arpResponseWaitMs = 1000;
	config.interBatchDelayMs = 0;

	std::vector<ScoutEvent> events;
	scout.onEvent([&](const ScoutEvent &event) { events.push_back(event); });
	assert(scout.init(config).status == ScoutStatus::Ok);
	assert(scout.scanNow().status == ScoutStatus::Ok);
	assert(scout.process(25).status == ScoutStatus::Ok);

	bool sawStarted = false;
	bool sawCompleted = false;
	for (const auto &event : events) {
		sawStarted |= event.type == ScoutEventType::ScanStarted;
		sawCompleted |= event.type == ScoutEventType::ScanCompleted;
	}
	assert(sawStarted);
	assert(!sawCompleted);

	assert(scout.deinit().status == ScoutStatus::Ok);
	assertTerminalScanPair(events);
	assert(events.back().type == ScoutEventType::ScanCompleted);
	assert(events.back().status == ScoutStatus::Cancelled);
}

void testProcessRejectsBackgroundMode() {
	Scout scout;
	ScoutConfig config;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	assert(scout.init(config).status == ScoutStatus::Ok);
	assert(scout.process(10).status == ScoutStatus::WrongExecutionMode);
	assert(std::strcmp(scout.statusToString(ScoutStatus::WrongExecutionMode), "wrong_execution_mode") == 0);
	assert(scout.deinit().status == ScoutStatus::Ok);
}

void testCallerDrivenDestructionFromCallback() {
	networkMode.store(NetworkMode::None);
	std::atomic<Scout *> scout{new Scout()};
	std::atomic<bool> destroyed{false};

	Scout *instance = scout.load();
	instance->onEvent([&](const ScoutEvent &event) {
		if (event.type != ScoutEventType::CoverageLost || destroyed.load()) {
			return;
		}
		Scout *doomed = scout.exchange(nullptr);
		assert(doomed != nullptr);
		delete doomed;
		destroyed.store(true);
	});

	ScoutConfig config;
	config.execution.mode = ScoutExecutionMode::CallerDriven;
	config.execution.workBudgetMs = 25;
	config.scanOnInit = false;
	config.providers.icmp.enabled = false;
	config.providers.mdns.enabled = false;
	config.providers.ssdp.enabled = false;
	config.providers.nbns.enabled = false;
	config.providers.reverseDns.enabled = false;
	config.arpResponseWaitMs = 1;
	config.interBatchDelayMs = 0;
	assert(instance->init(config).status == ScoutStatus::Ok);
	assert(instance->scanNow().status == ScoutStatus::Ok);

	const ScoutResult processResult = instance->process(25);
	assert(
	    processResult.status == ScoutStatus::Ok ||
	    processResult.status == ScoutStatus::Cancelled
	);
	waitUntil([&] { return destroyed.load(); });
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	assert(scout.load() == nullptr);
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
    void *,
    const ProviderRunControl *
) {
	return {};
}

ProviderRunStats runMdnsProvider(
    const ProviderTarget *,
    size_t,
    MdnsProviderState &state,
    const ScoutMdnsConfig &,
    EnrichmentSink,
    void *,
    const ProviderRunControl *
) {
	ProviderRunStats stats{};
	testMdnsRuns.fetch_add(1);
	if (testMdnsYieldNext.exchange(false)) {
		stats.budgetYielded = true;
		state.active = true;
		state.enumerationComplete = true;
		state.remainingQueries = 1;
	} else {
		state.active = false;
		state.remainingQueries = 0;
	}
	return stats;
}

ProviderRunStats runSsdpProvider(
    const ProviderTarget *,
    size_t,
    SsdpProviderState &state,
    const ScoutSsdpConfig &,
    char *,
    size_t,
    EnrichmentSink,
    void *,
    const ProviderRunControl *
) {
	ProviderRunStats stats{};
	testSsdpRuns.fetch_add(1);
	stats.plannedUnits = 2;
	stats.workUnits = 1;
	if (testSsdpYieldNext.exchange(false)) {
		stats.budgetYielded = true;
		state.active = true;
		state.interfaceCursor = 1;
		state.remainingInterfaces = 1;
	} else {
		state.active = false;
		state.remainingInterfaces = 0;
	}
	return stats;
}

ProviderRunStats runNbnsProvider(
    const ProviderTarget *,
    size_t,
    NbnsProviderState &state,
    const ScoutNbnsConfig &,
    EnrichmentSink,
    void *,
    const ProviderRunControl *
) {
	ProviderRunStats stats{};
	testNbnsRuns.fetch_add(1);
	stats.plannedUnits = 2;
	stats.workUnits = 1;
	if (testNbnsYieldNext.exchange(false)) {
		stats.budgetYielded = true;
		state.active = true;
		state.targetLimit = 2;
		state.batchOffset = 1;
	} else {
		state = {};
	}
	return stats;
}

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *,
    size_t,
    size_t &,
    const ScoutReverseDnsConfig &,
    EnrichmentSink,
    void *,
    const ProviderRunControl *
) {
	return {};
}

esp_err_t collectInterfaces(
    InterfaceSnapshot *out, size_t capacity, size_t &count, bool *truncated
) {
	const auto mode = networkMode.load();
	if (truncated != nullptr) { *truncated = mode == NetworkMode::TruncatedInterfaces; }
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
	testWorkerDoesNotRestartStoppingState();
	testLifecycleSnapshots();
	testScanStatusAndCoverage();
	testRegistryAgingAndDeduplication();
	testEndpointReplacementDiagnostics();
	testLazyDetailsAllocation();
	testScalarEnrichmentSourcePrecedence();
	testStaleProviderObservationAndDiagnostics();
	testFormattingHelpers();
	testInvalidSsdpHttpTimeout();
	testIdentityGroupingKeepsModerateRelationsSeparate();
	testIdentityGroupConfidenceRequiresCertainConnectivity();
	testIdentityGroupRejectsTransitiveContradiction();
	testIdentityRelationCapacityDoesNotCreateUnbackedGroups();
	testIdentityGroupMemberLimitIsExplicit();
	testCallerDrivenExecution();
	testMdnsBudgetContinuation();
	testOuiBudgetContinuation();
	testTopologyContinuationRestart();
	testIdentityRelationEvictsLowerConfidence();
	testTruncatedInterfacesDisableCoverage();
	testProviderBudgetContinuation();
	testCallerDrivenDeinitCompletesActiveScan();
	testProcessRejectsBackgroundMode();
	testCallerDrivenDestructionFromCallback();
	testDestructionFromCallback();
	std::cout << "Scout runtime host tests passed\n";
}
