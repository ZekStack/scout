#include "internal/ScoutProviders.h"
#include "internal/ScoutNetwork.h"
#include "internal/ScoutDns.h"

#include <esp_netif.h>
#include <mdns.h>
#include <esp_timer.h>

#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class Scenario {
	None,
	Nbns,
	MdnsHostname,
	SsdpUnrelated,
	SsdpConflict,
	SsdpBudget,
	SsdpBodyLimit,
};

Scenario scenario = Scenario::None;
int nextFd = 10;
std::map<int, int> socketTypes;
std::map<int, uint32_t> boundAddresses;
std::map<int, bool> datagramDelivered;
int udpSendCount = 0;
uint32_t lastUdpDestination = 0;
uint16_t lastUdpDestinationPort = 0;
uint32_t mdnsHostnameTtlSeconds = 120;
bool mdnsForceTimeout = false;
std::map<int, std::vector<uint8_t>> sentUdpPayloads;
std::map<int, uint32_t> mdnsTargetAddresses;
std::vector<uint32_t> mdnsQueriedAddresses;
int streamSocketCount = 0;
uint32_t lastStreamBind = 0;
uint32_t receiveDelayMs = 2;
uint32_t ssdpDatagramDelayMs = 0;
bool httpDelivered = false;
size_t httpBodyPayloadSize = 0;
size_t httpHeaderPadding = 0;
int mdnsQueryCount = 0;
bool slowMdnsEnumeration = false;
bool interfaceCollectionFails = false;
size_t interfaceCountForTest = 1;
std::vector<scout_internal::EnrichmentObservation> observations;

esp_netif_t ethernetNetif{
    .key = "ETH_DEF",
    .ipv4 = 0,
    .dns = 0,
    .isDefault = true,
};
esp_netif_t wifiNetif{
    .key = "WIFI_STA_DEF",
    .ipv4 = 0,
    .dns = 0,
    .isDefault = false,
};

uint64_t nowMs() {
	return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
}

uint32_t ipv4(const char *value) {
	in_addr address{};
	assert(inet_pton(AF_INET, value, &address) == 1);
	return address.s_addr;
}

void resetHarness(Scenario nextScenario) {
	scenario = nextScenario;
	nextFd = 10;
	socketTypes.clear();
	boundAddresses.clear();
	datagramDelivered.clear();
	udpSendCount = 0;
	lastUdpDestination = 0;
	lastUdpDestinationPort = 0;
	mdnsHostnameTtlSeconds = 120;
	mdnsForceTimeout = false;
	sentUdpPayloads.clear();
	mdnsTargetAddresses.clear();
	mdnsQueriedAddresses.clear();
	streamSocketCount = 0;
	lastStreamBind = 0;
	receiveDelayMs = 2;
	ssdpDatagramDelayMs = 0;
	httpDelivered = false;
	httpBodyPayloadSize = 0;
	httpHeaderPadding = 0;
	mdnsQueryCount = 0;
	slowMdnsEnumeration = false;
	interfaceCollectionFails = false;
	interfaceCountForTest = 1;
	observations.clear();
	ethernetNetif.ipv4 = ipv4("192.168.1.1");
	ethernetNetif.dns = ipv4("192.168.1.1");
	wifiNetif.ipv4 = ipv4("192.168.2.1");
	wifiNetif.dns = ipv4("192.168.2.1");
}

scout_internal::ProviderTarget makeTarget(
    const char *interfaceKey,
    uint8_t interfaceIndex,
    const char *address,
    uint8_t macSuffix
) {
	scout_internal::ProviderTarget target{};
	target.mac =
	    ScoutMacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, static_cast<uint8_t>(macSuffix)}};
	target.ipv4.value = ipv4(address);
	target.interfaceIndex = interfaceIndex;
	std::strncpy(target.interfaceKey, interfaceKey, sizeof(target.interfaceKey) - 1);
	return target;
}

void captureObservation(
    const ScoutMacAddress &,
    const scout_internal::EnrichmentObservation &observation,
    void *
) {
	observations.push_back(observation);
}

std::string ssdpResponseForFd(int fd) {
	const uint32_t local = boundAddresses[fd];
	if (scenario == Scenario::SsdpUnrelated) {
		return "HTTP/1.1 200 OK\r\n"
		       "LOCATION: http://192.168.1.99/device.xml\r\n"
		       "USN: uuid:origin::upnp:rootdevice\r\n"
		       "ST: upnp:rootdevice\r\n"
		       "CACHE-CONTROL: max-age=60\r\n\r\n";
	}
	if (scenario == Scenario::SsdpConflict || scenario == Scenario::SsdpBodyLimit) {
		return "HTTP/1.1 200 OK\r\n"
		       "LOCATION: http://192.168.1.42/device.xml\r\n"
		       "USN: uuid:origin::upnp:rootdevice\r\n"
		       "ST: upnp:rootdevice\r\n"
		       "CACHE-CONTROL: max-age=60\r\n\r\n";
	}
	if (scenario == Scenario::SsdpBudget && local == ipv4("192.168.1.1")) {
		return "HTTP/1.1 200 OK\r\n"
		       "LOCATION: http://192.168.1.42/one.xml\r\n"
		       "USN: uuid:one::upnp:rootdevice\r\n"
		       "ST: upnp:rootdevice\r\n\r\n";
	}
	if (scenario == Scenario::SsdpBudget) {
		return "HTTP/1.1 200 OK\r\n"
		       "LOCATION: http://192.168.2.43/two.xml\r\n"
		       "USN: uuid:two::upnp:rootdevice\r\n"
		       "ST: upnp:rootdevice\r\n\r\n";
	}
	return {};
}

uint32_t senderForFd(int fd) {
	const uint32_t local = boundAddresses[fd];
	if (scenario == Scenario::SsdpBudget && local == ipv4("192.168.2.1")) {
		return ipv4("192.168.2.43");
	}
	return ipv4("192.168.1.42");
}

uint32_t mdnsTargetFromQuery(const uint8_t *query, size_t length) {
	assert(query != nullptr && length > 16);
	size_t offset = 12;
	uint8_t reversed[4]{};
	for (size_t i = 0; i < 4; ++i) {
		assert(offset < length);
		const size_t labelLength = query[offset++];
		assert(labelLength > 0 && labelLength <= 3 && offset + labelLength <= length);
		unsigned value = 0;
		for (size_t j = 0; j < labelLength; ++j) {
			const uint8_t byte = query[offset + j];
			assert(byte >= '0' && byte <= '9');
			value = value * 10U + static_cast<unsigned>(byte - '0');
		}
		assert(value <= 255U);
		reversed[i] = static_cast<uint8_t>(value);
		offset += labelLength;
	}
	const uint8_t bytes[4] = {reversed[3], reversed[2], reversed[1], reversed[0]};
	uint32_t address = 0;
	std::memcpy(&address, bytes, sizeof(address));
	return address;
}

std::vector<uint8_t> mdnsHostnameResponse(int fd) {
	const auto queryIt = sentUdpPayloads.find(fd);
	assert(queryIt != sentUdpPayloads.end());
	const auto &query = queryIt->second;
	assert(query.size() > 20);

	std::vector<uint8_t> response(256, 0);
	std::memcpy(response.data(), query.data(), query.size());
	response[2] = 0x84;
	response[3] = 0;
	response[6] = 0;
	response[7] = 1;
	size_t offset = query.size();
	response[offset++] = 0xC0;
	response[offset++] = 0x0C;
	response[offset++] = 0;
	response[offset++] = 12;
	response[offset++] = 0;
	response[offset++] = 1;
	response[offset++] = static_cast<uint8_t>((mdnsHostnameTtlSeconds >> 24U) & 0xFFU);
	response[offset++] = static_cast<uint8_t>((mdnsHostnameTtlSeconds >> 16U) & 0xFFU);
	response[offset++] = static_cast<uint8_t>((mdnsHostnameTtlSeconds >> 8U) & 0xFFU);
	response[offset++] = static_cast<uint8_t>(mdnsHostnameTtlSeconds & 0xFFU);
	response[offset++] = 0;
	response[offset++] = 19;
	response[offset++] = 11;
	std::memcpy(response.data() + offset, "Gabi-iPhone", 11);
	offset += 11;
	response[offset++] = 5;
	std::memcpy(response.data() + offset, "local", 5);
	offset += 5;
	response[offset++] = 0;
	response.resize(offset);
	return response;
}

std::string httpResponse() {
	std::string body;
	if (scenario == Scenario::SsdpConflict) {
		body = "<root><device><friendlyName>Device</friendlyName>"
		       "<manufacturer>Maker</manufacturer><serialNumber>SERIAL-X</serialNumber>"
		       "<UDN>uuid:other</UDN></device></root>";
	} else {
		body = "<root><device><friendlyName>Device</friendlyName>"
		       "<manufacturer>Maker</manufacturer><serialNumber>SERIAL-1</serialNumber>"
		       "<UDN>uuid:one</UDN></device></root>";
	}
	if (scenario == Scenario::SsdpBodyLimit && httpBodyPayloadSize > 0) {
		assert(body.size() <= httpBodyPayloadSize);
		body.append(httpBodyPayloadSize - body.size(), ' ');
	}
	std::string headers = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
	                      "\r\nConnection: close\r\n";
	if (httpHeaderPadding > 0) {
		headers += "X-Padding: " + std::string(httpHeaderPadding, 'x') + "\r\n";
	}
	return headers + "\r\n" + body;
}

void testNbnsRetriesBudgetInterruptedBatch() {
	resetHarness(Scenario::Nbns);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutNbnsConfig config{};
	config.enabled = true;
	config.maxTargetsPerRun = 1;
	config.responseWindowMs = 100;

	scout_internal::NbnsProviderState state{};
	receiveDelayMs = 15;
	const scout_internal::ProviderRunControl budget{
	    nullptr,
	    nowMs() + 10,
	    nullptr,
	};
	const auto first = scout_internal::runNbnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    &budget
	);
	assert(first.budgetYielded);
	assert(state.active);
	assert(state.batchOffset == 0);
	assert(udpSendCount == 1);

	config.responseWindowMs = 1;
	receiveDelayMs = 2;
	const auto second = scout_internal::runNbnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(!second.budgetYielded);
	assert(!state.active);
	assert(udpSendCount == 2);
}

void testMdnsEnumerationResumesIntoServiceQuery() {
	resetHarness(Scenario::None);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutMdnsConfig config{};
	config.enabled = true;
	config.queryTimeoutMs = 100;
	config.maxServiceQueriesPerRun = 1;

	scout_internal::MdnsProviderState state{};
	slowMdnsEnumeration = true;
	const scout_internal::ProviderRunControl budget{
	    nullptr,
	    nowMs() + 10,
	    nullptr,
	};
	const auto first = scout_internal::runMdnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    &budget
	);
	assert(first.budgetYielded);
	assert(state.active);
	assert(!state.enumerationComplete);
	assert(mdnsQueryCount == 1);

	slowMdnsEnumeration = false;
	const auto second = scout_internal::runMdnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(!second.budgetYielded);
	assert(!state.active);
	assert(mdnsQueryCount == 3);
}

void testDirectMdnsHostnameDiscovery() {
	resetHarness(Scenario::MdnsHostname);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutMdnsConfig config{};
	config.enabled = true;
	config.serviceDiscoveryEnabled = false;
	config.hostnameDiscoveryEnabled = true;
	config.hostnameQueryTimeoutMs = 20;
	config.maxHostnameTargetsPerRun = 1;

	scout_internal::MdnsProviderState state{};
	const auto stats = scout_internal::runMdnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    nullptr
	);

	assert(!state.active);
	assert(stats.hostnameQueries == 1);
	assert(stats.hostnameResponses == 1);
	assert(stats.observations == 1);
	assert(mdnsQueryCount == 0);
	assert(udpSendCount == 1);
	assert(lastUdpDestination == ipv4("224.0.0.251"));
	assert(lastUdpDestinationPort == 5353);
	assert(boundAddresses[10] == ipv4("192.168.1.1"));
	assert(observations.size() == 1);
	assert(observations[0].source == ScoutObservationSource::Mdns);
	assert(observations[0].nameCount == 1);
	assert(observations[0].names[0].source == ScoutNameSource::MdnsHostname);
	assert(std::strcmp(observations[0].names[0].value, "Gabi-iPhone.local") == 0);
	assert(
	    observations[0].names[0].expiresAtMs - observations[0].names[0].lastSeenAtMs ==
	    120000ULL
	);
}

void testDirectMdnsHostnameGoodbyeTtl() {
	resetHarness(Scenario::MdnsHostname);
	mdnsHostnameTtlSeconds = 0;
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutMdnsConfig config{};
	config.serviceDiscoveryEnabled = false;
	config.hostnameDiscoveryEnabled = true;
	config.hostnameQueryTimeoutMs = 20;
	config.maxHostnameTargetsPerRun = 1;

	scout_internal::MdnsProviderState state{};
	const auto stats = scout_internal::runMdnsProvider(
	    &target,
	    1,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(stats.hostnameResponses == 1);
	assert(observations.size() == 1);
	assert(observations[0].nameCount == 1);
	assert(
	    observations[0].names[0].expiresAtMs - observations[0].names[0].lastSeenAtMs ==
	    1000ULL
	);
}

void testDirectMdnsHostnameRotation() {
	resetHarness(Scenario::MdnsHostname);
	scout_internal::ProviderTarget targets[] = {
	    makeTarget("ETH_DEF", 1, "192.168.1.42", 1),
	    makeTarget("ETH_DEF", 1, "192.168.1.43", 2),
	    makeTarget("ETH_DEF", 1, "192.168.1.44", 3),
	};
	ScoutMdnsConfig config{};
	config.serviceDiscoveryEnabled = false;
	config.hostnameDiscoveryEnabled = true;
	config.hostnameQueryTimeoutMs = 20;
	config.maxHostnameTargetsPerRun = 1;

	scout_internal::MdnsProviderState state{};
	for (size_t i = 0; i < 4; ++i) {
		const auto stats = scout_internal::runMdnsProvider(
		    targets,
		    3,
		    state,
		    config,
		    &captureObservation,
		    nullptr,
		    nullptr
		);
		assert(stats.hostnameQueries == 1);
		assert(stats.hostnameResponses == 1);
		assert(!state.active);
	}
	assert(mdnsQueriedAddresses.size() == 4);
	assert(mdnsQueriedAddresses[0] == ipv4("192.168.1.42"));
	assert(mdnsQueriedAddresses[1] == ipv4("192.168.1.43"));
	assert(mdnsQueriedAddresses[2] == ipv4("192.168.1.44"));
	assert(mdnsQueriedAddresses[3] == ipv4("192.168.1.42"));
}

void testDirectMdnsHostnameBudgetRetry() {
	resetHarness(Scenario::MdnsHostname);
	scout_internal::ProviderTarget targets[] = {
	    makeTarget("ETH_DEF", 1, "192.168.1.42", 1),
	    makeTarget("ETH_DEF", 1, "192.168.1.43", 2),
	};
	ScoutMdnsConfig config{};
	config.serviceDiscoveryEnabled = false;
	config.hostnameDiscoveryEnabled = true;
	config.hostnameQueryTimeoutMs = 100;
	config.maxHostnameTargetsPerRun = 1;

	scout_internal::MdnsProviderState state{};
	std::atomic<bool> stopRequested{false};
	mdnsForceTimeout = true;
	receiveDelayMs = 60;
	const scout_internal::ProviderRunControl limited{
	    &stopRequested,
	    nowMs() + 50,
	    nullptr,
	};
	const auto first = scout_internal::runMdnsProvider(
	    targets,
	    2,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    &limited
	);
	assert(first.budgetYielded);
	assert(state.active);
	assert(state.hostnameCursor == 0);
	assert(state.hostnameRemaining == 1);
	assert(mdnsQueriedAddresses.size() == 1);
	assert(mdnsQueriedAddresses[0] == ipv4("192.168.1.42"));

	mdnsForceTimeout = false;
	const auto second = scout_internal::runMdnsProvider(
	    targets,
	    2,
	    state,
	    config,
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(!second.budgetYielded);
	assert(!state.active);
	assert(mdnsQueriedAddresses.size() == 2);
	assert(mdnsQueriedAddresses[1] == ipv4("192.168.1.42"));
	assert(state.hostnameCursor == 1);
}

void testSsdpRejectsUnrelatedLocation() {
	resetHarness(Scenario::SsdpUnrelated);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 1;
	config.httpTimeoutMs = 100;
	config.maxDescriptionFetchesPerRun = 4;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};

	const auto stats = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(stats.descriptionErrors == 1);
	assert(stats.dropped == 1);
	assert(streamSocketCount == 0);
	assert(observations.size() == 1);
	assert(std::strcmp(observations[0].upnpUdn, "uuid:origin") == 0);
}

void testSsdpConflictKeepsUsnIdentityAndLocalBind() {
	resetHarness(Scenario::SsdpConflict);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 1;
	config.httpTimeoutMs = 100;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};

	const auto stats = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(stats.identityConflicts == 1);
	assert(streamSocketCount == 1);
	assert(lastStreamBind == ipv4("192.168.1.1"));
	assert(observations.size() == 1);
	assert(std::strcmp(observations[0].upnpUdn, "uuid:origin") == 0);
	assert(observations[0].serialNumber[0] == '\0');
}

void testSsdpPreservesObservationWhenDescriptionBudgetExpires() {
	resetHarness(Scenario::SsdpConflict);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 100;
	config.httpTimeoutMs = 100;
	config.maxDescriptionFetchesPerRun = 4;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};

	ssdpDatagramDelayMs = 15;
	const scout_internal::ProviderRunControl budget{
	    nullptr,
	    nowMs() + 10,
	    nullptr,
	};
	const auto stats = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    &budget
	);

	assert(stats.budgetYielded);
	assert(streamSocketCount == 0);
	assert(observations.size() == 1);
	assert(std::strcmp(observations[0].upnpUdn, "uuid:origin") == 0);
}

void testSsdpDescriptionBodyLimitExcludesHeaders() {
	resetHarness(Scenario::SsdpBodyLimit);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 1;
	config.httpTimeoutMs = 100;
	config.maxDescriptionBytes = 256;
	httpBodyPayloadSize = config.maxDescriptionBytes;
	httpHeaderPadding = 512;
	char scratch[scout_internal::ProviderHttpHeaderBytes + 257]{};
	scout_internal::SsdpProviderState state{};

	const auto accepted = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(accepted.descriptionErrors == 0);
	assert(observations.size() == 1);
	assert(observations[0].nameCount == 1);

	resetHarness(Scenario::SsdpBodyLimit);
	httpBodyPayloadSize = config.maxDescriptionBytes + 1;
	state = {};
	const auto rejected = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(rejected.descriptionErrors == 1);
	assert(observations.size() == 1);
	assert(observations[0].nameCount == 0);
}

void testSsdpInterfaceFailureClearsContinuationState() {
	resetHarness(Scenario::SsdpConflict);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};
	state.active = true;
	state.interfaceSignature = 123;
	state.remainingInterfaces = 1;
	state.descriptionFetches = 1;
	state.fetchedLocationHashes[0] = 456;
	state.fetchedLocationCount = 1;

	interfaceCollectionFails = true;
	const auto stats = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);

	assert(stats.errors == 1);
	assert(stats.transportErrors == 1);
	assert(!state.active);
	assert(state.remainingInterfaces == 0);
	assert(state.descriptionFetches == 0);
	assert(state.fetchedLocationCount == 0);
}

void testSsdpTopologyRestartResetsDescriptionState() {
	resetHarness(Scenario::SsdpConflict);
	auto target = makeTarget("ETH_DEF", 1, "192.168.1.42", 1);
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 1;
	config.httpTimeoutMs = 100;
	config.maxDescriptionFetchesPerRun = 1;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};
	state.active = true;
	state.interfaceSignature = 1;
	state.remainingInterfaces = 1;
	state.descriptionFetches = 1;
	state.fetchedLocationHashes[0] = 456;
	state.fetchedLocationCount = 1;

	const auto stats = scout_internal::runSsdpProvider(
	    &target,
	    1,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);

	assert(stats.topologyRestarts == 1);
	assert(streamSocketCount == 1);
	assert(observations.size() == 1);
	assert(stats.identityConflicts == 1);
}

void testSsdpDescriptionBudgetSurvivesContinuation() {
	resetHarness(Scenario::SsdpBudget);
	interfaceCountForTest = 2;
	scout_internal::ProviderTarget targets[2] = {
	    makeTarget("ETH_DEF", 1, "192.168.1.42", 1),
	    makeTarget("WIFI_STA_DEF", 2, "192.168.2.43", 2),
	};
	ScoutSsdpConfig config{};
	config.enabled = true;
	config.responseWindowMs = 100;
	config.httpTimeoutMs = 100;
	config.maxDescriptionFetchesPerRun = 1;
	char scratch[4096]{};
	scout_internal::SsdpProviderState state{};

	receiveDelayMs = 25;
	const scout_internal::ProviderRunControl budget{
	    nullptr,
	    nowMs() + 20,
	    nullptr,
	};
	const auto first = scout_internal::runSsdpProvider(
	    targets,
	    2,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    &budget
	);
	assert(first.budgetYielded);
	assert(state.active);
	assert(state.remainingInterfaces == 1);
	assert(state.descriptionFetches == 1);
	assert(streamSocketCount == 1);

	config.responseWindowMs = 1;
	receiveDelayMs = 2;
	const auto second = scout_internal::runSsdpProvider(
	    targets,
	    2,
	    state,
	    config,
	    scratch,
	    sizeof(scratch),
	    &captureObservation,
	    nullptr,
	    nullptr
	);
	assert(!state.active);
	assert(second.dropped >= 1);
	assert(streamSocketCount == 1);
}

} // namespace

int scout_test_socket(int, int type, int) {
	const int fd = nextFd++;
	socketTypes[fd] = type;
	if (type == SOCK_STREAM) {
		streamSocketCount++;
	}
	return fd;
}

int scout_test_setsockopt(int, int, int, const void *, socklen_t) {
	return 0;
}

int scout_test_bind(int fd, const sockaddr *address, socklen_t) {
	const auto *ipv4Address = reinterpret_cast<const sockaddr_in *>(address);
	boundAddresses[fd] = ipv4Address->sin_addr.s_addr;
	if (socketTypes[fd] == SOCK_STREAM) {
		lastStreamBind = ipv4Address->sin_addr.s_addr;
	}
	return 0;
}

ssize_t scout_test_sendto(
    int fd,
    const void *data,
    size_t length,
    int,
    const sockaddr *destination,
    socklen_t
) {
	udpSendCount++;
	if (destination != nullptr) {
		const auto *ipv4Destination = reinterpret_cast<const sockaddr_in *>(destination);
		lastUdpDestination = ipv4Destination->sin_addr.s_addr;
		lastUdpDestinationPort = ntohs(ipv4Destination->sin_port);
		if (scenario == Scenario::MdnsHostname && lastUdpDestinationPort == 5353 &&
		    data != nullptr) {
			const auto *bytes = static_cast<const uint8_t *>(data);
			sentUdpPayloads[fd] = std::vector<uint8_t>(bytes, bytes + length);
			const uint32_t target = mdnsTargetFromQuery(bytes, length);
			mdnsTargetAddresses[fd] = target;
			mdnsQueriedAddresses.push_back(target);
		}
	}
	return static_cast<ssize_t>(length);
}

ssize_t scout_test_recvfrom(
    int fd,
    void *buffer,
    size_t length,
    int,
    sockaddr *source,
    socklen_t *sourceLength
) {
	if (scenario == Scenario::MdnsHostname) {
		if (mdnsForceTimeout) {
			std::this_thread::sleep_for(std::chrono::milliseconds(receiveDelayMs));
			errno = EAGAIN;
			return -1;
		}
		if (!datagramDelivered[fd]) {
			const auto response = mdnsHostnameResponse(fd);
			assert(response.size() <= length);
			std::memcpy(buffer, response.data(), response.size());
			auto *sender = reinterpret_cast<sockaddr_in *>(source);
			sender->sin_family = AF_INET;
			sender->sin_port = htons(5353);
			sender->sin_addr.s_addr = mdnsTargetAddresses[fd];
			if (sourceLength != nullptr) {
				*sourceLength = sizeof(sockaddr_in);
			}
			datagramDelivered[fd] = true;
			return static_cast<ssize_t>(response.size());
		}
	}
	if (scenario == Scenario::Nbns) {
		std::this_thread::sleep_for(std::chrono::milliseconds(receiveDelayMs));
		errno = EAGAIN;
		return -1;
	}
	if ((scenario == Scenario::SsdpUnrelated || scenario == Scenario::SsdpConflict ||
	     scenario == Scenario::SsdpBudget || scenario == Scenario::SsdpBodyLimit) &&
	    !datagramDelivered[fd]) {
		if (ssdpDatagramDelayMs > 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(ssdpDatagramDelayMs));
		}
		const std::string response = ssdpResponseForFd(fd);
		assert(response.size() <= length);
		std::memcpy(buffer, response.data(), response.size());
		auto *sender = reinterpret_cast<sockaddr_in *>(source);
		sender->sin_family = AF_INET;
		sender->sin_port = htons(1900);
		sender->sin_addr.s_addr = senderForFd(fd);
		if (sourceLength != nullptr) {
			*sourceLength = sizeof(sockaddr_in);
		}
		datagramDelivered[fd] = true;
		return static_cast<ssize_t>(response.size());
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(receiveDelayMs));
	errno = EAGAIN;
	return -1;
}

int scout_test_close(int) {
	return 0;
}

int scout_test_connect(int, const sockaddr *, socklen_t) {
	return 0;
}

int scout_test_getsockopt(int, int, int, void *value, socklen_t *) {
	*static_cast<int *>(value) = 0;
	return 0;
}

ssize_t scout_test_send(int, const void *, size_t length, int) {
	return static_cast<ssize_t>(length);
}

ssize_t scout_test_recv(int, void *buffer, size_t length, int) {
	if (httpDelivered) {
		return 0;
	}
	const std::string response = httpResponse();
	assert(response.size() <= length);
	std::memcpy(buffer, response.data(), response.size());
	httpDelivered = true;
	return static_cast<ssize_t>(response.size());
}

int scout_test_select(int, fd_set *, fd_set *, fd_set *, timeval *) {
	return 1;
}

int scout_test_fcntl(int, int command, ...) {
	if (command == F_GETFL) {
		return 0;
	}
	return 0;
}

esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) {
	if (key != nullptr && std::strcmp(key, ethernetNetif.key) == 0) {
		return &ethernetNetif;
	}
	if (key != nullptr && std::strcmp(key, wifiNetif.key) == 0) {
		return &wifiNetif;
	}
	return nullptr;
}

esp_err_t esp_netif_get_ip_info(esp_netif_t *netif, esp_netif_ip_info_t *info) {
	if (netif == nullptr || info == nullptr) {
		return ESP_FAIL;
	}
	info->ip.addr = netif->ipv4;
	return ESP_OK;
}

esp_err_t
esp_netif_get_dns_info(esp_netif_t *netif, esp_netif_dns_type_t, esp_netif_dns_info_t *info) {
	if (netif == nullptr || info == nullptr || netif->dns == 0) {
		return ESP_FAIL;
	}
	info->ip.type = ESP_IPADDR_TYPE_V4;
	info->ip.u_addr.ip4.addr = netif->dns;
	return ESP_OK;
}

esp_netif_t *esp_netif_get_default_netif() {
	return &ethernetNetif;
}

const char *esp_netif_get_ifkey(esp_netif_t *netif) {
	return netif != nullptr ? netif->key : nullptr;
}

esp_err_t mdns_init() {
	return ESP_OK;
}

esp_err_t mdns_query_ptr(
    const char *service,
    const char *,
    uint32_t,
    size_t,
    mdns_result_t **results
) {
	mdnsQueryCount++;
	if (results != nullptr) {
		*results = nullptr;
	}
	if (slowMdnsEnumeration && service != nullptr &&
	    std::strcmp(service, "_services._dns-sd") == 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(15));
	}
	return ESP_ERR_TIMEOUT;
}

void mdns_query_results_free(mdns_result_t *) {
}

namespace scout_internal {

esp_err_t collectInterfaces(
    InterfaceSnapshot *out, size_t capacity, size_t &count, bool *truncated
) {
	if (truncated != nullptr) {
		*truncated = false;
	}
	if (interfaceCollectionFails) {
		count = 0;
		return ESP_FAIL;
	}
	assert(capacity >= interfaceCountForTest);
	count = interfaceCountForTest;
	out[0] = {};
	out[0].index = 1;
	out[0].ipv4 = ipv4("192.168.1.1");
	std::strcpy(out[0].key, "ETH_DEF");
	out[0].type = ScoutInterfaceType::Ethernet;
	if (count > 1) {
		out[1] = {};
		out[1].index = 2;
		out[1].ipv4 = ipv4("192.168.2.1");
		std::strcpy(out[1].key, "WIFI_STA_DEF");
		out[1].type = ScoutInterfaceType::WifiStation;
	}
	return ESP_OK;
}

} // namespace scout_internal

int main() {
	testNbnsRetriesBudgetInterruptedBatch();
	testMdnsEnumerationResumesIntoServiceQuery();
	testDirectMdnsHostnameDiscovery();
	testDirectMdnsHostnameGoodbyeTtl();
	testDirectMdnsHostnameRotation();
	testDirectMdnsHostnameBudgetRetry();
	testSsdpRejectsUnrelatedLocation();
	testSsdpConflictKeepsUsnIdentityAndLocalBind();
	testSsdpPreservesObservationWhenDescriptionBudgetExpires();
	testSsdpDescriptionBodyLimitExcludesHeaders();
	testSsdpInterfaceFailureClearsContinuationState();
	testSsdpTopologyRestartResetsDescriptionState();
	testSsdpDescriptionBudgetSurvivesContinuation();
	std::cout << "Scout provider host tests passed\n";
}
