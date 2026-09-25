#include "internal/ScoutProviders.h"
#include "internal/ScoutNetwork.h"

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
	SsdpUnrelated,
	SsdpConflict,
	SsdpBudget,
};

Scenario scenario = Scenario::None;
int nextFd = 10;
std::map<int, int> socketTypes;
std::map<int, uint32_t> boundAddresses;
std::map<int, bool> datagramDelivered;
int udpSendCount = 0;
int streamSocketCount = 0;
uint32_t lastStreamBind = 0;
uint32_t receiveDelayMs = 2;
bool httpDelivered = false;
int mdnsQueryCount = 0;
bool slowMdnsEnumeration = false;
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
	streamSocketCount = 0;
	lastStreamBind = 0;
	receiveDelayMs = 2;
	httpDelivered = false;
	mdnsQueryCount = 0;
	slowMdnsEnumeration = false;
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
	if (scenario == Scenario::SsdpConflict) {
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
	return "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
	       "\r\nConnection: close\r\n\r\n" + body;
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
	assert(state.enumerationComplete);
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
	assert(mdnsQueryCount == 2);
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

ssize_t scout_test_sendto(int, const void *, size_t length, int, const sockaddr *, socklen_t) {
	udpSendCount++;
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
	if (scenario == Scenario::Nbns) {
		std::this_thread::sleep_for(std::chrono::milliseconds(receiveDelayMs));
		errno = EAGAIN;
		return -1;
	}
	if ((scenario == Scenario::SsdpUnrelated || scenario == Scenario::SsdpConflict ||
	     scenario == Scenario::SsdpBudget) &&
	    !datagramDelivered[fd]) {
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
	info->ip.type = 4;
	info->ip.ip4.addr = netif->dns;
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
	testSsdpRejectsUnrelatedLocation();
	testSsdpConflictKeepsUsnIdentityAndLocalBind();
	testSsdpDescriptionBudgetSurvivesContinuation();
	std::cout << "Scout provider host tests passed\n";
}
