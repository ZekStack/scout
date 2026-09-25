#include "ScoutProviders.h"

#include "ScoutDns.h"
#include "ScoutEnrichment.h"
#include "ScoutNetwork.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <strings.h>

#include <esp_netif.h>
#include <esp_timer.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <unistd.h>

#if __has_include(<mdns.h>)
#include <mdns.h>
#define SCOUT_HAS_MDNS 1
#else
#define SCOUT_HAS_MDNS 0
#endif

#if __has_include(<ping/ping_sock.h>)
#include <ping/ping_sock.h>
#define SCOUT_HAS_PING 1
#else
#define SCOUT_HAS_PING 0
#endif

namespace scout_internal {
namespace {

constexpr size_t MaxMdnsServiceTypes = ProviderMaxMdnsServiceTypes;
constexpr size_t MaxProviderTargetsPerRun = 32;
constexpr size_t MaxSsdpDescriptionFetches = ProviderMaxSsdpDescriptionFetches;
constexpr size_t NbnsBatchSize = 8;
constexpr uint32_t SocketPollMs = 50;

using MdnsServiceType = ProviderMdnsServiceType;

uint64_t providerNowMs() {
	return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
}

bool providerShouldStop(const ProviderRunControl *control) {
	if (control == nullptr) {
		return false;
	}
	if (control->stopRequested != nullptr &&
	    control->stopRequested->load(std::memory_order_acquire)) {
		return true;
	}
	return control->deadlineMs != UINT64_MAX && providerNowMs() >= control->deadlineMs;
}

void recordProviderStop(ProviderRunStats &stats, const ProviderRunControl *control) {
	if (control == nullptr) {
		return;
	}
	if (control->stopRequested != nullptr &&
	    control->stopRequested->load(std::memory_order_acquire)) {
		stats.cancelled = true;
		return;
	}
	if (control->deadlineMs != UINT64_MAX && providerNowMs() >= control->deadlineMs) {
		stats.budgetYielded = true;
	}
}

uint32_t providerRemainingMs(const ProviderRunControl *control, uint32_t fallbackMs) {
	if (control == nullptr || control->deadlineMs == UINT64_MAX) {
		return fallbackMs;
	}
	const uint64_t now = providerNowMs();
	if (now >= control->deadlineMs) {
		return 0;
	}
	return static_cast<uint32_t>(std::min<uint64_t>(fallbackMs, control->deadlineMs - now));
}

uint64_t expiryFromTtl(uint64_t now, uint32_t ttlSeconds, uint64_t fallbackMs) {
	if (ttlSeconds == 0) {
		return now + fallbackMs;
	}
	return now + static_cast<uint64_t>(ttlSeconds) * 1000ULL;
}

uint64_t mdnsRetentionFloorMs(
    const ScoutMdnsConfig &config, size_t serviceTypeCount, size_t serviceQueryCount
) {
	if (serviceQueryCount == 0 || config.intervalMs == 0 || config.fallbackMaxAgeMs == 0) {
		return 0;
	}
	const uint64_t rotationRuns = (serviceTypeCount + serviceQueryCount - 1U) / serviceQueryCount;
	const uint64_t retentionRuns = rotationRuns + 1U;
	if (retentionRuns > config.fallbackMaxAgeMs / config.intervalMs) {
		return config.fallbackMaxAgeMs;
	}
	return std::min<uint64_t>(
	    config.fallbackMaxAgeMs,
	    static_cast<uint64_t>(config.intervalMs) * retentionRuns
	);
}

bool targetMatchesInterface(const ProviderTarget &target, const char *interfaceKey) {
	if (interfaceKey == nullptr || interfaceKey[0] == '\0') {
		return true;
	}
	return target.interfaceKey[0] != '\0' &&
	       textEqualsIgnoreCase(target.interfaceKey, interfaceKey);
}

const ProviderTarget *findTarget(
    const ProviderTarget *targets, size_t targetCount, uint32_t ipv4, const char *interfaceKey
) {
	if (targets == nullptr || ipv4 == 0) {
		return nullptr;
	}

	if (interfaceKey != nullptr && interfaceKey[0] != '\0') {
		for (size_t i = 0; i < targetCount; ++i) {
			if (targets[i].ipv4.value == ipv4 && targetMatchesInterface(targets[i], interfaceKey)) {
				return &targets[i];
			}
		}
		return nullptr;
	}

	const ProviderTarget *match = nullptr;
	for (size_t i = 0; i < targetCount; ++i) {
		if (targets[i].ipv4.value != ipv4) {
			continue;
		}
		if (match != nullptr) {
			return nullptr;
		}
		match = &targets[i];
	}
	return match;
}

uint64_t hashLocation(const char *interfaceKey, const char *location) {
	constexpr uint64_t OffsetBasis = 1469598103934665603ULL;
	constexpr uint64_t Prime = 1099511628211ULL;
	uint64_t hash = OffsetBasis;
	auto add = [&](const char *value) {
		if (value == nullptr) {
			return;
		}
		for (; *value != '\0'; ++value) {
			unsigned char byte = static_cast<unsigned char>(*value);
			if (byte >= 'A' && byte <= 'Z') {
				byte = static_cast<unsigned char>(byte - 'A' + 'a');
			}
			hash ^= byte;
			hash *= Prime;
		}
	};
	add(interfaceKey);
	hash ^= 0xFFU;
	hash *= Prime;
	add(location);
	return hash;
}

bool locationAddressAllowed(
    const ProviderTarget *targets,
    size_t targetCount,
    const ProviderTarget &origin,
    uint32_t resolvedIpv4
) {
	if (resolvedIpv4 == 0) {
		return false;
	}
	for (size_t i = 0; i < targetCount; ++i) {
		const auto &candidate = targets[i];
		if (candidate.ipv4.value != resolvedIpv4 || candidate.mac != origin.mac) {
			continue;
		}
		if (origin.interfaceKey[0] == '\0' || candidate.interfaceKey[0] == '\0' ||
		    textEqualsIgnoreCase(origin.interfaceKey, candidate.interfaceKey)) {
			return true;
		}
	}
	return false;
}

bool selectDnsServer(
    const ProviderTarget &target,
    esp_netif_t *netif,
    const ProviderRunControl *control,
    uint32_t &serverIpv4
) {
	serverIpv4 = 0;
	if (control != nullptr && control->dnsServerLookup != nullptr &&
	    static_cast<bool>(*control->dnsServerLookup)) {
		ScoutIpv4Address server{};
		if ((*control->dnsServerLookup)(target.interfaceKey, server) && server.valid()) {
			serverIpv4 = server.value;
			return true;
		}
	}

#if defined(CONFIG_ESP_NETIF_SET_DNS_PER_DEFAULT_NETIF) && CONFIG_ESP_NETIF_SET_DNS_PER_DEFAULT_NETIF
	(void)target;
#else
	if (netif != esp_netif_get_default_netif()) {
		return false;
	}
#endif

	esp_netif_dns_info_t dnsInfo{};
	esp_err_t dnsResult = esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dnsInfo);
	if (dnsResult != ESP_OK || !IP_IS_V4_VAL(dnsInfo.ip) ||
	    ip4_addr_isany_val(*ip_2_ip4(&dnsInfo.ip))) {
		dnsInfo = {};
		dnsResult = esp_netif_get_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dnsInfo);
	}
	if (dnsResult != ESP_OK || !IP_IS_V4_VAL(dnsInfo.ip) ||
	    ip4_addr_isany_val(*ip_2_ip4(&dnsInfo.ip))) {
		return false;
	}
	serverIpv4 = ip_2_ip4(&dnsInfo.ip)->addr;
	return true;
}

bool setSocketTimeout(int socketFd, uint32_t timeoutMs) {
	struct timeval timeout{
	    .tv_sec = static_cast<time_t>(timeoutMs / 1000U),
	    .tv_usec = static_cast<suseconds_t>((timeoutMs % 1000U) * 1000U),
	};
	return setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
	       setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

int openBoundUdpSocket(uint32_t localIpv4, uint32_t timeoutMs) {
	const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		return -1;
	}
	if (!setSocketTimeout(fd, timeoutMs)) {
		close(fd);
		return -1;
	}

	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_port = 0;
	local.sin_addr.s_addr = localIpv4;
	if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

DnsPtrAnswer queryPtr(
    const ProviderTarget &target, uint32_t timeoutMs, const ProviderRunControl *control
) {
	DnsPtrAnswer result{};
	if (target.interfaceKey[0] == '\0') {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}

	esp_netif_t *netif = esp_netif_get_handle_from_ifkey(target.interfaceKey);
	if (netif == nullptr) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}

	esp_netif_ip_info_t ipInfo{};
	if (esp_netif_get_ip_info(netif, &ipInfo) != ESP_OK || ipInfo.ip.addr == 0) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}

	uint32_t dnsServer = 0;
	if (!selectDnsServer(target, netif, control, dnsServer)) {
		result.status = DnsParseStatus::ResolverUnavailable;
		return result;
	}

	const int fd = openBoundUdpSocket(ipInfo.ip.addr, timeoutMs);
	if (fd < 0) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}

	const uint16_t transactionId = static_cast<uint16_t>(
	    (providerNowMs() ^ target.ipv4.value ^ target.interfaceIndex) & 0xFFFFU
	);
	uint8_t request[128]{};
	uint8_t ipv4Bytes[4]{};
	std::memcpy(ipv4Bytes, &target.ipv4.value, sizeof(ipv4Bytes));
	const size_t requestLength = buildPtrQuery(transactionId, ipv4Bytes, request, sizeof(request));
	if (requestLength == 0) {
		close(fd);
		result.status = DnsParseStatus::Malformed;
		return result;
	}

	sockaddr_in destination{};
	destination.sin_family = AF_INET;
	destination.sin_port = htons(53);
	destination.sin_addr.s_addr = dnsServer;

	if (sendto(
	        fd,
	        request,
	        requestLength,
	        0,
	        reinterpret_cast<const sockaddr *>(&destination),
	        sizeof(destination)
	    ) < 0) {
		close(fd);
		result.status = DnsParseStatus::NetworkError;
		return result;
	}

	uint8_t response[768]{};
	sockaddr_in sender{};
	socklen_t senderLength = sizeof(sender);
	const int received = recvfrom(
	    fd,
	    response,
	    sizeof(response),
	    0,
	    reinterpret_cast<sockaddr *>(&sender),
	    &senderLength
	);
	const int socketError = errno;
	close(fd);

	if (received <= 0) {
		result.status = socketError == EAGAIN || socketError == EWOULDBLOCK
		                    ? DnsParseStatus::Timeout
		                    : DnsParseStatus::NetworkError;
		return result;
	}
	if (sender.sin_addr.s_addr != destination.sin_addr.s_addr ||
	    sender.sin_port != destination.sin_port) {
		result.status = DnsParseStatus::Malformed;
		return result;
	}
	return parsePtrResponse(response, static_cast<size_t>(received), transactionId, ipv4Bytes);
}

DnsAAnswer queryA(
    const ProviderTarget &target,
    const char *hostname,
    uint32_t timeoutMs,
    const ProviderRunControl *control
) {
	DnsAAnswer result{};
	if (target.interfaceKey[0] == '\0' || hostname == nullptr || hostname[0] == '\0') {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}
	esp_netif_t *netif = esp_netif_get_handle_from_ifkey(target.interfaceKey);
	if (netif == nullptr) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}
	esp_netif_ip_info_t ipInfo{};
	if (esp_netif_get_ip_info(netif, &ipInfo) != ESP_OK || ipInfo.ip.addr == 0) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}
	uint32_t dnsServer = 0;
	if (!selectDnsServer(target, netif, control, dnsServer)) {
		result.status = DnsParseStatus::ResolverUnavailable;
		return result;
	}

	const int fd = openBoundUdpSocket(ipInfo.ip.addr, timeoutMs);
	if (fd < 0) {
		result.status = DnsParseStatus::NetworkError;
		return result;
	}
	const uint16_t transactionId = static_cast<uint16_t>(
	    (providerNowMs() ^ target.ipv4.value ^ 0xA5A5U) & 0xFFFFU
	);
	uint8_t request[256]{};
	const size_t requestLength =
	    buildAQuery(transactionId, hostname, request, sizeof(request));
	if (requestLength == 0) {
		close(fd);
		result.status = DnsParseStatus::Malformed;
		return result;
	}
	sockaddr_in destination{};
	destination.sin_family = AF_INET;
	destination.sin_port = htons(53);
	destination.sin_addr.s_addr = dnsServer;
	if (sendto(
	        fd,
	        request,
	        requestLength,
	        0,
	        reinterpret_cast<const sockaddr *>(&destination),
	        sizeof(destination)
	    ) < 0) {
		close(fd);
		result.status = DnsParseStatus::NetworkError;
		return result;
	}
	uint8_t response[768]{};
	sockaddr_in sender{};
	socklen_t senderLength = sizeof(sender);
	const int received = recvfrom(
	    fd,
	    response,
	    sizeof(response),
	    0,
	    reinterpret_cast<sockaddr *>(&sender),
	    &senderLength
	);
	const int socketError = errno;
	close(fd);
	if (received <= 0) {
		result.status = socketError == EAGAIN || socketError == EWOULDBLOCK
		                    ? DnsParseStatus::Timeout
		                    : DnsParseStatus::NetworkError;
		return result;
	}
	if (sender.sin_addr.s_addr != destination.sin_addr.s_addr ||
	    sender.sin_port != destination.sin_port) {
		result.status = DnsParseStatus::Malformed;
		return result;
	}
	return parseAResponse(response, static_cast<size_t>(received), transactionId, hostname);
}

void appendMetadata(
    EnrichmentObservation &observation,
    ScoutObservationSource source,
    const char *key,
    const char *value,
    uint64_t now,
    uint64_t expiresAt
) {
	if (key == nullptr || key[0] == '\0' || value == nullptr || value[0] == '\0' ||
	    observation.metadataCount >= ProviderObservationMetadataCapacity) {
		return;
	}
	auto &metadata = observation.metadata[observation.metadataCount++];
	metadata = {};
	metadata.source = source;
	copyText(metadata.key, sizeof(metadata.key), key);
	copyText(metadata.value, sizeof(metadata.value), value != nullptr ? value : "");
	metadata.firstSeenAtMs = now;
	metadata.lastSeenAtMs = now;
	metadata.expiresAtMs = expiresAt;
}

void addName(
    EnrichmentObservation &observation,
    ScoutNameSource source,
    const char *value,
    uint64_t now,
    uint64_t expiresAt
) {
	if (value == nullptr || value[0] == '\0' || observation.nameCount >= 2) {
		return;
	}
	auto &name = observation.names[observation.nameCount++];
	name = {};
	name.source = source;
	copyText(name.value, sizeof(name.value), value);
	name.firstSeenAtMs = now;
	name.lastSeenAtMs = now;
	name.expiresAtMs = expiresAt;
}

bool persistentTxtIdHasStrongSemantics(const char *service, const char *key) {
	if (service == nullptr || key == nullptr) {
		return false;
	}
	const bool idKey = textEqualsIgnoreCase(key, "id");
	if (!idKey) {
		return false;
	}
	return textEqualsIgnoreCase(service, "_googlecast") || textEqualsIgnoreCase(service, "_hap");
}

void maybeSetPersistentField(
    EnrichmentObservation &observation,
    const char *service,
    const char *proto,
    const char *key,
    const char *value
) {
	if (key == nullptr || value == nullptr || value[0] == '\0') {
		return;
	}
	if (persistentTxtIdHasStrongSemantics(service, key)) {
		copyText(observation.persistentDeviceId, sizeof(observation.persistentDeviceId), value);
		std::snprintf(
		    observation.persistentDeviceNamespace,
		    sizeof(observation.persistentDeviceNamespace),
		    "%s.%s",
		    service,
		    proto != nullptr ? proto : ""
		);
	} else if (textEqualsIgnoreCase(key, "serial") || textEqualsIgnoreCase(key, "serialnumber")) {
		copyText(observation.serialNumber, sizeof(observation.serialNumber), value);
	} else if (textEqualsIgnoreCase(key, "manufacturer") || textEqualsIgnoreCase(key, "vendor")) {
		copyText(observation.manufacturer, sizeof(observation.manufacturer), value);
	} else if (textEqualsIgnoreCase(key, "model") || textEqualsIgnoreCase(key, "modelname")) {
		copyText(observation.modelName, sizeof(observation.modelName), value);
	}
}

#if SCOUT_HAS_PING
struct PingContext {
	std::atomic<bool> done{false};
	std::atomic<bool> replied{false};
};

void onPingSuccess(esp_ping_handle_t, void *args) {
	auto *context = static_cast<PingContext *>(args);
	if (context != nullptr) {
		context->replied.store(true, std::memory_order_release);
	}
}

void onPingTimeout(esp_ping_handle_t, void *) {
}

void onPingEnd(esp_ping_handle_t, void *args) {
	auto *context = static_cast<PingContext *>(args);
	if (context != nullptr) {
		context->done.store(true, std::memory_order_release);
	}
}
#endif

bool addServiceType(
    MdnsServiceType *types, size_t &count, size_t capacity, const char *service, const char *proto
) {
	if (types == nullptr || service == nullptr || proto == nullptr || service[0] == '\0' ||
	    proto[0] == '\0') {
		return false;
	}
	for (size_t i = 0; i < count; ++i) {
		if (textEqualsIgnoreCase(types[i].service, service) &&
		    textEqualsIgnoreCase(types[i].proto, proto)) {
			return false;
		}
	}
	if (count >= capacity) {
		return false;
	}
	copyText(types[count].service, sizeof(types[count].service), service);
	copyText(types[count].proto, sizeof(types[count].proto), proto);
	count++;
	return true;
}

bool splitServiceDescriptor(
    const char *value, char *service, size_t serviceCapacity, char *proto, size_t protoCapacity
) {
	if (value == nullptr) {
		return false;
	}
	const char *tcp = std::strstr(value, "._tcp");
	const char *udp = std::strstr(value, "._udp");
	const char *separator = tcp != nullptr ? tcp : udp;
	if (separator == nullptr || separator == value) {
		return false;
	}
	copyTextN(service, serviceCapacity, value, static_cast<size_t>(separator - value));
	copyText(proto, protoCapacity, separator + 1);
	return true;
}

#if SCOUT_HAS_MDNS
void emitMdnsResult(
    const mdns_result_t &result,
    const ProviderTarget *targets,
    size_t targetCount,
    const ScoutMdnsConfig &config,
    uint64_t retentionFloorMs,
    EnrichmentSink sink,
    void *context,
    ProviderRunStats &stats
) {
	const uint64_t now = providerNowMs();
	const uint64_t ttlExpiresAt = expiryFromTtl(now, result.ttl, config.fallbackMaxAgeMs);
	const uint64_t floorExpiresAt =
	    retentionFloorMs > UINT64_MAX - now ? UINT64_MAX : now + retentionFloorMs;
	const uint64_t expiresAt = std::max(ttlExpiresAt, floorExpiresAt);
	const char *interfaceKey =
	    result.esp_netif != nullptr ? esp_netif_get_ifkey(result.esp_netif) : nullptr;

	for (mdns_ip_addr_t *address = result.addr; address != nullptr; address = address->next) {
		if (address->addr.type != MDNS_IP_PROTOCOL_V4) {
			continue;
		}
		const uint32_t ipv4 = address->addr.u_addr.ip4.addr;
		const ProviderTarget *target = findTarget(targets, targetCount, ipv4, interfaceKey);
		if (target == nullptr) {
			continue;
		}

		EnrichmentObservation observation{};
		observation.source = ScoutObservationSource::Mdns;
		observation.ipv4.value = ipv4;
		observation.interfaceIndex = target->interfaceIndex;
		copyText(observation.interfaceKey, sizeof(observation.interfaceKey), target->interfaceKey);
		observation.identityExpiresAtMs = expiresAt;
		addName(observation, ScoutNameSource::MdnsHostname, result.hostname, now, expiresAt);
		addName(observation, ScoutNameSource::MdnsInstance, result.instance_name, now, expiresAt);

		if (result.service_type != nullptr && result.service_type[0] != '\0') {
			observation.hasService = true;
			auto &service = observation.service;
			service.source = ScoutObservationSource::Mdns;
			copyText(service.type, sizeof(service.type), result.service_type);
			copyText(service.protocol, sizeof(service.protocol), result.proto);
			copyText(service.instanceName, sizeof(service.instanceName), result.instance_name);
			copyText(service.hostname, sizeof(service.hostname), result.hostname);
			service.port = result.port;
			service.interfaceIndex = target->interfaceIndex;
			service.ttlSeconds = result.ttl;
			service.firstSeenAtMs = now;
			service.lastSeenAtMs = now;
			service.expiresAtMs = expiresAt;
		}

		for (size_t i = 0; i < result.txt_count && i < ProviderObservationMetadataCapacity; ++i) {
			const char *key = result.txt[i].key;
			const char *value = result.txt[i].value;
			const size_t valueLength = result.txt_value_len != nullptr
			                               ? result.txt_value_len[i]
			                               : (value != nullptr ? std::strlen(value) : 0);
			auto &metadata = observation.metadata[observation.metadataCount++];
			metadata = {};
			metadata.source = ScoutObservationSource::Mdns;
			copyText(metadata.key, sizeof(metadata.key), key != nullptr ? key : "");
			copyTextN(
			    metadata.value,
			    sizeof(metadata.value),
			    value != nullptr ? value : "",
			    valueLength
			);
			metadata.firstSeenAtMs = now;
			metadata.lastSeenAtMs = now;
			metadata.expiresAtMs = expiresAt;
			maybeSetPersistentField(
			    observation,
			    result.service_type,
			    result.proto,
			    metadata.key,
			    metadata.value
			);
		}
		if (result.txt_count > ProviderObservationMetadataCapacity) {
			stats.dropped += result.txt_count - ProviderObservationMetadataCapacity;
		}

		for (mdns_ip_addr_t *extra = result.addr;
		     extra != nullptr && observation.ipv6Count < SCOUT_MAX_IPV6_PER_ENDPOINT;
		     extra = extra->next) {
			if (extra->addr.type != MDNS_IP_PROTOCOL_V6) {
				continue;
			}
			auto &ipv6 = observation.ipv6[observation.ipv6Count++];
			std::memcpy(ipv6.bytes, extra->addr.u_addr.ip6.addr, sizeof(ipv6.bytes));
		}

		sink(target->mac, observation, context);
		stats.observations++;
	}
}
#endif

struct ParsedHttpUrl {
	char host[128] = {};
	char path[256] = "/";
	uint16_t port = 80;
};

enum class HttpFetchStatus : uint8_t {
	Ok,
	Timeout,
	NetworkError,
	InvalidResponse,
	HttpError,
	TooLarge,
	UnsupportedEncoding,
	UnsupportedAddress,
	ResolverUnavailable,
};

struct HttpFetchResult {
	HttpFetchStatus status = HttpFetchStatus::InvalidResponse;
	size_t bodyLength = 0;
};

bool parseHttpUrl(const char *url, ParsedHttpUrl &out) {
	out = {};
	if (!copyText(out.path, sizeof(out.path), "/") || url == nullptr ||
	    std::strncmp(url, "http://", 7) != 0) {
		return false;
	}
	const char *hostStart = url + 7;
	if (*hostStart == '\0' || *hostStart == '[' || std::strchr(hostStart, '@') != nullptr) {
		return false;
	}
	const char *pathStart = std::strchr(hostStart, '/');
	const char *hostEnd = pathStart != nullptr ? pathStart : hostStart + std::strlen(hostStart);
	const char *colon = nullptr;
	for (const char *cursor = hostStart; cursor < hostEnd; ++cursor) {
		if (*cursor == ':') {
			if (colon != nullptr) {
				return false;
			}
			colon = cursor;
		}
	}
	const char *nameEnd = colon != nullptr ? colon : hostEnd;
	if (nameEnd == hostStart ||
	    !copyTextN(out.host, sizeof(out.host), hostStart, static_cast<size_t>(nameEnd - hostStart))) {
		return false;
	}
	if (colon != nullptr) {
		if (colon + 1 == hostEnd) {
			return false;
		}
		unsigned port = 0;
		for (const char *cursor = colon + 1; cursor < hostEnd; ++cursor) {
			if (*cursor < '0' || *cursor > '9') {
				return false;
			}
			const unsigned digit = static_cast<unsigned>(*cursor - '0');
			if (port > (65535U - digit) / 10U) {
				return false;
			}
			port = port * 10U + digit;
		}
		if (port == 0) {
			return false;
		}
		out.port = static_cast<uint16_t>(port);
	}
	if (pathStart != nullptr && !copyText(out.path, sizeof(out.path), pathStart)) {
		return false;
	}
	return true;
}

enum class SocketIoStatus : uint8_t {
	Ok,
	Timeout,
	Error,
};

SocketIoStatus waitSocketReady(int fd, bool writable, uint64_t deadlineMs) {
	for (;;) {
		const uint64_t now = providerNowMs();
		if (now >= deadlineMs) {
			return SocketIoStatus::Timeout;
		}
		const uint64_t remainingMs = deadlineMs - now;
		timeval timeout{
		    .tv_sec = static_cast<time_t>(remainingMs / 1000U),
		    .tv_usec = static_cast<suseconds_t>((remainingMs % 1000U) * 1000U),
		};
		fd_set readSet;
		fd_set writeSet;
		FD_ZERO(&readSet);
		FD_ZERO(&writeSet);
		if (writable) {
			FD_SET(fd, &writeSet);
		} else {
			FD_SET(fd, &readSet);
		}
		const int selected = select(
		    fd + 1,
		    writable ? nullptr : &readSet,
		    writable ? &writeSet : nullptr,
		    nullptr,
		    &timeout
		);
		if (selected > 0) {
			return SocketIoStatus::Ok;
		}
		if (selected == 0) {
			return SocketIoStatus::Timeout;
		}
		if (errno != EINTR) {
			return SocketIoStatus::Error;
		}
	}
}

bool setNonBlocking(int fd) {
	const int flags = fcntl(fd, F_GETFL, 0);
	return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

SocketIoStatus sendAll(int fd, const char *data, size_t length, uint64_t deadlineMs) {
	size_t sent = 0;
	while (sent < length) {
		const int count = send(fd, data + sent, length - sent, 0);
		if (count > 0) {
			sent += static_cast<size_t>(count);
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			const auto ready = waitSocketReady(fd, true, deadlineMs);
			if (ready != SocketIoStatus::Ok) {
				return ready;
			}
			continue;
		}
		return SocketIoStatus::Error;
	}
	return SocketIoStatus::Ok;
}

bool hasChunkedTransferEncoding(const char *data, size_t length) {
	const char *body = std::strstr(data, "\r\n\r\n");
	if (body == nullptr || body >= data + length) {
		return false;
	}
	const size_t headerLength = static_cast<size_t>(body - data) + 4;
	for (size_t i = 0; i + 18 < headerLength; ++i) {
		if ((i == 0 || data[i - 1] == '\n') &&
		    strncasecmp(data + i, "Transfer-Encoding:", 18) == 0) {
			const char *value = data + i + 18;
			const char *lineEnd = std::strstr(value, "\r\n");
			if (lineEnd == nullptr || lineEnd > data + headerLength) {
				return false;
			}
			for (const char *p = value; p + 7 <= lineEnd; ++p) {
				if (strncasecmp(p, "chunked", 7) == 0) {
					return true;
				}
			}
		}
	}
	return false;
}

bool completeContentLengthBody(const char *data, size_t length) {
	const char *body = std::strstr(data, "\r\n\r\n");
	if (body == nullptr || body >= data + length) {
		return false;
	}
	body += 4;
	const size_t headerLength = static_cast<size_t>(body - data);
	for (size_t i = 0; i + 15 < headerLength; ++i) {
		if ((i == 0 || data[i - 1] == '\n') && strncasecmp(data + i, "Content-Length:", 15) == 0) {
			const char *value = data + i + 15;
			while (value < data + headerLength && (*value == ' ' || *value == '\t')) {
				value++;
			}
			size_t declared = 0;
			bool hasDigit = false;
			while (value < data + headerLength && *value >= '0' && *value <= '9') {
				const size_t digit = static_cast<size_t>(*value - '0');
				if (declared > (SIZE_MAX - digit) / 10U) {
					return false;
				}
				hasDigit = true;
				declared = declared * 10U + digit;
				value++;
			}
			return hasDigit && length - headerLength >= declared;
		}
	}
	return false;
}

HttpFetchResult fetchHttpBody(
    const char *url,
    const ProviderTarget &origin,
    const ProviderTarget *targets,
    size_t targetCount,
    uint32_t timeoutMs,
    char *scratch,
    size_t capacity,
    const ProviderRunControl *control
) {
	HttpFetchResult result{};
	if (scratch == nullptr || capacity < 2 || timeoutMs == 0) {
		return result;
	}
	ParsedHttpUrl parsed{};
	if (!parseHttpUrl(url, parsed)) {
		return result;
	}

	const uint64_t deadlineMs = providerNowMs() + timeoutMs;
	sockaddr_in remote{};
	remote.sin_family = AF_INET;
	remote.sin_port = htons(parsed.port);
	if (inet_pton(AF_INET, parsed.host, &remote.sin_addr) == 1) {
		if (!locationAddressAllowed(targets, targetCount, origin, remote.sin_addr.s_addr)) {
			result.status = HttpFetchStatus::UnsupportedAddress;
			return result;
		}
	} else {
		const uint64_t now = providerNowMs();
		if (now >= deadlineMs) {
			result.status = HttpFetchStatus::Timeout;
			return result;
		}
		const uint32_t dnsTimeout =
		    static_cast<uint32_t>(std::min<uint64_t>(UINT32_MAX, deadlineMs - now));
		const DnsAAnswer answer = queryA(origin, parsed.host, dnsTimeout, control);
		if (answer.status != DnsParseStatus::Ok) {
			result.status = answer.status == DnsParseStatus::ResolverUnavailable
			                    ? HttpFetchStatus::ResolverUnavailable
			                : answer.status == DnsParseStatus::Timeout
			                    ? HttpFetchStatus::Timeout
			                    : HttpFetchStatus::NetworkError;
			return result;
		}
		bool resolved = false;
		for (size_t i = 0; i < answer.addressCount; ++i) {
			if (!locationAddressAllowed(targets, targetCount, origin, answer.addresses[i])) {
				continue;
			}
			remote.sin_addr.s_addr = answer.addresses[i];
			resolved = true;
			break;
		}
		if (!resolved) {
			result.status = HttpFetchStatus::UnsupportedAddress;
			return result;
		}
	}
	const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		result.status = HttpFetchStatus::NetworkError;
		return result;
	}
	if (!setNonBlocking(fd)) {
		close(fd);
		result.status = HttpFetchStatus::NetworkError;
		return result;
	}

	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_port = 0;
	local.sin_addr.s_addr = origin.ipv4.value;
	if (origin.ipv4.value == 0 ||
	    bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0) {
		close(fd);
		result.status = HttpFetchStatus::NetworkError;
		return result;
	}

	if (connect(fd, reinterpret_cast<const sockaddr *>(&remote), sizeof(remote)) != 0) {
		if (errno != EINPROGRESS && errno != EAGAIN && errno != EWOULDBLOCK) {
			const int socketError = errno;
			close(fd);
			if (socketError == ETIMEDOUT) {
				result.status = HttpFetchStatus::Timeout;
			} else {
				result.status = HttpFetchStatus::NetworkError;
			}
			return result;
		}
		const auto ready = waitSocketReady(fd, true, deadlineMs);
		if (ready != SocketIoStatus::Ok) {
			close(fd);
			if (ready == SocketIoStatus::Timeout) {
				result.status = HttpFetchStatus::Timeout;
			} else {
				result.status = HttpFetchStatus::NetworkError;
			}
			return result;
		}
		int socketError = 0;
		socklen_t socketErrorLength = sizeof(socketError);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 ||
		    socketError != 0) {
			close(fd);
			if (socketError == ETIMEDOUT) {
				result.status = HttpFetchStatus::Timeout;
			} else {
				result.status = HttpFetchStatus::NetworkError;
			}
			return result;
		}
	}

	char request[512] = {};
	const int requestLength = std::snprintf(
	    request,
	    sizeof(request),
	    "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n"
	    "Accept: application/xml,text/xml,*/*\r\n\r\n",
	    parsed.path,
	    parsed.host,
	    static_cast<unsigned>(parsed.port)
	);
	if (requestLength <= 0 || static_cast<size_t>(requestLength) >= sizeof(request)) {
		close(fd);
		result.status = HttpFetchStatus::InvalidResponse;
		return result;
	}
	const size_t requestSize = static_cast<size_t>(requestLength);
	const auto sendStatus = sendAll(fd, request, requestSize, deadlineMs);
	if (sendStatus != SocketIoStatus::Ok) {
		close(fd);
		if (sendStatus == SocketIoStatus::Timeout) {
			result.status = HttpFetchStatus::Timeout;
		} else {
			result.status = HttpFetchStatus::NetworkError;
		}
		return result;
	}

	size_t received = 0;
	bool complete = false;
	while (received + 1 < capacity) {
		const auto ready = waitSocketReady(fd, false, deadlineMs);
		if (ready != SocketIoStatus::Ok) {
			close(fd);
			result.status = ready == SocketIoStatus::Timeout ? HttpFetchStatus::Timeout
			                                                 : HttpFetchStatus::NetworkError;
			return result;
		}

		const int count = recv(fd, scratch + received, capacity - received - 1, 0);
		if (count == 0) {
			complete = true;
			break;
		}
		if (count < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			close(fd);
			result.status = HttpFetchStatus::NetworkError;
			return result;
		}
		received += static_cast<size_t>(count);
		scratch[received] = '\0';
		if (hasChunkedTransferEncoding(scratch, received)) {
			close(fd);
			result.status = HttpFetchStatus::UnsupportedEncoding;
			return result;
		}
		if (completeContentLengthBody(scratch, received)) {
			complete = true;
			break;
		}
	}
	close(fd);
	scratch[received] = '\0';

	if (!complete && received + 1 >= capacity) {
		result.status = HttpFetchStatus::TooLarge;
		return result;
	}
	if (received < 12 || std::strncmp(scratch, "HTTP/1.", 7) != 0) {
		return result;
	}
	const char *statusSpace = std::strchr(scratch, ' ');
	if (statusSpace == nullptr || statusSpace + 3 >= scratch + received || statusSpace[1] < '0' ||
	    statusSpace[1] > '9' || statusSpace[2] < '0' || statusSpace[2] > '9' ||
	    statusSpace[3] < '0' || statusSpace[3] > '9') {
		return result;
	}
	const int statusCode =
	    (statusSpace[1] - '0') * 100 + (statusSpace[2] - '0') * 10 + (statusSpace[3] - '0');
	if (statusCode < 200 || statusCode >= 300) {
		result.status = HttpFetchStatus::HttpError;
		return result;
	}

	char *body = std::strstr(scratch, "\r\n\r\n");
	if (body == nullptr) {
		return result;
	}
	body += 4;
	const size_t headerLength = static_cast<size_t>(body - scratch);

	for (size_t i = 0; i + 18 < headerLength; ++i) {
		if ((i == 0 || scratch[i - 1] == '\n') &&
		    strncasecmp(scratch + i, "Transfer-Encoding:", 18) == 0) {
			const char *value = scratch + i + 18;
			const char *lineEnd = std::strstr(value, "\r\n");
			if (lineEnd != nullptr) {
				for (const char *p = value; p + 7 <= lineEnd; ++p) {
					if (strncasecmp(p, "chunked", 7) == 0) {
						result.status = HttpFetchStatus::UnsupportedEncoding;
						return result;
					}
				}
			}
		}
	}

	const size_t bodyLength = received >= headerLength ? received - headerLength : 0;
	bool hasContentLength = false;
	size_t declaredLength = 0;
	for (size_t i = 0; i + 15 < headerLength; ++i) {
		if ((i == 0 || scratch[i - 1] == '\n') &&
		    strncasecmp(scratch + i, "Content-Length:", 15) == 0) {
			const char *value = scratch + i + 15;
			while (value < scratch + headerLength && (*value == ' ' || *value == '\t')) {
				value++;
			}
			size_t declared = 0;
			bool hasDigit = false;
			while (value < scratch + headerLength && *value >= '0' && *value <= '9') {
				const size_t digit = static_cast<size_t>(*value - '0');
				if (declared > (SIZE_MAX - digit) / 10U) {
					result.status = HttpFetchStatus::TooLarge;
					return result;
				}
				hasDigit = true;
				declared = declared * 10U + digit;
				value++;
			}
			if (!hasDigit) {
				result.status = HttpFetchStatus::InvalidResponse;
				return result;
			}
			if (hasContentLength && declaredLength != declared) {
				result.status = HttpFetchStatus::InvalidResponse;
				return result;
			}
			hasContentLength = true;
			declaredLength = declared;
		}
	}
	if (hasContentLength) {
		if (declaredLength > bodyLength) {
			result.status = declaredLength >= capacity ? HttpFetchStatus::TooLarge
			                                           : HttpFetchStatus::InvalidResponse;
			return result;
		}
		std::memmove(scratch, body, declaredLength);
		scratch[declaredLength] = '\0';
		result.status = HttpFetchStatus::Ok;
		result.bodyLength = declaredLength;
		return result;
	}

	std::memmove(scratch, body, bodyLength);
	scratch[bodyLength] = '\0';
	result.status = HttpFetchStatus::Ok;
	result.bodyLength = bodyLength;
	return result;
}

void extractUpnpUdn(const char *usn, char *out, size_t capacity) {
	if (usn == nullptr || out == nullptr || capacity == 0) {
		return;
	}
	const char *end = std::strstr(usn, "::");
	const size_t length = end != nullptr ? static_cast<size_t>(end - usn) : std::strlen(usn);
	if (length > 5 && std::strncmp(usn, "uuid:", 5) == 0) {
		copyTextN(out, capacity, usn, length);
	}
}

void buildNbnsNodeStatusRequest(uint8_t *buffer, size_t capacity, uint16_t transactionId) {
	if (buffer == nullptr || capacity < 50) {
		return;
	}
	std::memset(buffer, 0, 50);
	buffer[0] = static_cast<uint8_t>(transactionId >> 8U);
	buffer[1] = static_cast<uint8_t>(transactionId & 0xFFU);
	buffer[4] = 0;
	buffer[5] = 1;
	buffer[12] = 32;
	uint8_t rawName[16];
	std::memset(rawName, ' ', sizeof(rawName));
	rawName[0] = '*';
	for (size_t i = 0; i < sizeof(rawName); ++i) {
		buffer[13 + i * 2] = static_cast<uint8_t>('A' + ((rawName[i] >> 4U) & 0x0FU));
		buffer[14 + i * 2] = static_cast<uint8_t>('A' + (rawName[i] & 0x0FU));
	}
	buffer[45] = 0;
	buffer[46] = 0;
	buffer[47] = 0x21;
	buffer[48] = 0;
	buffer[49] = 1;
}

} // namespace

ProviderRunStats runIcmpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutIcmpConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
		return stats;
	}
#if SCOUT_HAS_PING
	const size_t limit = std::min({MaxProviderTargetsPerRun, config.maxTargetsPerRun, targetCount});
	stats.plannedUnits = limit;
	size_t processedCount = 0;
	for (; processedCount < limit; ++processedCount) {
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			break;
		}
		const size_t index = (cursor + processedCount) % targetCount;
		const auto &target = targets[index];

		PingContext pingContext{};
		esp_ping_config_t pingConfig = ESP_PING_DEFAULT_CONFIG();
		pingConfig.count = 1;
		pingConfig.interval_ms = 0;
		const uint32_t pingTimeout = providerRemainingMs(control, config.timeoutMs);
		if (pingTimeout == 0) {
			recordProviderStop(stats, control);
			break;
		}
		stats.workUnits++;
		pingConfig.timeout_ms = pingTimeout;
		pingConfig.task_stack_size = config.taskStackBytes;
		pingConfig.task_prio = config.taskPriority;
		pingConfig.interface = target.interfaceIndex;
		pingConfig.target_addr.type = IPADDR_TYPE_V4;
		pingConfig.target_addr.u_addr.ip4.addr = target.ipv4.value;

		esp_ping_callbacks_t callbacks{};
		callbacks.on_ping_success = onPingSuccess;
		callbacks.on_ping_timeout = onPingTimeout;
		callbacks.on_ping_end = onPingEnd;
		callbacks.cb_args = &pingContext;

		esp_ping_handle_t handle = nullptr;
		if (esp_ping_new_session(&pingConfig, &callbacks, &handle) != ESP_OK || handle == nullptr) {
			stats.errors++;
			continue;
		}
		if (esp_ping_start(handle) != ESP_OK) {
			esp_ping_delete_session(handle);
			stats.errors++;
			continue;
		}

		uint64_t deadline = providerNowMs() + static_cast<uint64_t>(pingTimeout) + 250U;
		if (control != nullptr && control->deadlineMs != UINT64_MAX) {
			deadline = std::min(deadline, control->deadlineMs);
		}
		while (!pingContext.done.load(std::memory_order_acquire) && providerNowMs() < deadline &&
		       !providerShouldStop(control)) {
			vTaskDelay(pdMS_TO_TICKS(5));
		}
		const bool sessionTimedOut = !pingContext.done.load(std::memory_order_acquire);
		if (sessionTimedOut) {
			esp_ping_stop(handle);
		}
		const bool replied = pingContext.replied.load(std::memory_order_acquire);
		esp_ping_delete_session(handle);

		if (replied) {
			EnrichmentObservation observation{};
			observation.source = ScoutObservationSource::Icmp;
			observation.ipv4 = target.ipv4;
			observation.interfaceIndex = target.interfaceIndex;
			copyText(
			    observation.interfaceKey,
			    sizeof(observation.interfaceKey),
			    target.interfaceKey
			);
			observation.confirmed = true;
			sink(target.mac, observation, context);
			stats.observations++;
		} else {
			(void)sessionTimedOut;
			stats.timeouts++;
		}
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
	}
	cursor = (cursor + processedCount) % targetCount;
#else
	(void)cursor;
	(void)config;
	(void)context;
	stats.errors = 1;
#endif
	return stats;
}

ProviderRunStats runMdnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    MdnsProviderState &state,
    const ScoutMdnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		state.active = false;
		state.enumerationComplete = false;
		state.serviceTypeCount = 0;
		state.remainingQueries = 0;
		return stats;
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
		return stats;
	}
#if SCOUT_HAS_MDNS
	if (config.initializeIfNeeded) {
		const esp_err_t initResult = mdns_init();
		if (initResult != ESP_OK && initResult != ESP_ERR_INVALID_STATE) {
			stats.errors++;
			return stats;
		}
	}

	if (!state.active) {
		state.active = true;
		state.enumerationComplete = false;
		state.serviceTypeCount = 0;
		state.remainingQueries = 0;
		const size_t serviceTypeCapacity =
		    std::min(config.maxServiceTypes, MaxMdnsServiceTypes);
		constexpr struct {
			const char *service;
			const char *proto;
		} CommonServices[] = {
		    {"_http", "_tcp"},        {"_https", "_tcp"},
		    {"_workstation", "_tcp"}, {"_device-info", "_tcp"},
		    {"_airplay", "_tcp"},     {"_raop", "_tcp"},
		    {"_googlecast", "_tcp"},  {"_ipp", "_tcp"},
		    {"_ipps", "_tcp"},        {"_printer", "_tcp"},
		    {"_ssh", "_tcp"},         {"_sftp-ssh", "_tcp"},
		    {"_smb", "_tcp"},         {"_home-assistant", "_tcp"},
		    {"_hap", "_tcp"},         {"_matter", "_tcp"},
		    {"_matterc", "_udp"},     {"_arduino", "_tcp"},
		    {"_esphomelib", "_tcp"},
		};
		for (const auto &service : CommonServices) {
			addServiceType(
			    state.serviceTypes,
			    state.serviceTypeCount,
			    serviceTypeCapacity,
			    service.service,
			    service.proto
			);
		}
	}

	if (!state.enumerationComplete) {
		const size_t serviceTypeCapacity =
		    std::min(config.maxServiceTypes, MaxMdnsServiceTypes);
		uint32_t enumerationTimeout = std::max<uint32_t>(20, config.queryTimeoutMs / 4U);
		enumerationTimeout = providerRemainingMs(control, enumerationTimeout);
		if (enumerationTimeout == 0) {
			recordProviderStop(stats, control);
			return stats;
		}
		mdns_result_t *serviceTypes = nullptr;
		const esp_err_t enumerationResult = mdns_query_ptr(
		    "_services._dns-sd",
		    "_udp",
		    enumerationTimeout,
		    serviceTypeCapacity,
		    &serviceTypes
		);
		if (enumerationResult == ESP_OK) {
			for (mdns_result_t *result = serviceTypes; result != nullptr; result = result->next) {
				const char *descriptor =
				    result->instance_name != nullptr ? result->instance_name : result->hostname;
				char service[SCOUT_SERVICE_TYPE_SIZE] = {};
				char proto[SCOUT_SERVICE_PROTO_SIZE] = {};
				if (splitServiceDescriptor(
				        descriptor,
				        service,
				        sizeof(service),
				        proto,
				        sizeof(proto)
				    )) {
					if (!addServiceType(
					        state.serviceTypes,
					        state.serviceTypeCount,
					        serviceTypeCapacity,
					        service,
					        proto
					    ) &&
					    state.serviceTypeCount >= serviceTypeCapacity) {
						stats.dropped++;
					}
				}
			}
			mdns_query_results_free(serviceTypes);
		} else if (enumerationResult == ESP_ERR_TIMEOUT) {
			stats.timeouts++;
		} else {
			stats.errors++;
		}
		state.enumerationComplete = true;
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			return stats;
		}
	}

	if (state.serviceTypeCount == 0) {
		state.active = false;
		state.enumerationComplete = false;
		return stats;
	}

	if (state.remainingQueries == 0) {
		state.remainingQueries =
		    std::min(state.serviceTypeCount, config.maxServiceQueriesPerRun);
	}
	stats.plannedUnits = state.remainingQueries;
	const size_t runQueryCount =
	    std::min(state.serviceTypeCount, config.maxServiceQueriesPerRun);
	const uint64_t retentionFloorMs =
	    mdnsRetentionFloorMs(config, state.serviceTypeCount, runQueryCount);
	uint32_t baseTimeout = config.queryTimeoutMs /
	                       static_cast<uint32_t>(std::max<size_t>(1, runQueryCount));
	baseTimeout = std::max<uint32_t>(1, baseTimeout);

	while (state.remainingQueries > 0) {
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			break;
		}
		const uint32_t perQueryTimeout = providerRemainingMs(control, baseTimeout);
		if (perQueryTimeout == 0) {
			recordProviderStop(stats, control);
			break;
		}
		const size_t i = state.serviceCursor % state.serviceTypeCount;
		mdns_result_t *results = nullptr;
		stats.workUnits++;
		const esp_err_t queryResult = mdns_query_ptr(
		    state.serviceTypes[i].service,
		    state.serviceTypes[i].proto,
		    perQueryTimeout,
		    config.maxResults,
		    &results
		);
		state.serviceCursor = (state.serviceCursor + 1) % state.serviceTypeCount;
		state.remainingQueries--;
		if (queryResult != ESP_OK) {
			if (queryResult == ESP_ERR_TIMEOUT) {
				stats.timeouts++;
			} else {
				stats.errors++;
			}
			continue;
		}
		for (mdns_result_t *result = results; result != nullptr; result = result->next) {
			emitMdnsResult(
			    *result,
			    targets,
			    targetCount,
			    config,
			    retentionFloorMs,
			    sink,
			    context,
			    stats
			);
		}
		mdns_query_results_free(results);
	}

	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
	}
	if (!stats.budgetYielded && !stats.cancelled && state.remainingQueries == 0) {
		state.active = false;
		state.enumerationComplete = false;
		state.serviceTypeCount = 0;
	}
#else
	(void)config;
	(void)context;
	(void)state;
	stats.errors = 1;
#endif
	return stats;
}

ProviderRunStats runSsdpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    SsdpProviderState &state,
    const ScoutSsdpConfig &config,
    char *httpScratch,
    size_t httpScratchCapacity,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		state = {};
		return stats;
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
		return stats;
	}

	InterfaceSnapshot interfaces[MaxInterfaces]{};
	size_t interfaceCount = 0;
	if (collectInterfaces(interfaces, MaxInterfaces, interfaceCount) != ESP_OK) {
		stats.errors++;
		stats.transportErrors++;
		state.remainingInterfaces = 0;
		return stats;
	}
	if (interfaceCount == 0) {
		state = {};
		return stats;
	}
	if (!state.active) {
		state.active = true;
		state.remainingInterfaces = interfaceCount;
		state.descriptionFetches = 0;
		state.fetchedLocationCount = 0;
	}
	state.interfaceCursor %= interfaceCount;
	const size_t plannedInterfaces = std::min(state.remainingInterfaces, interfaceCount);
	stats.plannedUnits = plannedInterfaces;
	constexpr char Search[] = "M-SEARCH * HTTP/1.1\r\n"
	                          "HOST: 239.255.255.250:1900\r\n"
	                          "MAN: \"ssdp:discover\"\r\n"
	                          "MX: 1\r\n"
	                          "ST: ssdp:all\r\n\r\n";
	sockaddr_in destination{};
	destination.sin_family = AF_INET;
	destination.sin_port = htons(1900);
	inet_pton(AF_INET, "239.255.255.250", &destination.sin_addr);

	auto rememberLocation = [&](const char *interfaceKey, const char *location) {
		if (location == nullptr || location[0] == '\0') {
			return false;
		}
		const uint64_t hash = hashLocation(interfaceKey, location);
		for (size_t i = 0; i < state.fetchedLocationCount; ++i) {
			if (state.fetchedLocationHashes[i] == hash) {
				return false;
			}
		}
		if (state.fetchedLocationCount >= MaxSsdpDescriptionFetches) {
			return false;
		}
		state.fetchedLocationHashes[state.fetchedLocationCount++] = hash;
		return true;
	};
	size_t processedInterfaces = 0;
	for (; processedInterfaces < plannedInterfaces; ++processedInterfaces) {
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			break;
		}
		stats.workUnits++;
		const size_t interfaceIndex =
		    (state.interfaceCursor + processedInterfaces) % interfaceCount;
		const auto &interfaceInfo = interfaces[interfaceIndex];
		const uint32_t socketTimeout =
		    std::max<uint32_t>(1, providerRemainingMs(control, SocketPollMs));
		const int fd = openBoundUdpSocket(interfaceInfo.ipv4, socketTimeout);
		if (fd < 0) {
			stats.errors++;
			stats.transportErrors++;
			continue;
		}
		if (sendto(
		        fd,
		        Search,
		        sizeof(Search) - 1,
		        0,
		        reinterpret_cast<const sockaddr *>(&destination),
		        sizeof(destination)
		    ) < 0) {
			stats.errors++;
			stats.transportErrors++;
			close(fd);
			continue;
		}

		uint64_t deadline = providerNowMs() + config.responseWindowMs;
		if (control != nullptr && control->deadlineMs != UINT64_MAX) {
			deadline = std::min(deadline, control->deadlineMs);
		}
		while (providerNowMs() < deadline && !providerShouldStop(control)) {
			char response[2048] = {};
			sockaddr_in sender{};
			socklen_t senderLength = sizeof(sender);
			const int received = recvfrom(
			    fd,
			    response,
			    sizeof(response) - 1,
			    0,
			    reinterpret_cast<sockaddr *>(&sender),
			    &senderLength
			);
			if (received <= 0) {
				continue;
			}
			const ProviderTarget *target =
			    findTarget(targets, targetCount, sender.sin_addr.s_addr, interfaceInfo.key);
			if (target == nullptr) {
				continue;
			}

			SsdpResponseInfo parsed{};
			if (!parseSsdpResponse(response, static_cast<size_t>(received), parsed)) {
				stats.malformedResponses++;
				continue;
			}
			const uint64_t now = providerNowMs();
			const uint64_t expiresAt =
			    expiryFromTtl(now, parsed.maxAgeSeconds, config.fallbackMaxAgeMs);

			EnrichmentObservation observation{};
			observation.source = ScoutObservationSource::Ssdp;
			observation.ipv4 = target->ipv4;
			observation.interfaceIndex = target->interfaceIndex;
			copyText(
			    observation.interfaceKey,
			    sizeof(observation.interfaceKey),
			    target->interfaceKey
			);
			observation.identityExpiresAtMs = expiresAt;
			appendMetadata(
			    observation,
			    ScoutObservationSource::Ssdp,
			    "ssdp.usn",
			    parsed.usn,
			    now,
			    expiresAt
			);
			appendMetadata(
			    observation,
			    ScoutObservationSource::Ssdp,
			    "ssdp.server",
			    parsed.server,
			    now,
			    expiresAt
			);
			appendMetadata(
			    observation,
			    ScoutObservationSource::Ssdp,
			    "ssdp.st",
			    parsed.searchTarget,
			    now,
			    expiresAt
			);
			appendMetadata(
			    observation,
			    ScoutObservationSource::Ssdp,
			    "ssdp.location",
			    parsed.location,
			    now,
			    expiresAt
			);
			extractUpnpUdn(parsed.usn, observation.upnpUdn, sizeof(observation.upnpUdn));

			const size_t descriptionBudget =
			    std::min(MaxSsdpDescriptionFetches, config.maxDescriptionFetchesPerRun);
			const bool newDescriptionLocation =
			    parsed.location[0] != '\0' && rememberLocation(interfaceInfo.key, parsed.location);
			if (config.fetchDeviceDescription && newDescriptionLocation && httpScratch != nullptr &&
			    httpScratchCapacity > 1 && state.descriptionFetches < descriptionBudget) {
				const uint32_t httpTimeout = providerRemainingMs(control, config.httpTimeoutMs);
				if (httpTimeout == 0) {
					break;
				}
				const HttpFetchResult fetch = fetchHttpBody(
				    parsed.location,
				    *target,
				    targets,
				    targetCount,
				    httpTimeout,
				    httpScratch,
				    httpScratchCapacity,
				    control
				);
				state.descriptionFetches++;
				if (fetch.status == HttpFetchStatus::Ok && fetch.bodyLength > 0) {
					UpnpDescriptionInfo description{};
					if (parseUpnpDescription(httpScratch, fetch.bodyLength, description)) {
						addName(
						    observation,
						    ScoutNameSource::SsdpFriendlyName,
						    description.friendlyName,
						    now,
						    expiresAt
						);
						copyText(
						    observation.manufacturer,
						    sizeof(observation.manufacturer),
						    description.manufacturer
						);
						copyText(
						    observation.modelName,
						    sizeof(observation.modelName),
						    description.modelName
						);
						copyText(
						    observation.modelNumber,
						    sizeof(observation.modelNumber),
						    description.modelNumber
						);
						copyText(
						    observation.serialNumber,
						    sizeof(observation.serialNumber),
						    description.serialNumber
						);
						if (description.udn[0] != '\0') {
							if (observation.upnpUdn[0] == '\0') {
								copyText(
								    observation.upnpUdn,
								    sizeof(observation.upnpUdn),
								    description.udn
								);
							} else if (!textEqualsIgnoreCase(
							               observation.upnpUdn,
							               description.udn
							           )) {
								stats.identityConflicts++;
							}
						}
						appendMetadata(
						    observation,
						    ScoutObservationSource::Ssdp,
						    "upnp.deviceType",
						    description.deviceType,
						    now,
						    expiresAt
						);
					} else {
						stats.malformedResponses++;
						stats.descriptionErrors++;
					}
				} else {
					stats.descriptionErrors++;
					switch (fetch.status) {
					case HttpFetchStatus::Timeout:
						stats.timeouts++;
						break;
					case HttpFetchStatus::TooLarge:
					case HttpFetchStatus::UnsupportedAddress:
						stats.dropped++;
						break;
					case HttpFetchStatus::InvalidResponse:
					case HttpFetchStatus::UnsupportedEncoding:
						stats.malformedResponses++;
						break;
					case HttpFetchStatus::HttpError:
						stats.serverErrors++;
						break;
					case HttpFetchStatus::ResolverUnavailable:
						stats.resolverUnavailable++;
						break;
					case HttpFetchStatus::NetworkError:
						stats.errors++;
						stats.transportErrors++;
						break;
					case HttpFetchStatus::Ok:
						break;
					}
				}
			} else if (config.fetchDeviceDescription && newDescriptionLocation &&
			           state.descriptionFetches >= descriptionBudget) {
				stats.dropped++;
			}

			sink(target->mac, observation, context);
			stats.observations++;
		}
		close(fd);
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
	}
	state.interfaceCursor = (state.interfaceCursor + processedInterfaces) % interfaceCount;
	state.remainingInterfaces = processedInterfaces >= state.remainingInterfaces
	                                ? 0
	                                : state.remainingInterfaces - processedInterfaces;
	if (stats.cancelled) {
		state = {};
	} else if (!stats.budgetYielded && state.remainingInterfaces == 0) {
		state.active = false;
		state.descriptionFetches = 0;
		state.fetchedLocationCount = 0;
	}
	return stats;
}

ProviderRunStats runNbnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    NbnsProviderState &state,
    const ScoutNbnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		state = {};
		return stats;
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
		return stats;
	}

	InterfaceSnapshot interfaces[MaxInterfaces]{};
	size_t interfaceCount = 0;
	if (collectInterfaces(interfaces, MaxInterfaces, interfaceCount) != ESP_OK) {
		stats.errors++;
		state = {};
		return stats;
	}
	if (interfaceCount == 0) {
		state = {};
		return stats;
	}

	if (!state.active || state.targetLimit == 0 || state.runStartCursor >= targetCount ||
	    state.targetLimit > targetCount) {
		state.active = true;
		state.runStartCursor = state.targetCursor % targetCount;
		state.targetLimit = std::min(targetCount, config.maxTargetsPerRun);
		state.interfaceCursor = 0;
		state.batchOffset = 0;
	}
	stats.plannedUnits = state.targetLimit;

	while (state.interfaceCursor < interfaceCount) {
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			return stats;
		}
		const auto &interfaceInfo = interfaces[state.interfaceCursor];

		size_t batchIndices[NbnsBatchSize]{};
		size_t batchCount = 0;
		size_t nextOffset = state.batchOffset;
		while (nextOffset < state.targetLimit && batchCount < NbnsBatchSize) {
			const size_t targetIndex = (state.runStartCursor + nextOffset) % targetCount;
			nextOffset++;
			if (!targetMatchesInterface(targets[targetIndex], interfaceInfo.key)) {
				continue;
			}
			batchIndices[batchCount++] = targetIndex;
		}
		if (batchCount == 0) {
			state.interfaceCursor++;
			state.batchOffset = 0;
			continue;
		}

		const uint32_t socketTimeout =
		    std::max<uint32_t>(1, providerRemainingMs(control, SocketPollMs));
		const int fd = openBoundUdpSocket(interfaceInfo.ipv4, socketTimeout);
		if (fd < 0) {
			stats.errors++;
			stats.transportErrors++;
			state.batchOffset = nextOffset;
			continue;
		}

		bool sendInterrupted = false;
		for (size_t batchIndex = 0; batchIndex < batchCount; ++batchIndex) {
			if (providerShouldStop(control)) {
				recordProviderStop(stats, control);
				sendInterrupted = true;
				break;
			}
			const size_t targetIndex = batchIndices[batchIndex];
			uint8_t request[50]{};
			buildNbnsNodeStatusRequest(
			    request,
			    sizeof(request),
			    static_cast<uint16_t>(0x4000U + (targetIndex & 0x3FFFU))
			);
			sockaddr_in destination{};
			destination.sin_family = AF_INET;
			destination.sin_port = htons(137);
			destination.sin_addr.s_addr = targets[targetIndex].ipv4.value;
			stats.workUnits++;
			if (sendto(
			        fd,
			        request,
			        sizeof(request),
			        0,
			        reinterpret_cast<const sockaddr *>(&destination),
			        sizeof(destination)
			    ) < 0) {
				stats.errors++;
				stats.transportErrors++;
			}
		}
		if (sendInterrupted) {
			close(fd);
			return stats;
		}

		uint64_t responseDeadline = providerNowMs() + config.responseWindowMs;
		if (control != nullptr && control->deadlineMs != UINT64_MAX) {
			responseDeadline = std::min(responseDeadline, control->deadlineMs);
		}
		while (providerNowMs() < responseDeadline && !providerShouldStop(control)) {
			uint8_t response[1024]{};
			sockaddr_in sender{};
			socklen_t senderLength = sizeof(sender);
			const int received = recvfrom(
			    fd,
			    response,
			    sizeof(response),
			    0,
			    reinterpret_cast<sockaddr *>(&sender),
			    &senderLength
			);
			if (received <= 0) {
				continue;
			}
			const ProviderTarget *target =
			    findTarget(targets, targetCount, sender.sin_addr.s_addr, interfaceInfo.key);
			if (target == nullptr) {
				continue;
			}
			const size_t targetIndex = static_cast<size_t>(target - targets);
			bool belongsToBatch = false;
			for (size_t i = 0; i < batchCount; ++i) {
				if (batchIndices[i] == targetIndex) {
					belongsToBatch = true;
					break;
				}
			}
			if (!belongsToBatch) {
				continue;
			}
			char name[SCOUT_NAME_SIZE] = {};
			const uint16_t expectedTransactionId =
			    static_cast<uint16_t>(0x4000U + (targetIndex & 0x3FFFU));
			if (!parseNbnsNodeStatusName(
			        response,
			        static_cast<size_t>(received),
			        expectedTransactionId,
			        name,
			        sizeof(name)
			    )) {
				continue;
			}
			const uint64_t now = providerNowMs();
			EnrichmentObservation observation{};
			observation.source = ScoutObservationSource::Nbns;
			observation.ipv4 = target->ipv4;
			observation.interfaceIndex = target->interfaceIndex;
			copyText(
			    observation.interfaceKey,
			    sizeof(observation.interfaceKey),
			    target->interfaceKey
			);
			addName(observation, ScoutNameSource::Nbns, name, now, now + config.maxAgeMs);
			sink(target->mac, observation, context);
			stats.observations++;
		}
		close(fd);

		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			// Do not advance. The same bounded batch is retransmitted after a budget
			// yield so replies lost with the old socket cannot create permanent gaps.
			return stats;
		}

		state.batchOffset = nextOffset;
		if (state.batchOffset >= state.targetLimit) {
			state.interfaceCursor++;
			state.batchOffset = 0;
		}
	}

	state.targetCursor = (state.runStartCursor + state.targetLimit) % targetCount;
	state.runStartCursor = state.targetCursor;
	state.targetLimit = 0;
	state.interfaceCursor = 0;
	state.batchOffset = 0;
	state.active = false;
	return stats;
}

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutReverseDnsConfig &config,
    EnrichmentSink sink,
    void *context,
    const ProviderRunControl *control
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
		return stats;
	}

	const size_t limit = std::min({MaxProviderTargetsPerRun, config.maxTargetsPerRun, targetCount});
	stats.plannedUnits = limit;
	size_t processedCount = 0;
	for (; processedCount < limit; ++processedCount) {
		if (providerShouldStop(control)) {
			recordProviderStop(stats, control);
			break;
		}
		const size_t index = (cursor + processedCount) % targetCount;
		const auto &target = targets[index];
		const uint32_t timeoutMs = providerRemainingMs(control, config.timeoutMs);
		if (timeoutMs == 0) {
			recordProviderStop(stats, control);
			break;
		}
		stats.workUnits++;
		const DnsPtrAnswer answer = queryPtr(target, timeoutMs, control);

		switch (answer.status) {
		case DnsParseStatus::Ok: {
			const uint64_t now = providerNowMs();
			EnrichmentObservation observation{};
			observation.source = ScoutObservationSource::ReverseDns;
			observation.ipv4 = target.ipv4;
			observation.interfaceIndex = target.interfaceIndex;
			copyText(
			    observation.interfaceKey,
			    sizeof(observation.interfaceKey),
			    target.interfaceKey
			);
			const uint64_t expiresAt = expiryFromTtl(now, answer.ttlSeconds, config.maxAgeMs);
			addName(observation, ScoutNameSource::ReverseDns, answer.hostname, now, expiresAt);
			sink(target.mac, observation, context);
			stats.observations++;
			break;
		}
		case DnsParseStatus::NoRecord:
			stats.noRecords++;
			break;
		case DnsParseStatus::Timeout:
			stats.timeouts++;
			break;
		case DnsParseStatus::Malformed:
			stats.malformedResponses++;
			break;
		case DnsParseStatus::ServerError:
			stats.serverErrors++;
			break;
		case DnsParseStatus::ResolverUnavailable:
			stats.resolverUnavailable++;
			break;
		case DnsParseStatus::NetworkError:
			stats.errors++;
			stats.transportErrors++;
			break;
		}
	}
	if (providerShouldStop(control)) {
		recordProviderStop(stats, control);
	}
	cursor = (cursor + processedCount) % targetCount;
	return stats;
}

} // namespace scout_internal
