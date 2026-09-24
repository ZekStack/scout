#include "ScoutProviders.h"

#include "ScoutDns.h"
#include "ScoutEnrichment.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <strings.h>

#include <esp_netif.h>
#include <esp_netif_net_stack.h>
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

constexpr size_t MaxLocalInterfaces = 8;
constexpr size_t MaxMdnsServiceTypes = 64;
constexpr size_t MaxProviderTargetsPerRun = 32;
constexpr size_t MaxSsdpDescriptionFetches = 16;
constexpr uint32_t SocketPollMs = 50;

struct LocalInterface {
	uint32_t ipv4 = 0;
	uint32_t netmask = 0;
	char key[SCOUT_INTERFACE_KEY_SIZE] = {};
};

struct LocalInterfaceCollectContext {
	LocalInterface *out = nullptr;
	size_t capacity = 0;
	size_t count = 0;
};

struct MdnsServiceType {
	char service[SCOUT_SERVICE_TYPE_SIZE] = {};
	char proto[SCOUT_SERVICE_PROTO_SIZE] = {};
};

uint64_t providerNowMs() {
	return static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
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

esp_err_t collectLocalInterfacesTcpip(void *rawContext) {
	auto *context = static_cast<LocalInterfaceCollectContext *>(rawContext);
	if (context == nullptr || context->out == nullptr || context->capacity == 0) {
		return ESP_ERR_INVALID_ARG;
	}

	context->count = 0;
	esp_netif_t *netif = nullptr;
	while ((netif = esp_netif_next_unsafe(netif)) != nullptr && context->count < context->capacity
	) {
		esp_netif_ip_info_t info{};
		if (esp_netif_get_ip_info(netif, &info) != ESP_OK || info.ip.addr == 0 ||
		    info.netmask.addr == 0) {
			continue;
		}
		auto &item = context->out[context->count++];
		item = {};
		item.ipv4 = info.ip.addr;
		item.netmask = info.netmask.addr;
		const char *key = esp_netif_get_ifkey(netif);
		copyText(item.key, sizeof(item.key), key != nullptr ? key : "");
	}
	return ESP_OK;
}

size_t collectLocalInterfaces(LocalInterface *out, size_t capacity) {
	if (out == nullptr || capacity == 0) {
		return 0;
	}
	LocalInterfaceCollectContext context{
	    .out = out,
	    .capacity = capacity,
	};
	if (esp_netif_tcpip_exec(collectLocalInterfacesTcpip, &context) != ESP_OK) {
		return 0;
	}
	return context.count;
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
			if (targets[i].ipv4.value == ipv4 &&
			    targetMatchesInterface(targets[i], interfaceKey)) {
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
	setSocketTimeout(fd, timeoutMs);

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

DnsPtrAnswer queryPtr(const ProviderTarget &target, uint32_t timeoutMs) {
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

	esp_netif_dns_info_t dnsInfo{};
	esp_err_t dnsResult = esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dnsInfo);
	if (dnsResult != ESP_OK || !IP_IS_V4_VAL(dnsInfo.ip) ||
	    ip4_addr_isany_val(*ip_2_ip4(&dnsInfo.ip))) {
		dnsInfo = {};
		dnsResult = esp_netif_get_dns_info(netif, ESP_NETIF_DNS_BACKUP, &dnsInfo);
	}
	if (dnsResult != ESP_OK || !IP_IS_V4_VAL(dnsInfo.ip) ||
	    ip4_addr_isany_val(*ip_2_ip4(&dnsInfo.ip))) {
		result.status = DnsParseStatus::NetworkError;
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
	destination.sin_addr.s_addr = ip_2_ip4(&dnsInfo.ip)->addr;

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
};

struct HttpFetchResult {
	HttpFetchStatus status = HttpFetchStatus::InvalidResponse;
	size_t bodyLength = 0;
};

bool parseHttpUrl(const char *url, ParsedHttpUrl &out) {
	out = {};
	copyText(out.path, sizeof(out.path), "/");
	if (url == nullptr || std::strncmp(url, "http://", 7) != 0) {
		return false;
	}
	const char *hostStart = url + 7;
	const char *pathStart = std::strchr(hostStart, '/');
	const char *hostEnd = pathStart != nullptr ? pathStart : hostStart + std::strlen(hostStart);
	const char *colon = nullptr;
	for (const char *cursor = hostStart; cursor < hostEnd; ++cursor) {
		if (*cursor == ':') {
			colon = cursor;
			break;
		}
	}
	if (colon != nullptr) {
		copyTextN(out.host, sizeof(out.host), hostStart, static_cast<size_t>(colon - hostStart));
		unsigned port = 0;
		for (const char *cursor = colon + 1; cursor < hostEnd; ++cursor) {
			if (*cursor < '0' || *cursor > '9') {
				return false;
			}
			port = port * 10U + static_cast<unsigned>(*cursor - '0');
		}
		if (port == 0 || port > 65535U) {
			return false;
		}
		out.port = static_cast<uint16_t>(port);
	} else {
		copyTextN(out.host, sizeof(out.host), hostStart, static_cast<size_t>(hostEnd - hostStart));
	}
	if (pathStart != nullptr) {
		copyText(out.path, sizeof(out.path), pathStart);
	}
	return out.host[0] != '\0';
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
    const char *url, uint32_t localIpv4, uint32_t timeoutMs, char *scratch, size_t capacity
) {
	HttpFetchResult result{};
	if (scratch == nullptr || capacity < 2 || timeoutMs == 0) {
		return result;
	}
	ParsedHttpUrl parsed{};
	if (!parseHttpUrl(url, parsed)) {
		return result;
	}

	sockaddr_in remote{};
	remote.sin_family = AF_INET;
	remote.sin_port = htons(parsed.port);
	if (inet_pton(AF_INET, parsed.host, &remote.sin_addr) != 1) {
		result.status = HttpFetchStatus::UnsupportedAddress;
		return result;
	}

	const uint64_t deadlineMs = providerNowMs() + timeoutMs;
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
	local.sin_addr.s_addr = localIpv4;
	if (localIpv4 == 0 ||
	    bind(fd, reinterpret_cast<const sockaddr *>(&local), sizeof(local)) != 0) {
		close(fd);
		result.status = HttpFetchStatus::NetworkError;
		return result;
	}

	if (connect(fd, reinterpret_cast<const sockaddr *>(&remote), sizeof(remote)) != 0) {
		if (errno != EINPROGRESS && errno != EAGAIN && errno != EWOULDBLOCK) {
			const int socketError = errno;
			close(fd);
			result.status = socketError == ETIMEDOUT ? HttpFetchStatus::Timeout
			                                           : HttpFetchStatus::NetworkError;
			return result;
		}
		const auto ready = waitSocketReady(fd, true, deadlineMs);
		if (ready != SocketIoStatus::Ok) {
			close(fd);
			result.status = ready == SocketIoStatus::Timeout ? HttpFetchStatus::Timeout
			                                                 : HttpFetchStatus::NetworkError;
			return result;
		}
		int socketError = 0;
		socklen_t socketErrorLength = sizeof(socketError);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength) != 0 ||
		    socketError != 0) {
			close(fd);
			result.status = socketError == ETIMEDOUT ? HttpFetchStatus::Timeout
			                                           : HttpFetchStatus::NetworkError;
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
	const auto sendStatus =
	    sendAll(fd, request, static_cast<size_t>(requestLength), deadlineMs);
	if (sendStatus != SocketIoStatus::Ok) {
		close(fd);
		result.status = sendStatus == SocketIoStatus::Timeout ? HttpFetchStatus::Timeout
		                                                   : HttpFetchStatus::NetworkError;
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
    void *context
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}
#if SCOUT_HAS_PING
	const size_t limit = std::min({MaxProviderTargetsPerRun, config.maxTargetsPerRun, targetCount});
	for (size_t processed = 0; processed < limit; ++processed) {
		const size_t index = (cursor + processed) % targetCount;
		const auto &target = targets[index];

		PingContext pingContext{};
		esp_ping_config_t pingConfig = ESP_PING_DEFAULT_CONFIG();
		pingConfig.count = 1;
		pingConfig.interval_ms = 0;
		pingConfig.timeout_ms = config.timeoutMs;
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

		const uint64_t deadline = providerNowMs() + config.timeoutMs + 250U;
		while (!pingContext.done.load(std::memory_order_acquire) && providerNowMs() < deadline) {
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
	cursor = (cursor + limit) % targetCount;
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
    size_t &serviceCursor,
    const ScoutMdnsConfig &config,
    EnrichmentSink sink,
    void *context
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
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

	MdnsServiceType types[MaxMdnsServiceTypes]{};
	size_t typeCount = 0;
	const size_t serviceTypeCapacity = std::min(config.maxServiceTypes, MaxMdnsServiceTypes);
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
		addServiceType(types, typeCount, serviceTypeCapacity, service.service, service.proto);
	}

	mdns_result_t *serviceTypes = nullptr;
	const uint32_t enumerationTimeout = std::max<uint32_t>(100, config.queryTimeoutMs / 4U);
	if (mdns_query_ptr(
	        "_services._dns-sd",
	        "_udp",
	        enumerationTimeout,
	        serviceTypeCapacity,
	        &serviceTypes
	    ) == ESP_OK) {
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
				if (!addServiceType(types, typeCount, serviceTypeCapacity, service, proto) &&
				    typeCount >= serviceTypeCapacity) {
					stats.dropped++;
				}
			}
		}
		mdns_query_results_free(serviceTypes);
	}

	const uint32_t queryBudget = config.queryTimeoutMs > enumerationTimeout
	                                 ? config.queryTimeoutMs - enumerationTimeout
	                                 : config.queryTimeoutMs;
	const size_t queryCount = std::min(typeCount, config.maxServiceQueriesPerRun);
	const uint64_t retentionFloorMs = mdnsRetentionFloorMs(config, typeCount, queryCount);
	const uint32_t perQueryTimeout = std::max<uint32_t>(
	    20,
	    queryCount > 0 ? queryBudget / static_cast<uint32_t>(queryCount) : 20
	);

	for (size_t processed = 0; processed < queryCount; ++processed) {
		const size_t i = typeCount > 0 ? (serviceCursor + processed) % typeCount : 0;
		mdns_result_t *results = nullptr;
		const esp_err_t queryResult = mdns_query_ptr(
		    types[i].service,
		    types[i].proto,
		    perQueryTimeout,
		    config.maxResults,
		    &results
		);
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
	if (typeCount > 0) {
		serviceCursor = (serviceCursor + queryCount) % typeCount;
	}
#else
	(void)config;
	(void)context;
	stats.errors = 1;
#endif
	return stats;
}

ProviderRunStats runSsdpProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    const ScoutSsdpConfig &config,
    char *httpScratch,
    size_t httpScratchCapacity,
    EnrichmentSink sink,
    void *context
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}

	LocalInterface interfaces[MaxLocalInterfaces]{};
	const size_t interfaceCount = collectLocalInterfaces(interfaces, MaxLocalInterfaces);
	constexpr char Search[] = "M-SEARCH * HTTP/1.1\r\n"
	                          "HOST: 239.255.255.250:1900\r\n"
	                          "MAN: \"ssdp:discover\"\r\n"
	                          "MX: 1\r\n"
	                          "ST: ssdp:all\r\n\r\n";
	sockaddr_in destination{};
	destination.sin_family = AF_INET;
	destination.sin_port = htons(1900);
	inet_pton(AF_INET, "239.255.255.250", &destination.sin_addr);

	size_t descriptionFetches = 0;
	char fetchedLocations[MaxSsdpDescriptionFetches][256]{};
	char fetchedLocationInterfaces[MaxSsdpDescriptionFetches][SCOUT_INTERFACE_KEY_SIZE]{};
	size_t fetchedLocationCount = 0;
	auto rememberLocation = [&](const char *interfaceKey, const char *location) {
		if (location == nullptr || location[0] == '\0') {
			return false;
		}
		for (size_t i = 0; i < fetchedLocationCount; ++i) {
			if (textEqualsIgnoreCase(fetchedLocations[i], location) &&
			    textEqualsIgnoreCase(fetchedLocationInterfaces[i], interfaceKey)) {
				return false;
			}
		}
		if (fetchedLocationCount >= MaxSsdpDescriptionFetches) {
			return false;
		}
		copyText(
		    fetchedLocations[fetchedLocationCount],
		    sizeof(fetchedLocations[fetchedLocationCount]),
		    location
		);
		copyText(
		    fetchedLocationInterfaces[fetchedLocationCount],
		    sizeof(fetchedLocationInterfaces[fetchedLocationCount]),
		    interfaceKey
		);
		fetchedLocationCount++;
		return true;
	};
	for (size_t interfaceIndex = 0; interfaceIndex < interfaceCount; ++interfaceIndex) {
		const auto &interfaceInfo = interfaces[interfaceIndex];
		const int fd = openBoundUdpSocket(interfaceInfo.ipv4, SocketPollMs);
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

		const uint64_t deadline = providerNowMs() + config.responseWindowMs;
		while (providerNowMs() < deadline) {
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
			    httpScratchCapacity > 1 && descriptionFetches < descriptionBudget) {
				const HttpFetchResult fetch = fetchHttpBody(
				    parsed.location,
				    interfaceInfo.ipv4,
				    config.httpTimeoutMs,
				    httpScratch,
				    httpScratchCapacity
				);
				descriptionFetches++;
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
							copyText(
							    observation.upnpUdn,
							    sizeof(observation.upnpUdn),
							    description.udn
							);
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
					case HttpFetchStatus::NetworkError:
						stats.errors++;
						stats.transportErrors++;
						break;
					case HttpFetchStatus::Ok:
						break;
					}
				}
			} else if (config.fetchDeviceDescription && newDescriptionLocation &&
			           descriptionFetches >= descriptionBudget) {
				stats.dropped++;
			}

			sink(target->mac, observation, context);
			stats.observations++;
		}
		close(fd);
	}
	return stats;
}

ProviderRunStats runNbnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutNbnsConfig &config,
    EnrichmentSink sink,
    void *context
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}

	LocalInterface interfaces[MaxLocalInterfaces]{};
	const size_t interfaceCount = collectLocalInterfaces(interfaces, MaxLocalInterfaces);
	for (size_t interfaceIndex = 0; interfaceIndex < interfaceCount; ++interfaceIndex) {
		const auto &interfaceInfo = interfaces[interfaceIndex];
		const int fd = openBoundUdpSocket(interfaceInfo.ipv4, SocketPollMs);
		if (fd < 0) {
			stats.errors++;
			continue;
		}

		const size_t targetLimit = std::min(targetCount, config.maxTargetsPerRun);
		for (size_t processed = 0; processed < targetLimit; ++processed) {
			const size_t i = (cursor + processed) % targetCount;
			if (!targetMatchesInterface(targets[i], interfaceInfo.key)) {
				continue;
			}
			uint8_t request[50]{};
			buildNbnsNodeStatusRequest(
			    request,
			    sizeof(request),
			    static_cast<uint16_t>(0x4000U + (i & 0x3FFFU))
			);
			sockaddr_in destination{};
			destination.sin_family = AF_INET;
			destination.sin_port = htons(137);
			destination.sin_addr.s_addr = targets[i].ipv4.value;
			if (sendto(
			        fd,
			        request,
			        sizeof(request),
			        0,
			        reinterpret_cast<const sockaddr *>(&destination),
			        sizeof(destination)
			    ) < 0) {
				stats.errors++;
			}
		}

		const uint64_t deadline = providerNowMs() + config.responseWindowMs;
		while (providerNowMs() < deadline) {
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
			char name[SCOUT_NAME_SIZE] = {};
			const size_t targetIndex = static_cast<size_t>(target - targets);
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
	}
	cursor = (cursor + std::min(targetCount, config.maxTargetsPerRun)) % targetCount;
	return stats;
}

ProviderRunStats runReverseDnsProvider(
    const ProviderTarget *targets,
    size_t targetCount,
    size_t &cursor,
    const ScoutReverseDnsConfig &config,
    EnrichmentSink sink,
    void *context
) {
	ProviderRunStats stats{};
	if (!config.enabled || targets == nullptr || targetCount == 0 || sink == nullptr) {
		return stats;
	}

	const size_t limit = std::min({MaxProviderTargetsPerRun, config.maxTargetsPerRun, targetCount});
	for (size_t processed = 0; processed < limit; ++processed) {
		const size_t index = (cursor + processed) % targetCount;
		const auto &target = targets[index];
		const DnsPtrAnswer answer = queryPtr(target, config.timeoutMs);

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
		case DnsParseStatus::NetworkError:
			stats.errors++;
			break;
		}
	}
	cursor = (cursor + limit) % targetCount;
	return stats;
}

} // namespace scout_internal
