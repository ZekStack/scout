#include "ScoutProviders.h"

#include "ScoutEnrichment.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>

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
constexpr size_t MaxMdnsServiceTypes = 32;
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

esp_err_t collectLocalInterfacesTcpip(void *rawContext) {
	auto *context = static_cast<LocalInterfaceCollectContext *>(rawContext);
	if (context == nullptr || context->out == nullptr || context->capacity == 0) {
		return ESP_ERR_INVALID_ARG;
	}

	context->count = 0;
	esp_netif_t *netif = nullptr;
	while ((netif = esp_netif_next_unsafe(netif)) != nullptr &&
	    context->count < context->capacity) {
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
	if (interfaceKey == nullptr || interfaceKey[0] == '\0' || target.interfaceKey[0] == '\0') {
		return true;
	}
	return textEqualsIgnoreCase(target.interfaceKey, interfaceKey);
}

const ProviderTarget *findTarget(
    const ProviderTarget *targets, size_t targetCount, uint32_t ipv4, const char *interfaceKey
) {
	if (targets == nullptr || ipv4 == 0) {
		return nullptr;
	}
	const ProviderTarget *fallback = nullptr;
	for (size_t i = 0; i < targetCount; ++i) {
		if (targets[i].ipv4.value != ipv4) {
			continue;
		}
		if (fallback == nullptr) {
			fallback = &targets[i];
		}
		if (targetMatchesInterface(targets[i], interfaceKey)) {
			return &targets[i];
		}
	}
	return fallback;
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

void appendMetadata(
    EnrichmentObservation &observation,
    ScoutObservationSource source,
    const char *key,
    const char *value,
    uint64_t now,
    uint64_t expiresAt
) {
	if (key == nullptr || key[0] == '\0' ||
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

void maybeSetPersistentField(
    EnrichmentObservation &observation, const char *key, const char *value
) {
	if (key == nullptr || value == nullptr || value[0] == '\0') {
		return;
	}
	if (textEqualsIgnoreCase(key, "deviceid") || textEqualsIgnoreCase(key, "device_id")) {
		copyText(observation.persistentDeviceId, sizeof(observation.persistentDeviceId), value);
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
    EnrichmentSink sink,
    void *context,
    ProviderRunStats &stats
) {
	const uint64_t now = providerNowMs();
	const uint64_t expiresAt = expiryFromTtl(now, result.ttl, config.fallbackMaxAgeMs);
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
			maybeSetPersistentField(observation, metadata.key, metadata.value);
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

size_t fetchHttpBody(const char *url, uint32_t timeoutMs, char *scratch, size_t capacity) {
	if (scratch == nullptr || capacity < 2) {
		return 0;
	}
	ParsedHttpUrl parsed{};
	if (!parseHttpUrl(url, parsed)) {
		return 0;
	}

	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	char portText[8] = {};
	std::snprintf(portText, sizeof(portText), "%u", static_cast<unsigned>(parsed.port));
	addrinfo *resolved = nullptr;
	if (getaddrinfo(parsed.host, portText, &hints, &resolved) != 0 || resolved == nullptr) {
		return 0;
	}

	const int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		freeaddrinfo(resolved);
		return 0;
	}
	setSocketTimeout(fd, timeoutMs);
	if (connect(fd, resolved->ai_addr, resolved->ai_addrlen) != 0) {
		close(fd);
		freeaddrinfo(resolved);
		return 0;
	}
	freeaddrinfo(resolved);

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
	if (requestLength <= 0 || static_cast<size_t>(requestLength) >= sizeof(request) ||
	    send(fd, request, static_cast<size_t>(requestLength), 0) < 0) {
		close(fd);
		return 0;
	}

	size_t received = 0;
	while (received + 1 < capacity) {
		const int count = recv(fd, scratch + received, capacity - received - 1, 0);
		if (count <= 0) {
			break;
		}
		received += static_cast<size_t>(count);
	}
	close(fd);
	scratch[received] = '\0';

	char *body = std::strstr(scratch, "\r\n\r\n");
	if (body == nullptr) {
		return 0;
	}
	body += 4;
	const size_t headerLength = static_cast<size_t>(body - scratch);
	const size_t bodyLength = received >= headerLength ? received - headerLength : 0;
	std::memmove(scratch, body, bodyLength);
	scratch[bodyLength] = '\0';
	return bodyLength;
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
		addServiceType(types, typeCount, MaxMdnsServiceTypes, service.service, service.proto);
	}

	mdns_result_t *serviceTypes = nullptr;
	const uint32_t enumerationTimeout = std::max<uint32_t>(100, config.queryTimeoutMs / 4U);
	if (mdns_query_ptr(
	        "_services._dns-sd",
	        "_udp",
	        enumerationTimeout,
	        std::min(config.maxServiceTypes, MaxMdnsServiceTypes),
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
				if (!addServiceType(types, typeCount, MaxMdnsServiceTypes, service, proto) &&
				    typeCount >= MaxMdnsServiceTypes) {
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
	const uint32_t perQueryTimeout = std::max<uint32_t>(
	    20,
	    queryCount > 0 ? queryBudget / static_cast<uint32_t>(queryCount) : 20
	);

	for (size_t i = 0; i < queryCount; ++i) {
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
			emitMdnsResult(*result, targets, targetCount, config, sink, context, stats);
		}
		mdns_query_results_free(results);
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
	for (size_t interfaceIndex = 0; interfaceIndex < interfaceCount; ++interfaceIndex) {
		const auto &interfaceInfo = interfaces[interfaceIndex];
		const int fd = openBoundUdpSocket(interfaceInfo.ipv4, SocketPollMs);
		if (fd < 0) {
			stats.errors++;
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
				stats.errors++;
				continue;
			}
			const uint64_t now = providerNowMs();
			const uint64_t expiresAt =
			    expiryFromTtl(now, parsed.maxAgeSeconds, config.fallbackMaxAgeMs);

			EnrichmentObservation observation{};
			observation.source = ScoutObservationSource::Ssdp;
			observation.ipv4 = target->ipv4;
			observation.interfaceIndex = target->interfaceIndex;
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

			if (config.fetchDeviceDescription && parsed.location[0] != '\0' &&
			    httpScratch != nullptr && httpScratchCapacity > 1 &&
			    descriptionFetches <
			        std::min(MaxSsdpDescriptionFetches, config.maxDescriptionFetchesPerRun)) {
				const size_t bodyLength = fetchHttpBody(
				    parsed.location,
				    config.httpTimeoutMs,
				    httpScratch,
				    httpScratchCapacity
				);
				descriptionFetches++;
				if (bodyLength > 0) {
					UpnpDescriptionInfo description{};
					if (parseUpnpDescription(httpScratch, bodyLength, description)) {
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
					}
				} else {
					stats.timeouts++;
				}
			} else if (descriptionFetches >=
			           std::min(MaxSsdpDescriptionFetches, config.maxDescriptionFetchesPerRun)) {
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
		for (size_t i = 0; i < targetLimit; ++i) {
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
			if (!parseNbnsNodeStatusName(
			        response,
			        static_cast<size_t>(received),
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
			addName(observation, ScoutNameSource::Nbns, name, now, now + config.maxAgeMs);
			sink(target->mac, observation, context);
			stats.observations++;
		}
		close(fd);
	}
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
#if defined(NI_NAMEREQD)
	(void)config.timeoutMs;
	for (size_t processed = 0; processed < limit; ++processed) {
		const size_t index = (cursor + processed) % targetCount;
		const auto &target = targets[index];
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = target.ipv4.value;
		char hostname[SCOUT_NAME_SIZE] = {};
		if (getnameinfo(
		        reinterpret_cast<const sockaddr *>(&address),
		        sizeof(address),
		        hostname,
		        sizeof(hostname),
		        nullptr,
		        0,
		        NI_NAMEREQD
		    ) != 0) {
			stats.timeouts++;
			continue;
		}
		const uint64_t now = providerNowMs();
		EnrichmentObservation observation{};
		observation.source = ScoutObservationSource::ReverseDns;
		observation.ipv4 = target.ipv4;
		observation.interfaceIndex = target.interfaceIndex;
		addName(observation, ScoutNameSource::ReverseDns, hostname, now, now + config.maxAgeMs);
		sink(target.mac, observation, context);
		stats.observations++;
	}
#else
	(void)config;
	stats.errors += limit;
#endif
	cursor = (cursor + limit) % targetCount;
	return stats;
}

} // namespace scout_internal
