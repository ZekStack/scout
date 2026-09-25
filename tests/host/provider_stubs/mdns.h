#pragma once
#include <cstddef>
#include <cstdint>

#include <esp_netif.h>

inline constexpr int MDNS_IP_PROTOCOL_V4 = 4;
inline constexpr int MDNS_IP_PROTOCOL_V6 = 6;

struct mdns_addr_value_t {
	int type = MDNS_IP_PROTOCOL_V4;
	union {
		struct {
			uint32_t addr;
		} ip4;
		struct {
			uint8_t addr[16];
		} ip6;
	} u_addr{};
};

struct mdns_ip_addr_t {
	mdns_addr_value_t addr{};
	mdns_ip_addr_t *next = nullptr;
};

struct mdns_txt_item_t {
	const char *key = nullptr;
	const char *value = nullptr;
};

struct mdns_result_t {
	mdns_result_t *next = nullptr;
	esp_netif_t *esp_netif = nullptr;
	mdns_ip_addr_t *addr = nullptr;
	const char *hostname = nullptr;
	const char *instance_name = nullptr;
	const char *service_type = nullptr;
	const char *proto = nullptr;
	uint16_t port = 0;
	uint32_t ttl = 0;
	size_t txt_count = 0;
	mdns_txt_item_t *txt = nullptr;
	size_t *txt_value_len = nullptr;
};

esp_err_t mdns_init();
esp_err_t mdns_query_ptr(
    const char *service,
    const char *proto,
    uint32_t timeoutMs,
    size_t maxResults,
    mdns_result_t **results
);
void mdns_query_results_free(mdns_result_t *results);
