#pragma once
#include <cstdint>

#include <esp_err.h>

struct ip4_addr_t {
	uint32_t addr = 0;
};

struct ip_addr_t {
	int type = 4;
	ip4_addr_t ip4{};
};

inline bool IP_IS_V4_VAL(const ip_addr_t &address) {
	return address.type == 4;
}

inline ip4_addr_t *ip_2_ip4(ip_addr_t *address) {
	return &address->ip4;
}

inline const ip4_addr_t *ip_2_ip4(const ip_addr_t *address) {
	return &address->ip4;
}

inline bool ip4_addr_isany_val(const ip4_addr_t &address) {
	return address.addr == 0;
}

constexpr uint8_t ESP_IPADDR_TYPE_V4 = 0;

struct esp_ip4_addr_t {
	uint32_t addr = 0;
};

struct esp_ip_addr_t {
	union {
		esp_ip4_addr_t ip4;
	} u_addr{};
	uint8_t type = ESP_IPADDR_TYPE_V4;
};

struct esp_netif_t {
	const char *key = nullptr;
	uint32_t ipv4 = 0;
	uint32_t dns = 0;
	bool isDefault = false;
};

struct esp_netif_ip_info_t {
	ip4_addr_t ip{};
	ip4_addr_t netmask{};
	ip4_addr_t gw{};
};

struct esp_netif_dns_info_t {
	esp_ip_addr_t ip{};
};

enum esp_netif_dns_type_t {
	ESP_NETIF_DNS_MAIN,
	ESP_NETIF_DNS_BACKUP,
};

esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key);
esp_err_t esp_netif_get_ip_info(esp_netif_t *netif, esp_netif_ip_info_t *info);
esp_err_t
esp_netif_get_dns_info(esp_netif_t *netif, esp_netif_dns_type_t type, esp_netif_dns_info_t *info);
esp_netif_t *esp_netif_get_default_netif();
const char *esp_netif_get_ifkey(esp_netif_t *netif);
