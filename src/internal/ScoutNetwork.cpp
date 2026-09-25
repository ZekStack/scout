#include "ScoutNetwork.h"

#include <algorithm>
#include <cstring>

#include <esp_netif.h>
#include <esp_netif_net_stack.h>

extern "C" {
#include <lwip/etharp.h>
#include <lwip/netif.h>
}

namespace scout_internal {
namespace {

struct CollectContext {
	InterfaceSnapshot *out = nullptr;
	size_t capacity = 0;
	size_t count = 0;
	bool truncated = false;
};

struct LookupContext {
	uint8_t interfaceIndex = 0;
	const uint32_t *ipv4Addresses = nullptr;
	size_t count = 0;
	ArpMapping *out = nullptr;
};

struct RequestContext {
	uint8_t interfaceIndex = 0;
	const uint32_t *ipv4Addresses = nullptr;
	size_t count = 0;
	ArpRequestStats stats{};
};

struct netif *findNetif(uint8_t index) {
	if (index == NETIF_NO_INDEX) {
		return nullptr;
	}
	return netif_get_by_index(index);
}

ScoutInterfaceType classifyInterface(const char *key) {
	if (key == nullptr) {
		return ScoutInterfaceType::Unknown;
	}
	if (std::strstr(key, "WIFI_STA") != nullptr) {
		return ScoutInterfaceType::WifiStation;
	}
	if (std::strstr(key, "WIFI_AP") != nullptr) {
		return ScoutInterfaceType::WifiAccessPoint;
	}
	if (std::strstr(key, "ETH") != nullptr) {
		return ScoutInterfaceType::Ethernet;
	}
	return ScoutInterfaceType::Custom;
}

bool isEligible(struct netif *netif) {
	if (netif == nullptr) {
		return false;
	}
	if (!netif_is_up(netif) || !netif_is_link_up(netif)) {
		return false;
	}
	if ((netif->flags & NETIF_FLAG_ETHARP) == 0) {
		return false;
	}
	if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
		return false;
	}
	if (ip4_addr_isany_val(*netif_ip4_netmask(netif))) {
		return false;
	}
	return true;
}

esp_err_t collectInterfacesTcpip(void *rawContext) {
	auto *context = static_cast<CollectContext *>(rawContext);
	if (context == nullptr || context->out == nullptr || context->capacity == 0) {
		return ESP_ERR_INVALID_ARG;
	}

	context->count = 0;
	esp_netif_t *espNetif = nullptr;
	while ((espNetif = esp_netif_next_unsafe(espNetif)) != nullptr) {
		auto *lwipNetif = static_cast<struct netif *>(esp_netif_get_netif_impl(espNetif));
		if (!isEligible(lwipNetif)) {
			continue;
		}
		if (context->count >= context->capacity) {
			context->truncated = true;
			break;
		}

		auto &snapshot = context->out[context->count++];
		snapshot = {};
		snapshot.index = netif_get_index(lwipNetif);
		snapshot.ipv4 = netif_ip4_addr(lwipNetif)->addr;
		snapshot.netmask = netif_ip4_netmask(lwipNetif)->addr;

		const char *key = esp_netif_get_ifkey(espNetif);
		if (key != nullptr) {
			std::strncpy(snapshot.key, key, sizeof(snapshot.key) - 1);
			snapshot.key[sizeof(snapshot.key) - 1] = '\0';
		}
		snapshot.type = classifyInterface(key);

		char name[NETIF_NAMESIZE] = {0};
		if (netif_index_to_name(snapshot.index, name) != nullptr) {
			std::strncpy(snapshot.name, name, sizeof(snapshot.name) - 1);
			snapshot.name[sizeof(snapshot.name) - 1] = '\0';
		}
	}

	return ESP_OK;
}

esp_err_t lookupArpTcpip(void *rawContext) {
	auto *context = static_cast<LookupContext *>(rawContext);
	if (context == nullptr || context->ipv4Addresses == nullptr || context->out == nullptr) {
		return ESP_ERR_INVALID_ARG;
	}

	auto *lwipNetif = findNetif(context->interfaceIndex);
	if (!isEligible(lwipNetif)) {
		return ESP_ERR_NOT_FOUND;
	}

	for (size_t i = 0; i < context->count; ++i) {
		context->out[i] = {};

		ip4_addr_t address{};
		address.addr = context->ipv4Addresses[i];

		struct eth_addr *ethernetAddress = nullptr;
		const ip4_addr_t *cachedAddress = nullptr;
		if (etharp_find_addr(lwipNetif, &address, &ethernetAddress, &cachedAddress) < 0 ||
		    ethernetAddress == nullptr) {
			continue;
		}

		context->out[i].found = true;
		std::memcpy(context->out[i].mac, ethernetAddress->addr, sizeof(context->out[i].mac));
	}

	return ESP_OK;
}

esp_err_t requestArpTcpip(void *rawContext) {
	auto *context = static_cast<RequestContext *>(rawContext);
	if (context == nullptr || context->ipv4Addresses == nullptr) {
		return ESP_ERR_INVALID_ARG;
	}

	auto *lwipNetif = findNetif(context->interfaceIndex);
	if (!isEligible(lwipNetif)) {
		return ESP_ERR_NOT_FOUND;
	}

	context->stats = {};
	for (size_t i = 0; i < context->count; ++i) {
		ip4_addr_t address{};
		address.addr = context->ipv4Addresses[i];

		if (etharp_request(lwipNetif, &address) == ERR_OK) {
			context->stats.sent++;
		} else {
			context->stats.failed++;
		}
	}

	return ESP_OK;
}

} // namespace

esp_err_t collectInterfaces(
    InterfaceSnapshot *out, size_t capacity, size_t &count, bool *truncated
) {
	CollectContext context{
	    .out = out,
	    .capacity = capacity,
	};

	const esp_err_t result = esp_netif_tcpip_exec(&collectInterfacesTcpip, &context);
	count = result == ESP_OK ? context.count : 0;
	if (truncated != nullptr) {
		*truncated = result == ESP_OK && context.truncated;
	}
	if (result == ESP_OK && out != nullptr && count > 1) {
		std::sort(out, out + count, [](const InterfaceSnapshot &left, const InterfaceSnapshot &right) {
			const int keyOrder = std::strcmp(left.key, right.key);
			if (keyOrder != 0) {
				return keyOrder < 0;
			}
			if (left.ipv4 != right.ipv4) {
				return left.ipv4 < right.ipv4;
			}
			return left.index < right.index;
		});
	}
	return result;
}

esp_err_t lookupArpMappings(
    uint8_t interfaceIndex, const uint32_t *ipv4Addresses, size_t count, ArpMapping *out
) {
	if (count == 0) {
		return ESP_OK;
	}

	LookupContext context{
	    .interfaceIndex = interfaceIndex,
	    .ipv4Addresses = ipv4Addresses,
	    .count = count,
	    .out = out,
	};
	return esp_netif_tcpip_exec(&lookupArpTcpip, &context);
}

esp_err_t requestArp(
    uint8_t interfaceIndex, const uint32_t *ipv4Addresses, size_t count, ArpRequestStats &stats
) {
	if (count == 0) {
		stats = {};
		return ESP_OK;
	}

	RequestContext context{
	    .interfaceIndex = interfaceIndex,
	    .ipv4Addresses = ipv4Addresses,
	    .count = count,
	};
	const esp_err_t result = esp_netif_tcpip_exec(&requestArpTcpip, &context);
	stats = context.stats;
	return result;
}

size_t recommendedArpBatchSize(size_t requested) {
	if (requested == 0) {
		return 1;
	}
	const size_t tableSize = static_cast<size_t>(ARP_TABLE_SIZE);
	return std::max<size_t>(1, std::min(requested, tableSize));
}

} // namespace scout_internal
