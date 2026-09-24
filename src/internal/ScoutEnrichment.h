#pragma once

#include "../Scout.h"

#include <cstddef>
#include <cstdint>

namespace scout_internal {

enum class EnrichmentUpsertResult : uint8_t {
	Unchanged,
	Changed,
	Replaced,
};

struct SsdpResponseInfo {
	char location[256] = {};
	char usn[192] = {};
	char server[160] = {};
	char searchTarget[128] = {};
	uint32_t maxAgeSeconds = 0;
};

struct UpnpDescriptionInfo {
	char friendlyName[SCOUT_NAME_SIZE] = {};
	char manufacturer[SCOUT_MANUFACTURER_SIZE] = {};
	char modelName[SCOUT_MODEL_SIZE] = {};
	char modelNumber[SCOUT_MODEL_SIZE] = {};
	char serialNumber[SCOUT_SERIAL_SIZE] = {};
	char udn[SCOUT_UPNP_UDN_SIZE] = {};
	char deviceType[SCOUT_METADATA_VALUE_SIZE] = {};
};

bool textEqualsIgnoreCase(const char *left, const char *right);
bool copyText(char *destination, size_t capacity, const char *source);
bool copyTextN(char *destination, size_t capacity, const char *source, size_t length);

bool macIsLocallyAdministered(const ScoutMacAddress &mac);
bool macIsMulticast(const ScoutMacAddress &mac);

EnrichmentUpsertResult upsertName(
    ScoutDeviceDetails &details,
    ScoutNameSource source,
    const char *value,
    uint64_t observedAtMs,
    uint64_t expiresAtMs
);

EnrichmentUpsertResult upsertService(ScoutDeviceDetails &details, const ScoutServiceInfo &service);

EnrichmentUpsertResult
upsertMetadata(ScoutDeviceDetails &details, const ScoutMetadataEntry &metadata);

bool upsertIpv6(ScoutEndpoint &endpoint, const ScoutIpv6Address &address);

ScoutDeviceChange expireEnrichment(ScoutDeviceDetails &details, uint64_t nowMs);
void mergeDeviceDetails(ScoutDeviceDetails &target, const ScoutDeviceDetails &source);

bool selectPreferredName(const ScoutDeviceDetails &details, ScoutPreferredName &out);

bool parseSsdpResponse(const char *data, size_t length, SsdpResponseInfo &out);
bool parseUpnpDescription(const char *data, size_t length, UpnpDescriptionInfo &out);
bool parseNbnsNodeStatusName(
    const uint8_t *data,
    size_t length,
    uint16_t expectedTransactionId,
    char *out,
    size_t outCapacity
);

bool identityRelation(
    const ScoutDeviceInfo &leftInfo,
    const ScoutDeviceDetails &leftDetails,
    const ScoutDeviceInfo &rightInfo,
    const ScoutDeviceDetails &rightDetails,
    ScoutIdentityRelation &out
);

uint64_t identityGroupRuntimeId(const ScoutDeviceKey *members, size_t count);

} // namespace scout_internal
