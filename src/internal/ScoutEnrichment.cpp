#include "ScoutEnrichment.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace scout_internal {
namespace {

template <size_t N> void removeAt(auto (&items)[N], size_t &count, size_t index) {
	if (index >= count) {
		return;
	}
	for (size_t i = index + 1; i < count; ++i) {
		items[i - 1] = items[i];
	}
	count--;
	items[count] = {};
}

bool expired(uint64_t expiresAtMs, uint64_t nowMs) {
	return expiresAtMs != 0 && nowMs >= expiresAtMs;
}

template <size_t N>
bool expireTextField(
    char (&value)[N], ScoutObservationSource &source, uint64_t &expiresAtMs, uint64_t nowMs
) {
	if (value[0] == '\0' || !expired(expiresAtMs, nowMs)) {
		return false;
	}
	value[0] = '\0';
	source = ScoutObservationSource::None;
	expiresAtMs = 0;
	return true;
}

size_t oldestNameIndex(const ScoutDeviceDetails &details) {
	size_t oldest = 0;
	for (size_t i = 1; i < details.nameCount; ++i) {
		if (details.names[i].lastSeenAtMs < details.names[oldest].lastSeenAtMs) {
			oldest = i;
		}
	}
	return oldest;
}

size_t oldestServiceIndex(const ScoutDeviceDetails &details) {
	size_t oldest = 0;
	for (size_t i = 1; i < details.serviceCount; ++i) {
		if (details.services[i].lastSeenAtMs < details.services[oldest].lastSeenAtMs) {
			oldest = i;
		}
	}
	return oldest;
}

size_t oldestMetadataIndex(const ScoutDeviceDetails &details) {
	size_t oldest = 0;
	for (size_t i = 1; i < details.metadataCount; ++i) {
		if (details.metadata[i].lastSeenAtMs < details.metadata[oldest].lastSeenAtMs) {
			oldest = i;
		}
	}
	return oldest;
}

int namePriority(ScoutNameSource source) {
	switch (source) {
	case ScoutNameSource::SsdpFriendlyName:
		return 0;
	case ScoutNameSource::MdnsInstance:
		return 1;
	case ScoutNameSource::MdnsHostname:
		return 2;
	case ScoutNameSource::Nbns:
		return 3;
	case ScoutNameSource::ReverseDns:
		return 4;
	case ScoutNameSource::ManufacturerModel:
		return 5;
	case ScoutNameSource::Vendor:
		return 6;
	case ScoutNameSource::None:
		return 100;
	}
	return 100;
}

const char *findHeader(const char *data, size_t length, const char *name, size_t &valueLength) {
	valueLength = 0;
	if (data == nullptr || name == nullptr) {
		return nullptr;
	}
	const size_t nameLength = std::strlen(name);
	for (size_t i = 0; i + nameLength + 1 < length; ++i) {
		const bool lineStart = i == 0 || data[i - 1] == '\n';
		if (!lineStart) {
			continue;
		}
		bool matches = true;
		for (size_t j = 0; j < nameLength; ++j) {
			if (std::tolower(static_cast<unsigned char>(data[i + j])) !=
			    std::tolower(static_cast<unsigned char>(name[j]))) {
				matches = false;
				break;
			}
		}
		if (!matches || data[i + nameLength] != ':') {
			continue;
		}
		size_t start = i + nameLength + 1;
		while (start < length && (data[start] == ' ' || data[start] == '\t')) {
			start++;
		}
		size_t end = start;
		while (end < length && data[end] != '\r' && data[end] != '\n') {
			end++;
		}
		while (end > start && (data[end - 1] == ' ' || data[end - 1] == '\t')) {
			end--;
		}
		valueLength = end - start;
		return data + start;
	}
	return nullptr;
}

bool extractXmlTag(
    const char *data, size_t length, const char *tag, char *out, size_t outCapacity
) {
	if (data == nullptr || tag == nullptr || out == nullptr || outCapacity == 0) {
		return false;
	}
	char open[64] = {};
	char close[64] = {};
	if (std::strlen(tag) + 3 >= sizeof(open)) {
		return false;
	}
	std::snprintf(open, sizeof(open), "<%s>", tag);
	std::snprintf(close, sizeof(close), "</%s>", tag);
	const size_t openLength = std::strlen(open);
	const size_t closeLength = std::strlen(close);

	for (size_t i = 0; i + openLength < length; ++i) {
		if (std::memcmp(data + i, open, openLength) != 0) {
			continue;
		}
		const size_t valueStart = i + openLength;
		for (size_t j = valueStart; j + closeLength <= length; ++j) {
			if (std::memcmp(data + j, close, closeLength) == 0) {
				return copyTextN(out, outCapacity, data + valueStart, j - valueStart);
			}
		}
	}
	return false;
}

bool sameNonEmpty(const char *left, const char *right) {
	return left != nullptr && right != nullptr && left[0] != '\0' && right[0] != '\0' &&
	       textEqualsIgnoreCase(left, right);
}

bool hasMatchingMdnsHostname(const ScoutDeviceDetails &left, const ScoutDeviceDetails &right) {
	for (size_t i = 0; i < left.nameCount; ++i) {
		if (left.names[i].source != ScoutNameSource::MdnsHostname) {
			continue;
		}
		for (size_t j = 0; j < right.nameCount; ++j) {
			if (right.names[j].source == ScoutNameSource::MdnsHostname &&
			    textEqualsIgnoreCase(left.names[i].value, right.names[j].value)) {
				return true;
			}
		}
	}
	return false;
}

bool hasMatchingServiceFingerprint(
    const ScoutDeviceDetails &left, const ScoutDeviceDetails &right
) {
	for (size_t i = 0; i < left.serviceCount; ++i) {
		const auto &a = left.services[i];
		if (a.instanceName[0] == '\0') {
			continue;
		}
		for (size_t j = 0; j < right.serviceCount; ++j) {
			const auto &b = right.services[j];
			if (textEqualsIgnoreCase(a.type, b.type) &&
			    textEqualsIgnoreCase(a.protocol, b.protocol) &&
			    textEqualsIgnoreCase(a.instanceName, b.instanceName)) {
				return true;
			}
		}
	}
	return false;
}

} // namespace

bool textEqualsIgnoreCase(const char *left, const char *right) {
	if (left == nullptr || right == nullptr) {
		return left == right;
	}
	while (*left != '\0' && *right != '\0') {
		if (std::tolower(static_cast<unsigned char>(*left)) !=
		    std::tolower(static_cast<unsigned char>(*right))) {
			return false;
		}
		left++;
		right++;
	}
	return *left == '\0' && *right == '\0';
}

bool copyText(char *destination, size_t capacity, const char *source) {
	return source != nullptr && copyTextN(destination, capacity, source, std::strlen(source));
}

bool copyTextN(char *destination, size_t capacity, const char *source, size_t length) {
	if (destination == nullptr || capacity == 0 || source == nullptr) {
		return false;
	}
	const size_t count = std::min(length, capacity - 1);
	std::memcpy(destination, source, count);
	destination[count] = '\0';
	return length < capacity;
}

bool macIsLocallyAdministered(const ScoutMacAddress &mac) {
	return mac.valid() && (mac.bytes[0] & 0x02U) != 0;
}

bool macIsMulticast(const ScoutMacAddress &mac) {
	return mac.valid() && (mac.bytes[0] & 0x01U) != 0;
}

EnrichmentUpsertResult upsertName(
    ScoutDeviceDetails &details,
    ScoutNameSource source,
    const char *value,
    uint64_t observedAtMs,
    uint64_t expiresAtMs
) {
	if (value == nullptr || value[0] == '\0') {
		return EnrichmentUpsertResult::Unchanged;
	}
	for (size_t i = 0; i < details.nameCount; ++i) {
		auto &name = details.names[i];
		if (name.source != source || !textEqualsIgnoreCase(name.value, value)) {
			continue;
		}
		name.lastSeenAtMs = observedAtMs;
		name.expiresAtMs = expiresAtMs;
		return EnrichmentUpsertResult::Unchanged;
	}

	const bool replacing = details.nameCount >= SCOUT_MAX_NAMES_PER_DEVICE;
	const size_t index = replacing ? oldestNameIndex(details) : details.nameCount++;
	auto &name = details.names[index];
	name = {};
	name.source = source;
	copyText(name.value, sizeof(name.value), value);
	name.firstSeenAtMs = observedAtMs;
	name.lastSeenAtMs = observedAtMs;
	name.expiresAtMs = expiresAtMs;
	return replacing ? EnrichmentUpsertResult::Replaced : EnrichmentUpsertResult::Changed;
}

EnrichmentUpsertResult
upsertService(ScoutDeviceDetails &details, const ScoutServiceInfo &incoming) {
	if (incoming.type[0] == '\0') {
		return EnrichmentUpsertResult::Unchanged;
	}
	for (size_t i = 0; i < details.serviceCount; ++i) {
		auto &service = details.services[i];
		if (service.interfaceIndex != incoming.interfaceIndex ||
		    service.source != incoming.source ||
		    !textEqualsIgnoreCase(service.type, incoming.type) ||
		    !textEqualsIgnoreCase(service.protocol, incoming.protocol) ||
		    !textEqualsIgnoreCase(service.instanceName, incoming.instanceName)) {
			continue;
		}
		const bool changed = service.port != incoming.port ||
		                     !textEqualsIgnoreCase(service.hostname, incoming.hostname);
		const uint64_t firstSeen = service.firstSeenAtMs;
		service = incoming;
		service.firstSeenAtMs = firstSeen != 0 ? firstSeen : incoming.lastSeenAtMs;
		return changed ? EnrichmentUpsertResult::Changed : EnrichmentUpsertResult::Unchanged;
	}

	const bool replacing = details.serviceCount >= SCOUT_MAX_SERVICES_PER_DEVICE;
	const size_t index = replacing ? oldestServiceIndex(details) : details.serviceCount++;
	details.services[index] = incoming;
	if (details.services[index].firstSeenAtMs == 0) {
		details.services[index].firstSeenAtMs = incoming.lastSeenAtMs;
	}
	return replacing ? EnrichmentUpsertResult::Replaced : EnrichmentUpsertResult::Changed;
}

EnrichmentUpsertResult
upsertMetadata(ScoutDeviceDetails &details, const ScoutMetadataEntry &incoming) {
	if (incoming.key[0] == '\0') {
		return EnrichmentUpsertResult::Unchanged;
	}
	for (size_t i = 0; i < details.metadataCount; ++i) {
		auto &metadata = details.metadata[i];
		if (metadata.source != incoming.source ||
		    !textEqualsIgnoreCase(metadata.key, incoming.key)) {
			continue;
		}
		const bool changed = !textEqualsIgnoreCase(metadata.value, incoming.value);
		const uint64_t firstSeen = metadata.firstSeenAtMs;
		metadata = incoming;
		metadata.firstSeenAtMs = firstSeen != 0 ? firstSeen : incoming.lastSeenAtMs;
		return changed ? EnrichmentUpsertResult::Changed : EnrichmentUpsertResult::Unchanged;
	}

	const bool replacing = details.metadataCount >= SCOUT_MAX_METADATA_PER_DEVICE;
	const size_t index = replacing ? oldestMetadataIndex(details) : details.metadataCount++;
	details.metadata[index] = incoming;
	if (details.metadata[index].firstSeenAtMs == 0) {
		details.metadata[index].firstSeenAtMs = incoming.lastSeenAtMs;
	}
	return replacing ? EnrichmentUpsertResult::Replaced : EnrichmentUpsertResult::Changed;
}

bool upsertIpv6(ScoutEndpoint &endpoint, const ScoutIpv6Address &address) {
	if (!address.valid()) {
		return false;
	}
	for (size_t i = 0; i < endpoint.ipv6Count; ++i) {
		if (endpoint.ipv6[i] == address) {
			return false;
		}
	}
	if (endpoint.ipv6Count < SCOUT_MAX_IPV6_PER_ENDPOINT) {
		endpoint.ipv6[endpoint.ipv6Count++] = address;
		return true;
	}
	return false;
}

ScoutDeviceChange expireEnrichment(ScoutDeviceDetails &details, uint64_t nowMs) {
	ScoutDeviceChange changes = ScoutDeviceChange::None;
	for (size_t i = 0; i < details.nameCount;) {
		if (expired(details.names[i].expiresAtMs, nowMs)) {
			removeAt(details.names, details.nameCount, i);
			changes |= ScoutDeviceChange::Name;
		} else {
			i++;
		}
	}
	for (size_t i = 0; i < details.serviceCount;) {
		if (expired(details.services[i].expiresAtMs, nowMs)) {
			removeAt(details.services, details.serviceCount, i);
			changes |= ScoutDeviceChange::Service;
		} else {
			i++;
		}
	}
	for (size_t i = 0; i < details.metadataCount;) {
		if (expired(details.metadata[i].expiresAtMs, nowMs)) {
			removeAt(details.metadata, details.metadataCount, i);
			changes |= ScoutDeviceChange::Metadata;
		} else {
			i++;
		}
	}

	if (expireTextField(
	        details.manufacturer,
	        details.manufacturerSource,
	        details.manufacturerExpiresAtMs,
	        nowMs
	    )) {
		changes |= ScoutDeviceChange::Metadata;
		if (details.vendor.known && details.vendor.source == ScoutVendorSource::Ssdp) {
			details.vendor = {};
			changes |= ScoutDeviceChange::Vendor;
		}
	}
	const bool modelNameExpired = expireTextField(
	    details.modelName,
	    details.modelNameSource,
	    details.modelNameExpiresAtMs,
	    nowMs
	);
	const bool modelNumberExpired = expireTextField(
	    details.modelNumber,
	    details.modelNumberSource,
	    details.modelNumberExpiresAtMs,
	    nowMs
	);
	if (modelNameExpired || modelNumberExpired) {
		changes |= ScoutDeviceChange::Metadata;
	}

	const bool serialExpired = expireTextField(
	    details.serialNumber,
	    details.serialNumberSource,
	    details.serialNumberExpiresAtMs,
	    nowMs
	);
	const bool persistentIdExpired = expireTextField(
	    details.persistentDeviceId,
	    details.persistentDeviceIdSource,
	    details.persistentDeviceIdExpiresAtMs,
	    nowMs
	);
	if (persistentIdExpired) {
		details.persistentDeviceNamespace[0] = '\0';
	}
	const bool upnpUdnExpired =
	    expireTextField(details.upnpUdn, details.upnpUdnSource, details.upnpUdnExpiresAtMs, nowMs);
	if (serialExpired || persistentIdExpired || upnpUdnExpired) {
		changes |= ScoutDeviceChange::Identity;
	}

	if (details.vendor.known && expired(details.vendor.expiresAtMs, nowMs)) {
		details.vendor = {};
		changes |= ScoutDeviceChange::Vendor;
	}
	return changes;
}

void mergeDeviceDetails(ScoutDeviceDetails &target, const ScoutDeviceDetails &source) {
	for (size_t i = 0; i < source.nameCount; ++i) {
		(void)upsertName(
		    target,
		    source.names[i].source,
		    source.names[i].value,
		    source.names[i].lastSeenAtMs,
		    source.names[i].expiresAtMs
		);
	}
	for (size_t i = 0; i < source.serviceCount; ++i) {
		(void)upsertService(target, source.services[i]);
	}
	for (size_t i = 0; i < source.metadataCount; ++i) {
		(void)upsertMetadata(target, source.metadata[i]);
	}
	if (!target.vendor.known && source.vendor.known) {
		target.vendor = source.vendor;
	}
	target.locallyAdministeredMac = target.locallyAdministeredMac || source.locallyAdministeredMac;
	target.multicastMac = target.multicastMac || source.multicastMac;

	auto mergeText = [](auto &targetValue,
	                    ScoutObservationSource &targetSource,
	                    uint64_t &targetExpiresAt,
	                    const auto &sourceValue,
	                    ScoutObservationSource sourceSource,
	                    uint64_t sourceExpiresAt) {
		if (targetValue[0] != '\0' || sourceValue[0] == '\0') {
			return;
		}
		copyText(targetValue, sizeof(targetValue), sourceValue);
		targetSource = sourceSource;
		targetExpiresAt = sourceExpiresAt;
	};
	mergeText(
	    target.manufacturer,
	    target.manufacturerSource,
	    target.manufacturerExpiresAtMs,
	    source.manufacturer,
	    source.manufacturerSource,
	    source.manufacturerExpiresAtMs
	);
	mergeText(
	    target.modelName,
	    target.modelNameSource,
	    target.modelNameExpiresAtMs,
	    source.modelName,
	    source.modelNameSource,
	    source.modelNameExpiresAtMs
	);
	mergeText(
	    target.modelNumber,
	    target.modelNumberSource,
	    target.modelNumberExpiresAtMs,
	    source.modelNumber,
	    source.modelNumberSource,
	    source.modelNumberExpiresAtMs
	);
	mergeText(
	    target.serialNumber,
	    target.serialNumberSource,
	    target.serialNumberExpiresAtMs,
	    source.serialNumber,
	    source.serialNumberSource,
	    source.serialNumberExpiresAtMs
	);
	const bool hadPersistentId = target.persistentDeviceId[0] != '\0';
	mergeText(
	    target.persistentDeviceId,
	    target.persistentDeviceIdSource,
	    target.persistentDeviceIdExpiresAtMs,
	    source.persistentDeviceId,
	    source.persistentDeviceIdSource,
	    source.persistentDeviceIdExpiresAtMs
	);
	if (!hadPersistentId && target.persistentDeviceId[0] != '\0') {
		copyText(
		    target.persistentDeviceNamespace,
		    sizeof(target.persistentDeviceNamespace),
		    source.persistentDeviceNamespace
		);
	}
	mergeText(
	    target.upnpUdn,
	    target.upnpUdnSource,
	    target.upnpUdnExpiresAtMs,
	    source.upnpUdn,
	    source.upnpUdnSource,
	    source.upnpUdnExpiresAtMs
	);
	target.lastEnrichedAtMs = std::max(target.lastEnrichedAtMs, source.lastEnrichedAtMs);
}

bool selectPreferredName(const ScoutDeviceDetails &details, ScoutPreferredName &out) {
	out = {};
	int bestPriority = 1000;
	for (size_t i = 0; i < details.nameCount; ++i) {
		const auto &name = details.names[i];
		if (name.value[0] == '\0') {
			continue;
		}
		const int priority = namePriority(name.source);
		if (priority < bestPriority) {
			bestPriority = priority;
			out.source = name.source;
			copyText(out.value, sizeof(out.value), name.value);
		}
	}
	if (out.value[0] != '\0') {
		return true;
	}

	if (details.manufacturer[0] != '\0' && details.modelName[0] != '\0') {
		out.source = ScoutNameSource::ManufacturerModel;
		copyText(out.value, sizeof(out.value), details.manufacturer);
		const size_t used = std::strlen(out.value);
		if (used + 1 < sizeof(out.value)) {
			out.value[used] = ' ';
			out.value[used + 1] = '\0';
			copyText(out.value + used + 1, sizeof(out.value) - used - 1, details.modelName);
		}
		return true;
	}
	if (details.modelName[0] != '\0') {
		out.source = ScoutNameSource::ManufacturerModel;
		copyText(out.value, sizeof(out.value), details.modelName);
		return true;
	}
	if (details.vendor.known && details.vendor.name[0] != '\0') {
		out.source = ScoutNameSource::Vendor;
		copyText(out.value, sizeof(out.value), details.vendor.name);
		return true;
	}
	return false;
}

bool parseSsdpResponse(const char *data, size_t length, SsdpResponseInfo &out) {
	out = {};
	if (data == nullptr || length == 0) {
		return false;
	}

	size_t statusLineLength = 0;
	while (statusLineLength < length && data[statusLineLength] != '\r' &&
	       data[statusLineLength] != '\n') {
		statusLineLength++;
	}
	if (statusLineLength < 12) {
		return false;
	}
	const bool http10 = std::memcmp(data, "HTTP/1.0 ", 9) == 0;
	const bool http11 = std::memcmp(data, "HTTP/1.1 ", 9) == 0;
	const bool statusOk = data[9] == '2' && data[10] == '0' && data[11] == '0';
	const bool validSeparator = statusLineLength == 12 || data[12] == ' ' || data[12] == '\t';
	if ((!http10 && !http11) || !statusOk || !validSeparator) {
		return false;
	}

	auto clearNullSentinel = [](char *value) {
		if (textEqualsIgnoreCase(value, "null") || textEqualsIgnoreCase(value, "(null)")) {
			value[0] = '\0';
		}
	};

	size_t valueLength = 0;
	if (const char *value = findHeader(data, length, "LOCATION", valueLength)) {
		copyTextN(out.location, sizeof(out.location), value, valueLength);
		clearNullSentinel(out.location);
	}
	if (const char *value = findHeader(data, length, "USN", valueLength)) {
		copyTextN(out.usn, sizeof(out.usn), value, valueLength);
		clearNullSentinel(out.usn);
	}
	if (const char *value = findHeader(data, length, "SERVER", valueLength)) {
		copyTextN(out.server, sizeof(out.server), value, valueLength);
		clearNullSentinel(out.server);
	}
	if (const char *value = findHeader(data, length, "ST", valueLength)) {
		copyTextN(out.searchTarget, sizeof(out.searchTarget), value, valueLength);
		clearNullSentinel(out.searchTarget);
	}
	if (const char *value = findHeader(data, length, "CACHE-CONTROL", valueLength)) {
		for (size_t i = 0; i + 7 < valueLength; ++i) {
			if (std::tolower(static_cast<unsigned char>(value[i])) == 'm' &&
			    std::tolower(static_cast<unsigned char>(value[i + 1])) == 'a' &&
			    std::tolower(static_cast<unsigned char>(value[i + 2])) == 'x' &&
			    value[i + 3] == '-' &&
			    std::tolower(static_cast<unsigned char>(value[i + 4])) == 'a' &&
			    std::tolower(static_cast<unsigned char>(value[i + 5])) == 'g' &&
			    std::tolower(static_cast<unsigned char>(value[i + 6])) == 'e') {
				size_t pos = i + 7;
				while (pos < valueLength && (value[pos] == ' ' || value[pos] == '=')) {
					pos++;
				}
				uint32_t parsed = 0;
				bool hasDigit = false;
				bool overflow = false;
				while (pos < valueLength && std::isdigit(static_cast<unsigned char>(value[pos]))) {
					const uint32_t digit = static_cast<uint32_t>(value[pos] - '0');
					hasDigit = true;
					if (parsed > (UINT32_MAX - digit) / 10U) {
						overflow = true;
					} else if (!overflow) {
						parsed = parsed * 10U + digit;
					}
					pos++;
				}
				if (hasDigit && !overflow) {
					out.maxAgeSeconds = parsed;
				}
				break;
			}
		}
	}
	return out.location[0] != '\0' || out.usn[0] != '\0' || out.searchTarget[0] != '\0';
}

bool parseUpnpDescription(const char *data, size_t length, UpnpDescriptionInfo &out) {
	out = {};
	if (data == nullptr || length == 0) {
		return false;
	}
	const bool any =
	    extractXmlTag(data, length, "friendlyName", out.friendlyName, sizeof(out.friendlyName)) |
	    extractXmlTag(data, length, "manufacturer", out.manufacturer, sizeof(out.manufacturer)) |
	    extractXmlTag(data, length, "modelName", out.modelName, sizeof(out.modelName)) |
	    extractXmlTag(data, length, "modelNumber", out.modelNumber, sizeof(out.modelNumber)) |
	    extractXmlTag(data, length, "serialNumber", out.serialNumber, sizeof(out.serialNumber)) |
	    extractXmlTag(data, length, "UDN", out.udn, sizeof(out.udn)) |
	    extractXmlTag(data, length, "deviceType", out.deviceType, sizeof(out.deviceType));
	return any;
}

bool parseNbnsNodeStatusName(
    const uint8_t *data,
    size_t length,
    uint16_t expectedTransactionId,
    char *out,
    size_t outCapacity
) {
	if (data == nullptr || length < 12 || out == nullptr || outCapacity == 0) {
		return false;
	}
	auto read16 = [](const uint8_t *p) {
		return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8U) | p[1]);
	};
	if (read16(data) != expectedTransactionId) {
		return false;
	}
	const uint16_t flags = read16(data + 2);
	if ((flags & 0x8000U) == 0 || (flags & 0x000FU) != 0) {
		return false;
	}

	auto skipName = [&](size_t start, size_t &consumed) {
		consumed = 0;
		size_t cursor = start;
		for (size_t labels = 0; labels < 128; ++labels) {
			if (cursor >= length) {
				return false;
			}
			const uint8_t label = data[cursor];
			if ((label & 0xC0U) == 0xC0U) {
				if (cursor + 1 >= length) {
					return false;
				}
				consumed += 2;
				return true;
			}
			if ((label & 0xC0U) != 0 || label > 63) {
				return false;
			}
			cursor++;
			consumed++;
			if (label == 0) {
				return true;
			}
			if (cursor + label > length) {
				return false;
			}
			cursor += label;
			consumed += label;
		}
		return false;
	};

	const uint16_t questions = read16(data + 4);
	const uint16_t answers = read16(data + 6);
	size_t offset = 12;
	for (uint16_t i = 0; i < questions; ++i) {
		size_t consumed = 0;
		if (!skipName(offset, consumed) || offset + consumed + 4 > length) {
			return false;
		}
		offset += consumed + 4;
	}

	for (uint16_t answer = 0; answer < answers; ++answer) {
		size_t consumed = 0;
		if (!skipName(offset, consumed) || offset + consumed + 10 > length) {
			return false;
		}
		offset += consumed;
		const uint16_t type = read16(data + offset);
		const uint16_t klass = read16(data + offset + 2);
		const uint16_t rdLength = read16(data + offset + 8);
		offset += 10;
		if (offset + rdLength > length) {
			return false;
		}
		if (type != 0x21U || klass != 1U || rdLength < 1) {
			offset += rdLength;
			continue;
		}
		const uint8_t count = data[offset];
		const size_t required = 1U + static_cast<size_t>(count) * 18U;
		if (count == 0 || count > 32 || required > rdLength) {
			return false;
		}
		for (uint8_t i = 0; i < count; ++i) {
			const uint8_t *entry = data + offset + 1U + static_cast<size_t>(i) * 18U;
			const uint8_t suffix = entry[15];
			const uint16_t nameFlags =
			    static_cast<uint16_t>(entry[16] << 8U) | static_cast<uint16_t>(entry[17]);
			if ((nameFlags & 0x8000U) != 0 || suffix != 0x00U) {
				continue;
			}
			size_t nameLength = 15;
			while (nameLength > 0 && entry[nameLength - 1] == ' ') {
				nameLength--;
			}
			if (nameLength > 0) {
				return copyTextN(
				    out,
				    outCapacity,
				    reinterpret_cast<const char *>(entry),
				    nameLength
				);
			}
		}
		offset += rdLength;
	}
	return false;
}

bool identityDetailsContradict(
    const ScoutDeviceDetails &leftDetails, const ScoutDeviceDetails &rightDetails
) {
	if (leftDetails.upnpUdn[0] != '\0' && rightDetails.upnpUdn[0] != '\0' &&
	    !textEqualsIgnoreCase(leftDetails.upnpUdn, rightDetails.upnpUdn)) {
		return true;
	}

	const bool persistentNamespacesMatch =
	    (leftDetails.persistentDeviceNamespace[0] == '\0' &&
	     rightDetails.persistentDeviceNamespace[0] == '\0') ||
	    sameNonEmpty(leftDetails.persistentDeviceNamespace, rightDetails.persistentDeviceNamespace);
	if (leftDetails.persistentDeviceId[0] != '\0' && rightDetails.persistentDeviceId[0] != '\0' &&
	    persistentNamespacesMatch &&
	    !textEqualsIgnoreCase(leftDetails.persistentDeviceId, rightDetails.persistentDeviceId)) {
		return true;
	}

	const bool trustedSerialPair =
	    leftDetails.serialNumberSource == ScoutObservationSource::Ssdp &&
	    rightDetails.serialNumberSource == ScoutObservationSource::Ssdp &&
	    leftDetails.manufacturerSource == ScoutObservationSource::Ssdp &&
	    rightDetails.manufacturerSource == ScoutObservationSource::Ssdp;
	if (trustedSerialPair && sameNonEmpty(leftDetails.manufacturer, rightDetails.manufacturer) &&
	    leftDetails.serialNumber[0] != '\0' && rightDetails.serialNumber[0] != '\0' &&
	    !textEqualsIgnoreCase(leftDetails.serialNumber, rightDetails.serialNumber)) {
		return true;
	}
	return false;
}

bool identityRelation(
    const ScoutDeviceInfo &leftInfo,
    const ScoutDeviceDetails &leftDetails,
    const ScoutDeviceInfo &rightInfo,
    const ScoutDeviceDetails &rightDetails,
    ScoutIdentityRelation &out
) {
	out = {};
	if (leftInfo.mac == rightInfo.mac) {
		return false;
	}
	out.first = leftInfo.key;
	out.second = rightInfo.key;

	if (identityDetailsContradict(leftDetails, rightDetails)) {
		return false;
	}

	const bool trustedSerialPair =
	    leftDetails.serialNumberSource == ScoutObservationSource::Ssdp &&
	    rightDetails.serialNumberSource == ScoutObservationSource::Ssdp &&
	    leftDetails.manufacturerSource == ScoutObservationSource::Ssdp &&
	    rightDetails.manufacturerSource == ScoutObservationSource::Ssdp;

	if (sameNonEmpty(leftDetails.upnpUdn, rightDetails.upnpUdn)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::UpnpUdn,
		    .confidence = ScoutIdentityConfidence::Certain,
		    .source = ScoutObservationSource::Ssdp,
		};
		return true;
	}
	if (sameNonEmpty(
	        leftDetails.persistentDeviceNamespace,
	        rightDetails.persistentDeviceNamespace
	    ) &&
	    sameNonEmpty(leftDetails.persistentDeviceId, rightDetails.persistentDeviceId)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::MdnsPersistentId,
		    .confidence = ScoutIdentityConfidence::Strong,
		    .source = ScoutObservationSource::Mdns,
		};
		return true;
	}
	if (trustedSerialPair && sameNonEmpty(leftDetails.serialNumber, rightDetails.serialNumber) &&
	    sameNonEmpty(leftDetails.manufacturer, rightDetails.manufacturer)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::SharedSerialNumber,
		    .confidence = ScoutIdentityConfidence::Strong,
		    .source = ScoutObservationSource::Ssdp,
		};
		return true;
	}
	if (hasMatchingMdnsHostname(leftDetails, rightDetails)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::MdnsHostname,
		    .confidence = ScoutIdentityConfidence::Moderate,
		    .source = ScoutObservationSource::Mdns,
		};
		return true;
	}
	if (hasMatchingServiceFingerprint(leftDetails, rightDetails)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::ServiceFingerprint,
		    .confidence = ScoutIdentityConfidence::Moderate,
		    .source = ScoutObservationSource::Mdns,
		};
		return true;
	}
	if (sameNonEmpty(leftDetails.manufacturer, rightDetails.manufacturer) &&
	    sameNonEmpty(leftDetails.modelName, rightDetails.modelName)) {
		out.evidence = {
		    .type = ScoutIdentityEvidenceType::SharedManufacturerModel,
		    .confidence = ScoutIdentityConfidence::Weak,
		    .source = ScoutObservationSource::None,
		};
		return true;
	}
	return false;
}

uint64_t identityGroupRuntimeId(const ScoutDeviceKey *members, size_t count) {
	constexpr uint64_t OffsetBasis = 1469598103934665603ULL;
	constexpr uint64_t Prime = 1099511628211ULL;
	uint64_t hash = OffsetBasis;
	if (members == nullptr) {
		return hash;
	}
	for (size_t i = 0; i < count; ++i) {
		for (uint8_t byte : members[i].mac.bytes) {
			hash ^= byte;
			hash *= Prime;
		}
	}
	return hash;
}

} // namespace scout_internal
