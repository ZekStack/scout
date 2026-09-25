#include "internal/ScoutDns.h"
#include "internal/ScoutEnrichment.h"
#include "internal/ScoutLogic.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

constexpr uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (static_cast<uint32_t>(a) << 24U) |
	       (static_cast<uint32_t>(b) << 16U) |
	       (static_cast<uint32_t>(c) << 8U) |
	       static_cast<uint32_t>(d);
}

bool upsertEndpoint(
    ScoutDeviceInfo &device,
    uint8_t interfaceIndex,
    const char *name,
    uint32_t address,
    uint64_t observedAt,
    bool confirmed = false
) {
	char key[SCOUT_INTERFACE_KEY_SIZE] = {};
	std::snprintf(key, sizeof(key), "TEST_%u", static_cast<unsigned>(interfaceIndex));
	return scout_internal::upsertEndpoint(
	    device,
	    interfaceIndex,
	    name,
	    key,
	    ScoutInterfaceType::Custom,
	    address,
	    observedAt,
	    confirmed ? ScoutObservationSource::ArpProbe : ScoutObservationSource::ArpCache,
	    confirmed
	);
}

ScoutMacAddress mac(uint8_t suffix) {
	return ScoutMacAddress{{0x00, 0x11, 0x22, 0x33, 0x44, suffix}};
}

ScoutDeviceInfo deviceWithMac(uint8_t suffix) {
	ScoutDeviceInfo info{};
	info.mac = mac(suffix);
	info.key.kind = ScoutIdentityKind::Mac;
	info.key.mac = info.mac;
	return info;
}

void testPublicDefaultsAndValueTypes() {
	ScoutConfig config;
	assert(config.memory.allocation == Strata::Placement::PreferExternal);
	assert(config.memory.taskStack == Strata::Placement::PreferExternal);
	assert(config.scanOnInit);
	assert(config.deviceMaxAgeMs == 5ULL * 60ULL * 1000ULL);
	assert(config.maxDevices == 128);
	assert(config.maxHostsPerSubnet == 512);
	assert(config.maxIdentityRelations == 512);
	assert(config.taskStackBytes == 32U * 1024U);
	assert(config.providers.icmp.enabled);
	assert(config.providers.mdns.enabled);
	assert(config.providers.ssdp.enabled);
	assert(!config.providers.nbns.enabled);
	assert(!config.providers.reverseDns.enabled);
	assert(config.providers.oui);
	assert(SCOUT_MAX_ENDPOINTS_PER_DEVICE == 16);
	assert(SCOUT_MAX_SERVICES_PER_DEVICE >= 32);
	assert(SCOUT_MAX_METADATA_PER_DEVICE >= 64);

	ScoutMacAddress empty;
	assert(!empty.valid());

	ScoutMacAddress address{{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
	assert(address.valid());

	ScoutDeviceKey macKey;
	macKey.kind = ScoutIdentityKind::Mac;
	macKey.mac = address;
	ScoutDeviceKey sameMacKey = macKey;
	assert(macKey == sameMacKey);

	ScoutDeviceKey ipv4Key;
	ipv4Key.kind = ScoutIdentityKind::ProvisionalIpv4;
	ipv4Key.ipv4.value = ipv4(192, 168, 1, 20);
	assert(!(macKey == ipv4Key));

	const ScoutObservationSource combined =
	    ScoutObservationSource::ArpCache | ScoutObservationSource::Mdns;
	assert(
	    scoutObservationMask(combined) ==
	    (scoutObservationMask(ScoutObservationSource::ArpCache) |
	     scoutObservationMask(ScoutObservationSource::Mdns))
	);
}

void testMacHelpers() {
	const uint8_t first[6] = {0x02, 1, 2, 3, 4, 5};
	const uint8_t same[6] = {0x02, 1, 2, 3, 4, 5};
	const uint8_t different[6] = {0x02, 1, 2, 3, 4, 6};

	assert(scout_internal::macEquals(first, same));
	assert(!scout_internal::macEquals(first, different));
	assert(!scout_internal::macEquals(first, nullptr));

	const ScoutMacAddress address = scout_internal::macFromBytes(first);
	assert(scout_internal::macEquals(address, same));
	assert(scout_internal::macIsLocallyAdministered(address));
	assert(!scout_internal::macIsMulticast(address));

	const ScoutMacAddress multicast{{0x01, 0, 0, 0, 0, 1}};
	assert(scout_internal::macIsMulticast(multicast));

	const ScoutMacAddress empty = scout_internal::macFromBytes(nullptr);
	assert(!empty.valid());
}

void testIpv4TargetEnumerationAndBounds() {
	uint32_t targets[512]{};

	const auto result = scout_internal::buildIpv4Targets(
	    ipv4(192, 168, 1, 10),
	    ipv4(255, 255, 255, 0),
	    512,
	    targets,
	    512
	);
	assert(result.status == scout_internal::Ipv4TargetStatus::Ok);
	assert(result.count == 253);
	assert(targets[0] == ipv4(192, 168, 1, 1));
	assert(targets[result.count - 1] == ipv4(192, 168, 1, 254));

	for (size_t i = 0; i < result.count; ++i) {
		assert(targets[i] != ipv4(192, 168, 1, 10));
	}

	const auto slash31 = scout_internal::buildIpv4Targets(
	    ipv4(10, 0, 0, 0),
	    ipv4(255, 255, 255, 254),
	    8,
	    targets,
	    8
	);
	assert(slash31.status == scout_internal::Ipv4TargetStatus::Ok);
	assert(slash31.count == 0);

	const auto tooLarge = scout_internal::buildIpv4Targets(
	    ipv4(10, 1, 2, 3),
	    ipv4(255, 255, 0, 0),
	    512,
	    targets,
	    512
	);
	assert(tooLarge.status == scout_internal::Ipv4TargetStatus::TooLarge);

	const auto invalid = scout_internal::buildIpv4Targets(
	    ipv4(192, 168, 1, 10),
	    ipv4(255, 255, 255, 0),
	    0,
	    targets,
	    512
	);
	assert(invalid.status == scout_internal::Ipv4TargetStatus::InvalidArgument);
}

void testEndpointInsertRefreshAndCapacity() {
	ScoutDeviceInfo device;

	assert(upsertEndpoint(device, 1, "en0", 0x01020304U, 100, true));
	assert(device.endpointCount == 1);
	const auto &first = device.endpoints[0];
	assert(first.interfaceIndex == 1);
	assert(first.ipv4.value == 0x01020304U);
	assert(first.firstSeenAtMs == 100);
	assert(first.lastSeenAtMs == 100);
	assert(first.lastConfirmedAtMs == 100);
	assert(std::strcmp(first.interfaceName, "en0") == 0);
	assert(std::strcmp(first.interfaceKey, "TEST_1") == 0);
	assert(first.interfaceType == ScoutInterfaceType::Custom);

	assert(!upsertEndpoint(device, 1, "en0", 0x01020304U, 250, false));
	assert(device.endpointCount == 1);
	assert(device.endpoints[0].firstSeenAtMs == 100);
	assert(device.endpoints[0].lastSeenAtMs == 250);
	assert(device.endpoints[0].lastConfirmedAtMs == 100);

	for (size_t i = 2; i <= SCOUT_MAX_ENDPOINTS_PER_DEVICE; ++i) {
		char name[SCOUT_INTERFACE_NAME_SIZE] = {};
		std::snprintf(name, sizeof(name), "i%u", static_cast<unsigned>(i));
		assert(upsertEndpoint(
		    device,
		    static_cast<uint8_t>(i),
		    name,
		    static_cast<uint32_t>(i),
		    300 + i
		));
	}
	assert(device.endpointCount == SCOUT_MAX_ENDPOINTS_PER_DEVICE);

	assert(upsertEndpoint(device, 42, "replace", 42, 1000));
	assert(device.endpointCount == SCOUT_MAX_ENDPOINTS_PER_DEVICE);
	bool foundReplacement = false;
	bool foundOldest = false;
	for (size_t i = 0; i < device.endpointCount; ++i) {
		foundReplacement |= device.endpoints[i].interfaceIndex == 42;
		foundOldest |= device.endpoints[i].interfaceIndex == 1;
	}
	assert(foundReplacement);
	assert(!foundOldest);
}

void testEndpointIpv6RemovalAndExpiry() {
	ScoutDeviceInfo device;
	assert(upsertEndpoint(device, 1, "if1", 1, 100));
	assert(upsertEndpoint(device, 2, "if2", 2, 200));

	ScoutIpv6Address ipv6{};
	ipv6.bytes[0] = 0xFE;
	ipv6.bytes[1] = 0x80;
	ipv6.bytes[15] = 1;
	assert(scout_internal::upsertIpv6(device.endpoints[0], ipv6));
	assert(!scout_internal::upsertIpv6(device.endpoints[0], ipv6));
	assert(device.endpoints[0].ipv6Count == 1);

	assert(scout_internal::removeEndpoint(device, 2, 2));
	assert(device.endpointCount == 1);
	assert(!scout_internal::removeEndpoint(device, 2, 2));

	device.lastSeenAtMs = 1000;
	assert(!scout_internal::deviceExpired(device, 1499, 500));
	assert(scout_internal::deviceExpired(device, 1500, 500));
	assert(!scout_internal::deviceExpired(device, 999, 500));
	assert(!scout_internal::deviceExpired(device, 5000, 0));
}

void testMergeDeviceInfo() {
	ScoutDeviceInfo target;
	target.firstSeenAtMs = 200;
	target.lastSeenAtMs = 300;
	target.lastConfirmedAtMs = 250;
	target.observationSources = scoutObservationMask(ScoutObservationSource::ArpCache);
	target.observationCount = 2;
	assert(upsertEndpoint(target, 1, "if1", 1, 300));

	ScoutDeviceInfo source;
	source.firstSeenAtMs = 100;
	source.lastSeenAtMs = 500;
	source.lastConfirmedAtMs = 450;
	source.observationSources = scoutObservationMask(ScoutObservationSource::ArpProbe);
	source.observationCount = 3;
	assert(upsertEndpoint(source, 1, "if1", 1, 450, true));
	assert(!upsertEndpoint(source, 1, "if1", 1, 500, false));
	assert(upsertEndpoint(source, 2, "if2", 2, 400));

	scout_internal::mergeDeviceInfo(target, source);
	assert(target.firstSeenAtMs == 100);
	assert(target.lastSeenAtMs == 500);
	assert(target.lastConfirmedAtMs == 450);
	assert(target.observationCount == 5);
	assert(target.endpointCount == 2);
	assert(target.endpoints[0].lastSeenAtMs == 500);
	assert(target.endpoints[0].lastConfirmedAtMs == 450);
}

void testEnrichmentUpsertPreferredNameAndExpiry() {
	ScoutDeviceDetails details{};
	assert(
	    scout_internal::upsertName(
	        details,
	        ScoutNameSource::MdnsHostname,
	        "living-room-tv.local",
	        100,
	        1000
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(
	    scout_internal::upsertName(
	        details,
	        ScoutNameSource::SsdpFriendlyName,
	        "Living Room TV",
	        110,
	        1200
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);

	ScoutServiceInfo service{};
	service.source = ScoutObservationSource::Mdns;
	std::strcpy(service.type, "_airplay");
	std::strcpy(service.protocol, "_tcp");
	std::strcpy(service.instanceName, "Living Room TV");
	service.port = 7000;
	service.interfaceIndex = 1;
	service.lastSeenAtMs = 120;
	service.expiresAtMs = 900;
	assert(
	    scout_internal::upsertService(details, service) ==
	    scout_internal::EnrichmentUpsertResult::Changed
	);

	ScoutMetadataEntry metadata{};
	metadata.source = ScoutObservationSource::Mdns;
	std::strcpy(metadata.key, "model");
	std::strcpy(metadata.value, "TV123");
	metadata.lastSeenAtMs = 120;
	metadata.expiresAtMs = 900;
	assert(
	    scout_internal::upsertMetadata(details, metadata) ==
	    scout_internal::EnrichmentUpsertResult::Changed
	);

	ScoutPreferredName preferred{};
	assert(scout_internal::selectPreferredName(details, preferred));
	assert(preferred.source == ScoutNameSource::SsdpFriendlyName);
	assert(std::strcmp(preferred.value, "Living Room TV") == 0);

	const auto firstExpiry = scout_internal::expireEnrichment(details, 950);
	assert(
	    (scoutDeviceChangeMask(firstExpiry) &
	     scoutDeviceChangeMask(ScoutDeviceChange::Service)) != 0
	);
	assert(details.serviceCount == 0);
	assert(details.metadataCount == 0);
	assert(details.nameCount == 2);

	std::strcpy(details.upnpUdn, "uuid:ttl-device");
	details.upnpUdnSource = ScoutObservationSource::Ssdp;
	details.upnpUdnExpiresAtMs = 1250;
	std::strcpy(details.serialNumber, "SERIAL-TTL");
	details.serialNumberSource = ScoutObservationSource::Ssdp;
	details.serialNumberExpiresAtMs = 1250;

	const auto secondExpiry = scout_internal::expireEnrichment(details, 1300);
	assert(
	    (scoutDeviceChangeMask(secondExpiry) &
	     scoutDeviceChangeMask(ScoutDeviceChange::Name)) != 0
	);
	assert(
	    (scoutDeviceChangeMask(secondExpiry) &
	     scoutDeviceChangeMask(ScoutDeviceChange::Identity)) != 0
	);
	assert(details.nameCount == 0);
	assert(details.upnpUdn[0] == '\0');
	assert(details.serialNumber[0] == '\0');
}


void testDnsPtrCodec() {
	const uint8_t address[4] = {192, 168, 1, 42};
	uint8_t query[128]{};
	const uint16_t transactionId = 0x1234;
	const size_t queryLength =
	    scout_internal::buildPtrQuery(transactionId, address, query, sizeof(query));
	assert(queryLength > 20);
	assert(query[0] == 0x12 && query[1] == 0x34);
	assert(query[12] == 2 && query[13] == '4' && query[14] == '2');

	uint8_t response[256]{};
	std::memcpy(response, query, queryLength);
	response[2] = 0x81;
	response[3] = 0x80;
	response[6] = 0;
	response[7] = 1;
	size_t offset = queryLength;
	response[offset++] = 0xC0;
	response[offset++] = 0x0C;
	response[offset++] = 0;
	response[offset++] = 12;
	response[offset++] = 0;
	response[offset++] = 1;
	response[offset++] = 0;
	response[offset++] = 0;
	response[offset++] = 0;
	response[offset++] = 120;
	response[offset++] = 0;
	response[offset++] = 14;
	response[offset++] = 6;
	std::memcpy(response + offset, "device", 6);
	offset += 6;
	response[offset++] = 5;
	std::memcpy(response + offset, "local", 5);
	offset += 5;
	response[offset++] = 0;

	const auto parsed =
	    scout_internal::parsePtrResponse(response, offset, transactionId, address);
	assert(parsed.status == scout_internal::DnsParseStatus::Ok);
	assert(std::strcmp(parsed.hostname, "device.local") == 0);
	assert(parsed.ttlSeconds == 120);

	uint8_t shortRdata[256]{};
	std::memcpy(shortRdata, response, offset);
	shortRdata[queryLength + 10] = 0;
	shortRdata[queryLength + 11] = 1;
	const auto shortRdataResult =
	    scout_internal::parsePtrResponse(shortRdata, offset, transactionId, address);
	assert(shortRdataResult.status == scout_internal::DnsParseStatus::Malformed);

	uint8_t wrongQuestion[256]{};
	std::memcpy(wrongQuestion, response, offset);
	wrongQuestion[queryLength - 4] = 0;
	wrongQuestion[queryLength - 3] = 1;
	const auto wrongQuestionResult =
	    scout_internal::parsePtrResponse(wrongQuestion, offset, transactionId, address);
	assert(wrongQuestionResult.status == scout_internal::DnsParseStatus::Malformed);

	const uint8_t differentAddress[4] = {192, 168, 1, 43};
	const auto mismatchedQuestion =
	    scout_internal::parsePtrResponse(response, offset, transactionId, differentAddress);
	assert(mismatchedQuestion.status == scout_internal::DnsParseStatus::Malformed);

	response[3] = 0x83;
	const auto noRecord =
	    scout_internal::parsePtrResponse(response, offset, transactionId, address);
	assert(noRecord.status == scout_internal::DnsParseStatus::NoRecord);

	response[3] = 0x80;
	response[6] = 0;
	response[7] = 1;
	offset = queryLength;
	const size_t pointerOffset = offset;
	response[offset++] =
	    static_cast<uint8_t>(0xC0U | ((pointerOffset >> 8U) & 0x3FU));
	response[offset++] = static_cast<uint8_t>(pointerOffset & 0xFFU);
	const auto malformed =
	    scout_internal::parsePtrResponse(response, offset, transactionId, address);
	assert(malformed.status == scout_internal::DnsParseStatus::Malformed);
}

void testDnsACodec() {
	constexpr uint16_t TransactionId = 0xCAFE;
	uint8_t query[256]{};
	const size_t queryLength =
	    scout_internal::buildAQuery(TransactionId, "device.local", query, sizeof(query));
	assert(queryLength > 20);
	assert(query[0] == 0xCA && query[1] == 0xFE);

	uint8_t response[320]{};
	std::memcpy(response, query, queryLength);
	response[2] = 0x81;
	response[3] = 0x80;
	response[6] = 0;
	response[7] = 1;
	size_t offset = queryLength;
	response[offset++] = 0xC0;
	response[offset++] = 0x0C;
	response[offset++] = 0;
	response[offset++] = 1;
	response[offset++] = 0;
	response[offset++] = 1;
	response[offset++] = 0;
	response[offset++] = 0;
	response[offset++] = 0;
	response[offset++] = 60;
	response[offset++] = 0;
	response[offset++] = 4;
	response[offset++] = 192;
	response[offset++] = 168;
	response[offset++] = 1;
	response[offset++] = 42;

	const auto parsed =
	    scout_internal::parseAResponse(response, offset, TransactionId, "device.local");
	assert(parsed.status == scout_internal::DnsParseStatus::Ok);
	assert(parsed.addressCount == 1);
	const uint8_t expectedBytes[4] = {192, 168, 1, 42};
	uint32_t expected = 0;
	std::memcpy(&expected, expectedBytes, sizeof(expected));
	assert(parsed.addresses[0] == expected);
	assert(parsed.ttlSeconds == 60);

	const auto wrongName =
	    scout_internal::parseAResponse(response, offset, TransactionId, "other.local");
	assert(wrongName.status == scout_internal::DnsParseStatus::Malformed);
}

void testPersistentIdentityClaims() {
	ScoutDeviceDetails details{};
	assert(
	    scout_internal::upsertPersistentIdentity(
	        details,
	        "_hap._tcp",
	        "hap-1",
	        ScoutObservationSource::Mdns,
	        100,
	        500
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(
	    scout_internal::upsertPersistentIdentity(
	        details,
	        "_googlecast._tcp",
	        "cast-1",
	        ScoutObservationSource::Mdns,
	        110,
	        800
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(details.persistentIdentityCount == 2);
	assert(std::strcmp(details.persistentDeviceId, "cast-1") == 0);

	ScoutDeviceDetails rotating{};
	assert(
	    scout_internal::upsertPersistentIdentity(
	        rotating,
	        "_hap._tcp",
	        "hap-old",
	        ScoutObservationSource::Mdns,
	        100,
	        500
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(
	    scout_internal::upsertPersistentIdentity(
	        rotating,
	        "_hap._tcp",
	        "hap-old",
	        ScoutObservationSource::Mdns,
	        150,
	        600
	    ) == scout_internal::EnrichmentUpsertResult::Unchanged
	);
	assert(rotating.persistentIdentities[0].firstSeenAtMs == 100);
	assert(rotating.persistentIdentities[0].lastSeenAtMs == 150);
	assert(
	    scout_internal::upsertPersistentIdentity(
	        rotating,
	        "_hap._tcp",
	        "hap-new",
	        ScoutObservationSource::Mdns,
	        200,
	        700
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(rotating.persistentIdentities[0].firstSeenAtMs == 200);
	assert(rotating.persistentIdentities[0].lastSeenAtMs == 200);

	ScoutDeviceDetails sameHap{};
	(void)scout_internal::upsertPersistentIdentity(
	    sameHap,
	    "_hap._tcp",
	    "hap-1",
	    ScoutObservationSource::Mdns,
	    120,
	    500
	);
	ScoutIdentityRelation relation{};
	const ScoutDeviceInfo first = deviceWithMac(10);
	const ScoutDeviceInfo second = deviceWithMac(11);
	assert(scout_internal::identityRelation(first, details, second, sameHap, relation));
	assert(relation.evidence.type == ScoutIdentityEvidenceType::MdnsPersistentId);
	assert(relation.evidence.confidence == ScoutIdentityConfidence::Strong);

	ScoutDeviceDetails conflictingHap{};
	(void)scout_internal::upsertPersistentIdentity(
	    conflictingHap,
	    "_hap._tcp",
	    "hap-2",
	    ScoutObservationSource::Mdns,
	    120,
	    500
	);
	assert(scout_internal::identityDetailsContradict(details, conflictingHap));

	const ScoutDeviceChange changes = scout_internal::expireEnrichment(details, 600);
	assert(
	    (scoutDeviceChangeMask(changes) &
	     scoutDeviceChangeMask(ScoutDeviceChange::Identity)) != 0
	);
	assert(details.persistentIdentityCount == 1);
	assert(std::strcmp(details.persistentIdentities[0].nameSpace, "_googlecast._tcp") == 0);
}

void testPersistentIdentityMergeTimestamps() {
	ScoutDeviceDetails source{};
	assert(
	    scout_internal::upsertPersistentIdentity(
	        source,
	        "_hap._tcp",
	        "hap-new",
	        ScoutObservationSource::Mdns,
	        100,
	        900
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	assert(
	    scout_internal::upsertPersistentIdentity(
	        source,
	        "_hap._tcp",
	        "hap-new",
	        ScoutObservationSource::Mdns,
	        500,
	        1200
	    ) == scout_internal::EnrichmentUpsertResult::Unchanged
	);
	assert(source.persistentIdentities[0].firstSeenAtMs == 100);
	assert(source.persistentIdentities[0].lastSeenAtMs == 500);

	ScoutDeviceDetails merged{};
	scout_internal::mergeDeviceDetails(merged, source);
	assert(merged.persistentIdentityCount == 1);
	assert(std::strcmp(merged.persistentIdentities[0].id, "hap-new") == 0);
	assert(merged.persistentIdentities[0].firstSeenAtMs == 100);
	assert(merged.persistentIdentities[0].lastSeenAtMs == 500);

	ScoutDeviceDetails replaced{};
	assert(
	    scout_internal::upsertPersistentIdentity(
	        replaced,
	        "_hap._tcp",
	        "hap-old",
	        ScoutObservationSource::Mdns,
	        50,
	        700
	    ) == scout_internal::EnrichmentUpsertResult::Changed
	);
	scout_internal::mergeDeviceDetails(replaced, source);
	assert(replaced.persistentIdentityCount == 1);
	assert(std::strcmp(replaced.persistentIdentities[0].id, "hap-new") == 0);
	assert(replaced.persistentIdentities[0].firstSeenAtMs == 100);
	assert(replaced.persistentIdentities[0].lastSeenAtMs == 500);
}

void testSsdpAndUpnpParsing() {
	constexpr char Response[] =
	    "HTTP/1.1 200 OK\r\n"
	    "CACHE-CONTROL: max-age=1800\r\n"
	    "LOCATION: http://192.168.1.20:1400/device.xml\r\n"
	    "SERVER: Example/1.0 UPnP/1.1 Product/1.0\r\n"
	    "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
	    "USN: uuid:1234-5678::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";

	scout_internal::SsdpResponseInfo response{};
	assert(scout_internal::parseSsdpResponse(Response, sizeof(Response) - 1, response));
	assert(response.maxAgeSeconds == 1800);
	assert(std::strcmp(response.location, "http://192.168.1.20:1400/device.xml") == 0);
	assert(std::strstr(response.usn, "uuid:1234-5678") != nullptr);

	constexpr char ErrorResponse[] =
	    "HTTP/1.1 404 Not Found\r\n"
	    "LOCATION: http://192.168.1.20/device.xml\r\n\r\n";
	assert(!scout_internal::parseSsdpResponse(
	    ErrorResponse, sizeof(ErrorResponse) - 1, response
	));

	constexpr char NotifyPacket[] =
	    "NOTIFY * HTTP/1.1\r\n"
	    "USN: uuid:unexpected\r\n\r\n";
	assert(!scout_internal::parseSsdpResponse(
	    NotifyPacket, sizeof(NotifyPacket) - 1, response
	));

	constexpr char SentinelResponse[] =
	    "HTTP/1.0 200 OK\r\n"
	    "CACHE-CONTROL: max-age=999999999999999999999\r\n"
	    "LOCATION: http://192.168.1.20/device.xml\r\n"
	    "USN: uuid:sentinel\r\n"
	    "ST: (null)\r\n\r\n";
	assert(scout_internal::parseSsdpResponse(
	    SentinelResponse, sizeof(SentinelResponse) - 1, response
	));
	assert(response.searchTarget[0] == '\0');
	assert(response.maxAgeSeconds == 0);

	constexpr char Xml[] =
	    "<?xml version=\"1.0\"?><root><device>"
	    "<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
	    "<friendlyName>Living Room TV</friendlyName>"
	    "<manufacturer>Example Corp</manufacturer>"
	    "<modelName>Model X</modelName>"
	    "<modelNumber>42</modelNumber>"
	    "<serialNumber>SERIAL-1</serialNumber>"
	    "<UDN>uuid:1234-5678</UDN>"
	    "</device></root>";
	scout_internal::UpnpDescriptionInfo description{};
	assert(scout_internal::parseUpnpDescription(Xml, sizeof(Xml) - 1, description));
	assert(std::strcmp(description.friendlyName, "Living Room TV") == 0);
	assert(std::strcmp(description.manufacturer, "Example Corp") == 0);
	assert(std::strcmp(description.udn, "uuid:1234-5678") == 0);
}

void testNbnsParsing() {
	uint8_t response[64]{};
	constexpr uint16_t TransactionId = 0x4321;
	response[0] = 0x43;
	response[1] = 0x21;
	response[2] = 0x85;
	response[3] = 0x00;
	response[6] = 0;
	response[7] = 1;

	size_t offset = 12;
	response[offset++] = 0;
	response[offset++] = 0;
	response[offset++] = 0x21;
	response[offset++] = 0;
	response[offset++] = 1;
	offset += 4;
	response[offset++] = 0;
	response[offset++] = 19;
	response[offset++] = 1;
	uint8_t *entry = response + offset;
	std::memcpy(entry, "DESKTOP-ABC    ", 15);
	entry[15] = 0x00;
	entry[16] = 0x00;
	entry[17] = 0x00;
	offset += 18;

	char name[SCOUT_NAME_SIZE]{};
	assert(scout_internal::parseNbnsNodeStatusName(
	    response,
	    offset,
	    TransactionId,
	    name,
	    sizeof(name)
	));
	assert(std::strcmp(name, "DESKTOP-ABC") == 0);
	assert(!scout_internal::parseNbnsNodeStatusName(
	    response,
	    offset,
	    static_cast<uint16_t>(TransactionId + 1),
	    name,
	    sizeof(name)
	));

	response[2] = 0;
	assert(!scout_internal::parseNbnsNodeStatusName(
	    response,
	    offset,
	    TransactionId,
	    name,
	    sizeof(name)
	));
}

void testIdentityEvidenceAndContradictions() {
	const ScoutDeviceInfo first = deviceWithMac(1);
	const ScoutDeviceInfo second = deviceWithMac(2);
	ScoutDeviceDetails firstDetails{};
	ScoutDeviceDetails secondDetails{};
	ScoutIdentityRelation relation{};

	std::strcpy(firstDetails.upnpUdn, "uuid:same-device");
	std::strcpy(secondDetails.upnpUdn, "uuid:same-device");
	assert(scout_internal::identityRelation(
	    first,
	    firstDetails,
	    second,
	    secondDetails,
	    relation
	));
	assert(relation.evidence.type == ScoutIdentityEvidenceType::UpnpUdn);
	assert(relation.evidence.confidence == ScoutIdentityConfidence::Certain);

	firstDetails = ScoutDeviceDetails{};
	secondDetails = ScoutDeviceDetails{};
	scout_internal::upsertName(
	    firstDetails,
	    ScoutNameSource::MdnsHostname,
	    "same-host.local",
	    1,
	    0
	);
	scout_internal::upsertName(
	    secondDetails,
	    ScoutNameSource::MdnsHostname,
	    "same-host.local",
	    1,
	    0
	);
	assert(scout_internal::identityRelation(
	    first,
	    firstDetails,
	    second,
	    secondDetails,
	    relation
	));
	assert(relation.evidence.confidence == ScoutIdentityConfidence::Moderate);

	std::strcpy(firstDetails.persistentDeviceNamespace, "_hap._tcp");
	std::strcpy(secondDetails.persistentDeviceNamespace, "_hap._tcp");
	std::strcpy(firstDetails.persistentDeviceId, "id-a");
	std::strcpy(secondDetails.persistentDeviceId, "id-b");
	assert(scout_internal::identityDetailsContradict(firstDetails, secondDetails));
	assert(!scout_internal::identityRelation(
	    first,
	    firstDetails,
	    second,
	    secondDetails,
	    relation
	));

	std::strcpy(secondDetails.persistentDeviceNamespace, "_googlecast._tcp");
	std::strcpy(secondDetails.persistentDeviceId, "id-a");
	assert(scout_internal::identityRelation(
	    first,
	    firstDetails,
	    second,
	    secondDetails,
	    relation
	));
	assert(relation.evidence.confidence == ScoutIdentityConfidence::Moderate);

	ScoutDeviceKey members[2]{first.key, second.key};
	assert(scout_internal::identityGroupRuntimeId(members, 2) != 0);
}

void testDetailsMerge() {
	ScoutDeviceDetails first{};
	ScoutDeviceDetails second{};
	scout_internal::upsertName(
	    first,
	    ScoutNameSource::MdnsHostname,
	    "host.local",
	    100,
	    1000
	);
	scout_internal::upsertName(
	    second,
	    ScoutNameSource::SsdpFriendlyName,
	    "Kitchen Speaker",
	    110,
	    1000
	);
	std::strcpy(second.manufacturer, "Example");
	std::strcpy(second.modelName, "Speaker");
	std::strcpy(second.persistentDeviceId, "device-42");
	std::strcpy(second.persistentDeviceNamespace, "_hap._tcp");
	second.persistentDeviceIdSource = ScoutObservationSource::Mdns;
	second.persistentDeviceIdExpiresAtMs = 900;
	second.lastEnrichedAtMs = 110;

	scout_internal::mergeDeviceDetails(first, second);
	assert(first.nameCount == 2);
	assert(std::strcmp(first.manufacturer, "Example") == 0);
	assert(std::strcmp(first.modelName, "Speaker") == 0);
	assert(std::strcmp(first.persistentDeviceId, "device-42") == 0);
	assert(std::strcmp(first.persistentDeviceNamespace, "_hap._tcp") == 0);
	assert(first.lastEnrichedAtMs == 110);
}

} // namespace

int main() {
	testPublicDefaultsAndValueTypes();
	testMacHelpers();
	testIpv4TargetEnumerationAndBounds();
	testEndpointInsertRefreshAndCapacity();
	testEndpointIpv6RemovalAndExpiry();
	testMergeDeviceInfo();
	testEnrichmentUpsertPreferredNameAndExpiry();
	testDnsPtrCodec();
	testDnsACodec();
	testPersistentIdentityClaims();
	testPersistentIdentityMergeTimestamps();
	testSsdpAndUpnpParsing();
	testNbnsParsing();
	testIdentityEvidenceAndContradictions();
	testDetailsMerge();
	return 0;
}
