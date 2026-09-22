#include "internal/ScoutLogic.h"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace {

constexpr uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (static_cast<uint32_t>(a) << 24U) |
	       (static_cast<uint32_t>(b) << 16U) |
	       (static_cast<uint32_t>(c) << 8U) |
	       static_cast<uint32_t>(d);
}

void testPublicDefaultsAndValueTypes() {
	ScoutConfig config;
	assert(config.memory.allocation == Strata::Placement::PreferExternal);
	assert(config.memory.taskStack == Strata::Placement::PreferExternal);
	assert(config.scanOnInit);
	assert(config.maxDevices == 128);
	assert(config.maxHostsPerSubnet == 512);

	ScoutMacAddress empty;
	assert(!empty.valid());

	ScoutMacAddress mac{{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
	assert(mac.valid());

	ScoutDeviceKey macKey;
	macKey.kind = ScoutIdentityKind::Mac;
	macKey.mac = mac;

	ScoutDeviceKey sameMacKey = macKey;
	assert(macKey == sameMacKey);

	ScoutDeviceKey ipv4Key;
	ipv4Key.kind = ScoutIdentityKind::ProvisionalIpv4;
	ipv4Key.ipv4.value = ipv4(192, 168, 1, 20);
	assert(!(macKey == ipv4Key));

	const ScoutObservationSource combined =
	    ScoutObservationSource::ArpCache | ScoutObservationSource::ArpProbe;
	assert(
	    scoutObservationMask(combined) ==
	    (scoutObservationMask(ScoutObservationSource::ArpCache) |
	     scoutObservationMask(ScoutObservationSource::ArpProbe))
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
	assert(!scout_internal::macEquals(address, different));

	const ScoutMacAddress empty = scout_internal::macFromBytes(nullptr);
	assert(!empty.valid());
}

void testIpv4TargetEnumeration() {
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

	const auto pointToPoint = scout_internal::buildIpv4Targets(
	    ipv4(10, 0, 0, 1),
	    ipv4(255, 255, 255, 252),
	    8,
	    targets,
	    8
	);
	assert(pointToPoint.status == scout_internal::Ipv4TargetStatus::Ok);
	assert(pointToPoint.count == 1);
	assert(targets[0] == ipv4(10, 0, 0, 2));

	const auto slash31 = scout_internal::buildIpv4Targets(
	    ipv4(10, 0, 0, 0),
	    ipv4(255, 255, 255, 254),
	    8,
	    targets,
	    8
	);
	assert(slash31.status == scout_internal::Ipv4TargetStatus::Ok);
	assert(slash31.count == 0);

	const auto slash32 = scout_internal::buildIpv4Targets(
	    0xFFFFFFFFU,
	    0xFFFFFFFFU,
	    8,
	    targets,
	    8
	);
	assert(slash32.status == scout_internal::Ipv4TargetStatus::Ok);
	assert(slash32.count == 0);
}

void testIpv4TargetBounds() {
	uint32_t targets[512]{};

	const auto tooLarge = scout_internal::buildIpv4Targets(
	    ipv4(10, 1, 2, 3),
	    ipv4(255, 255, 0, 0),
	    512,
	    targets,
	    512
	);
	assert(tooLarge.status == scout_internal::Ipv4TargetStatus::TooLarge);
	assert(tooLarge.count == 0);

	const auto capacityTooSmall = scout_internal::buildIpv4Targets(
	    ipv4(192, 168, 1, 10),
	    ipv4(255, 255, 255, 0),
	    512,
	    targets,
	    128
	);
	assert(capacityTooSmall.status == scout_internal::Ipv4TargetStatus::TooLarge);

	const auto invalidLimit = scout_internal::buildIpv4Targets(
	    ipv4(192, 168, 1, 10),
	    ipv4(255, 255, 255, 0),
	    0,
	    targets,
	    512
	);
	assert(invalidLimit.status == scout_internal::Ipv4TargetStatus::InvalidArgument);

	const auto nullOutput = scout_internal::buildIpv4Targets(
	    ipv4(192, 168, 1, 10),
	    ipv4(255, 255, 255, 0),
	    512,
	    nullptr,
	    512
	);
	assert(nullOutput.status == scout_internal::Ipv4TargetStatus::InvalidArgument);
}

void testEndpointInsertAndRefresh() {
	ScoutDeviceInfo device;

	assert(scout_internal::upsertEndpoint(device, 1, "en0", 0x01020304U, 100));
	assert(device.endpointCount == 1);
	assert(device.endpoints[0].interfaceIndex == 1);
	assert(device.endpoints[0].ipv4.value == 0x01020304U);
	assert(device.endpoints[0].lastSeenAtMs == 100);
	assert(std::strcmp(device.endpoints[0].interfaceName, "en0") == 0);

	assert(!scout_internal::upsertEndpoint(device, 1, "en0", 0x01020304U, 250));
	assert(device.endpointCount == 1);
	assert(device.endpoints[0].lastSeenAtMs == 250);

	assert(scout_internal::upsertEndpoint(device, 2, "wl0", 0x01020304U, 300));
	assert(device.endpointCount == 2);
	assert(device.endpoints[1].interfaceIndex == 2);
}

void testEndpointCapacityReplacesOldest() {
	ScoutDeviceInfo device;

	assert(scout_internal::upsertEndpoint(device, 1, "if1", 1, 100));
	assert(scout_internal::upsertEndpoint(device, 2, "if2", 2, 400));
	assert(scout_internal::upsertEndpoint(device, 3, "if3", 3, 300));
	assert(scout_internal::upsertEndpoint(device, 4, "if4", 4, 200));
	assert(device.endpointCount == SCOUT_MAX_ENDPOINTS_PER_DEVICE);

	assert(scout_internal::upsertEndpoint(
	    device,
	    5,
	    "interface-name-is-long",
	    5,
	    500
	));
	assert(device.endpointCount == SCOUT_MAX_ENDPOINTS_PER_DEVICE);

	bool foundNew = false;
	bool foundOldest = false;
	for (size_t i = 0; i < device.endpointCount; ++i) {
		if (device.endpoints[i].interfaceIndex == 5) {
			foundNew = true;
			assert(device.endpoints[i].lastSeenAtMs == 500);
			assert(device.endpoints[i].interfaceName[SCOUT_INTERFACE_NAME_SIZE - 1] == '\0');
			assert(std::strcmp(device.endpoints[i].interfaceName, "interfa") == 0);
		}
		if (device.endpoints[i].interfaceIndex == 1) {
			foundOldest = true;
		}
	}

	assert(foundNew);
	assert(!foundOldest);
}

} // namespace

int main() {
	testPublicDefaultsAndValueTypes();
	testMacHelpers();
	testIpv4TargetEnumeration();
	testIpv4TargetBounds();
	testEndpointInsertAndRefresh();
	testEndpointCapacityReplacesOldest();
	return 0;
}
