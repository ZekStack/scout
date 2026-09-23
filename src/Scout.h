#pragma once

#include <Arduino.h>
#include <Strata.h>

#include <cstddef>
#include <cstdint>
#include <functional>

constexpr size_t SCOUT_MAX_ENDPOINTS_PER_DEVICE = 4;
constexpr size_t SCOUT_INTERFACE_NAME_SIZE = 8;

enum class ScoutStatus : uint8_t {
	Ok,
	NotInitialized,
	AlreadyInitialized,
	InvalidConfig,
	NoMemory,
	TaskCreateFailed,
	Busy,
	Cancelled,
	Timeout,
	NetworkUnavailable,
	DeviceLimitReached,
	InternalError,
	NotFound,
};

enum class ScoutState : uint8_t {
	Stopped,
	Starting,
	Running,
	Stopping,
};

enum class ScoutIdentityKind : uint8_t {
	Mac,
	ProvisionalIpv4,
};

enum class ScoutObservationSource : uint32_t {
	None = 0,
	ArpCache = 1U << 0,
	ArpProbe = 1U << 1,
	Icmp = 1U << 2,
	Mdns = 1U << 3,
	Ssdp = 1U << 4,
	Nbns = 1U << 5,
};

constexpr ScoutObservationSource operator|(
    ScoutObservationSource left,
    ScoutObservationSource right
) {
	return static_cast<ScoutObservationSource>(
	    static_cast<uint32_t>(left) | static_cast<uint32_t>(right)
	);
}

constexpr uint32_t scoutObservationMask(ScoutObservationSource source) {
	return static_cast<uint32_t>(source);
}

struct ScoutIpv4Address {
	uint32_t value = 0;

	bool valid() const {
		return value != 0;
	}

	bool operator==(const ScoutIpv4Address &other) const {
		return value == other.value;
	}

	bool operator!=(const ScoutIpv4Address &other) const {
		return !(*this == other);
	}
};

struct ScoutMacAddress {
	uint8_t bytes[6] = {0, 0, 0, 0, 0, 0};

	bool valid() const {
		for (uint8_t byte : bytes) {
			if (byte != 0) {
				return true;
			}
		}
		return false;
	}

	bool operator==(const ScoutMacAddress &other) const {
		for (size_t i = 0; i < sizeof(bytes); ++i) {
			if (bytes[i] != other.bytes[i]) {
				return false;
			}
		}
		return true;
	}

	bool operator!=(const ScoutMacAddress &other) const {
		return !(*this == other);
	}
};

struct ScoutDeviceKey {
	ScoutIdentityKind kind = ScoutIdentityKind::Mac;
	ScoutMacAddress mac{};
	ScoutIpv4Address ipv4{};

	bool operator==(const ScoutDeviceKey &other) const {
		if (kind != other.kind) {
			return false;
		}
		if (kind == ScoutIdentityKind::Mac) {
			return mac == other.mac;
		}
		return ipv4 == other.ipv4;
	}
};

struct ScoutEndpoint {
	ScoutIpv4Address ipv4{};
	uint8_t interfaceIndex = 0;
	char interfaceName[SCOUT_INTERFACE_NAME_SIZE] = {0};
	uint64_t lastSeenAtMs = 0;
};

struct ScoutDeviceInfo {
	ScoutDeviceKey key{};
	ScoutMacAddress mac{};
	ScoutEndpoint endpoints[SCOUT_MAX_ENDPOINTS_PER_DEVICE]{};
	size_t endpointCount = 0;
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t lastConfirmedAtMs = 0;
	uint32_t observationSources = 0;
	uint32_t observationCount = 0;
};

enum class ScoutEventType : uint8_t {
	ScanStarted,
	ScanCompleted,
	ScanSkipped,
	DeviceDiscovered,
	DeviceObserved,
	DeviceChanged,
	DeviceExpired,
	CoverageLost,
	CoverageRestored,
	Error,
};

struct ScoutEvent {
	ScoutEventType type = ScoutEventType::ScanStarted;
	ScoutStatus status = ScoutStatus::Ok;
	uint64_t scanId = 0;
	ScoutObservationSource source = ScoutObservationSource::None;
	bool hasDevice = false;
	ScoutDeviceInfo device{};
	const char *message = "ok";
};

using ScoutEventCallback = std::function<void(const ScoutEvent &)>;

struct ScoutResult {
	ScoutStatus status = ScoutStatus::Ok;
	const char *message = "ok";

	explicit operator bool() const {
		return status == ScoutStatus::Ok;
	}

	static ScoutResult success(const char *message = "ok");
	static ScoutResult failure(ScoutStatus status, const char *message);
};

struct ScoutConfig {
	Strata::MemoryPolicy memory{
	    .allocation = Strata::Placement::PreferExternal,
	    .taskStack = Strata::Placement::PreferExternal,
	};

	uint32_t scanIntervalMs = 60U * 1000U;
	uint64_t deviceMaxAgeMs = 5ULL * 60ULL * 1000ULL;
	uint32_t arpResponseWaitMs = 150;
	uint32_t interBatchDelayMs = 10;

	size_t maxDevices = 128;
	size_t maxHostsPerSubnet = 512;
	size_t arpBatchSize = 4;

	uint32_t taskStackBytes = 6144;
	UBaseType_t taskPriority = 2;
	BaseType_t taskCore = tskNO_AFFINITY;

	bool scanOnInit = true;
};

struct ScoutDiagnostics {
	ScoutState state = ScoutState::Stopped;
	bool coverageAvailable = false;
	size_t activeInterfaceCount = 0;
	size_t deviceCount = 0;
	size_t peakDeviceCount = 0;

	uint64_t scanCount = 0;
	uint64_t completedScanCount = 0;
	uint64_t skippedScanCount = 0;
	uint64_t hostsConsidered = 0;
	uint64_t arpRequestsSent = 0;
	uint64_t arpRequestFailures = 0;
	uint64_t arpCacheHits = 0;
	uint64_t arpProbeDiscoveries = 0;
	uint64_t deviceLimitDrops = 0;
	uint64_t expiredDeviceCount = 0;
	uint64_t deduplicatedDeviceCount = 0;
	uint64_t endpointReassignmentCount = 0;
	uint64_t lastScanDurationMs = 0;

	Strata::Placement allocationPlacement = Strata::Placement::PreferExternal;
	Strata::Placement taskStackPlacement = Strata::Placement::PreferExternal;
	Strata::Region registryRegion = Strata::Region::Unknown;
	Strata::Region targetBufferRegion = Strata::Region::Unknown;
	Strata::Region taskStackRegion = Strata::Region::Unknown;
	size_t taskStackHighWaterMarkBytes = 0;
};

struct ScoutImpl;

class Scout {
  public:
	Scout();
	~Scout();

	Scout(const Scout &) = delete;
	Scout &operator=(const Scout &) = delete;

	ScoutResult init(const ScoutConfig &config = ScoutConfig{});
	ScoutResult deinit(uint32_t timeoutMs = 5000);

	ScoutResult scanNow();

	bool isInitialized() const;
	bool running() const;
	ScoutState state() const;

	size_t deviceCount() const;
	ScoutResult deviceAt(size_t index, ScoutDeviceInfo &out) const;
	ScoutResult findByMac(const ScoutMacAddress &mac, ScoutDeviceInfo &out) const;

	ScoutDiagnostics diagnostics() const;
	void onEvent(ScoutEventCallback callback);

	const char *statusToString(ScoutStatus status) const;
	const char *stateToString(ScoutState state) const;
	const char *eventTypeToString(ScoutEventType type) const;

  private:
	Strata::UniquePtr<ScoutImpl> _impl;
};
