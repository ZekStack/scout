#pragma once

#include <Strata.h>

extern "C" {
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
}

#include <cstddef>
#include <cstdint>
#include <functional>

constexpr size_t SCOUT_MAX_ENDPOINTS_PER_DEVICE = 16;
constexpr size_t SCOUT_MAX_IPV6_PER_ENDPOINT = 8;
constexpr size_t SCOUT_MAX_NAMES_PER_DEVICE = 16;
constexpr size_t SCOUT_MAX_SERVICES_PER_DEVICE = 48;
constexpr size_t SCOUT_MAX_METADATA_PER_DEVICE = 96;
constexpr size_t SCOUT_MAX_IDENTITY_GROUP_MEMBERS = 8;
constexpr size_t SCOUT_MAX_IDENTITY_EVIDENCE = 24;
constexpr size_t SCOUT_MAX_PERSISTENT_IDENTITIES = 8;

constexpr size_t SCOUT_INTERFACE_NAME_SIZE = 8;
constexpr size_t SCOUT_INTERFACE_KEY_SIZE = 24;
constexpr size_t SCOUT_NAME_SIZE = 96;
constexpr size_t SCOUT_SERVICE_TYPE_SIZE = 48;
constexpr size_t SCOUT_SERVICE_PROTO_SIZE = 8;
constexpr size_t SCOUT_SERVICE_INSTANCE_SIZE = 96;
constexpr size_t SCOUT_HOSTNAME_SIZE = 96;
constexpr size_t SCOUT_METADATA_KEY_SIZE = 48;
constexpr size_t SCOUT_METADATA_VALUE_SIZE = 160;
constexpr size_t SCOUT_VENDOR_NAME_SIZE = 64;
constexpr size_t SCOUT_MANUFACTURER_SIZE = 96;
constexpr size_t SCOUT_MODEL_SIZE = 96;
constexpr size_t SCOUT_SERIAL_SIZE = 96;
constexpr size_t SCOUT_PERSISTENT_ID_SIZE = 128;
constexpr size_t SCOUT_PERSISTENT_NAMESPACE_SIZE = 64;
constexpr size_t SCOUT_UPNP_UDN_SIZE = 128;

enum class ScoutStatus : uint8_t {
	Ok,
	NotInitialized,
	AlreadyInitialized,
	InvalidConfig,
	NoMemory,
	TaskCreateFailed,
	Busy,
	WrongExecutionMode,
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

enum class ScoutExecutionMode : uint8_t {
	BackgroundTask,
	CallerDriven,
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
	ReverseDns = 1U << 6,
	Oui = 1U << 7,
};

constexpr ScoutObservationSource
operator|(ScoutObservationSource left, ScoutObservationSource right) {
	return static_cast<ScoutObservationSource>(
	    static_cast<uint32_t>(left) | static_cast<uint32_t>(right)
	);
}

constexpr uint32_t scoutObservationMask(ScoutObservationSource source) {
	return static_cast<uint32_t>(source);
}

enum class ScoutInterfaceType : uint8_t {
	Unknown,
	WifiStation,
	WifiAccessPoint,
	Ethernet,
	Custom,
};

enum class ScoutNameSource : uint8_t {
	None,
	MdnsHostname,
	MdnsInstance,
	SsdpFriendlyName,
	Nbns,
	ReverseDns,
	ManufacturerModel,
	Vendor,
};

enum class ScoutVendorSource : uint8_t {
	None,
	Oui,
	Ssdp,
	Mdns,
};

enum class ScoutIdentityEvidenceType : uint8_t {
	None,
	PersistentDeviceId,
	UpnpUdn,
	MdnsPersistentId,
	MdnsHostname,
	ServiceFingerprint,
	SharedSerialNumber,
	SharedManufacturerModel,
};

enum class ScoutIdentityConfidence : uint8_t {
	Weak,
	Moderate,
	Strong,
	Certain,
};

enum class ScoutDeviceChange : uint32_t {
	None = 0,
	Endpoint = 1U << 0,
	Name = 1U << 1,
	Service = 1U << 2,
	Metadata = 1U << 3,
	Vendor = 1U << 4,
	Identity = 1U << 5,
	Confirmation = 1U << 6,
	Address = 1U << 7,
};

constexpr ScoutDeviceChange operator|(ScoutDeviceChange left, ScoutDeviceChange right) {
	return static_cast<ScoutDeviceChange>(
	    static_cast<uint32_t>(left) | static_cast<uint32_t>(right)
	);
}

constexpr ScoutDeviceChange &operator|=(ScoutDeviceChange &left, ScoutDeviceChange right) {
	left = left | right;
	return left;
}

constexpr uint32_t scoutDeviceChangeMask(ScoutDeviceChange change) {
	return static_cast<uint32_t>(change);
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

struct ScoutIpv6Address {
	uint8_t bytes[16] = {};

	bool valid() const {
		for (uint8_t byte : bytes) {
			if (byte != 0) {
				return true;
			}
		}
		return false;
	}

	bool operator==(const ScoutIpv6Address &other) const {
		for (size_t i = 0; i < sizeof(bytes); ++i) {
			if (bytes[i] != other.bytes[i]) {
				return false;
			}
		}
		return true;
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

bool scoutFormatIpv4(const ScoutIpv4Address &address, char *out, size_t capacity);
bool scoutFormatIpv6(const ScoutIpv6Address &address, char *out, size_t capacity);
bool scoutFormatMac(const ScoutMacAddress &address, char *out, size_t capacity);

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
	ScoutIpv6Address ipv6[SCOUT_MAX_IPV6_PER_ENDPOINT]{};
	size_t ipv6Count = 0;

	uint8_t interfaceIndex = 0;
	char interfaceName[SCOUT_INTERFACE_NAME_SIZE] = {};
	char interfaceKey[SCOUT_INTERFACE_KEY_SIZE] = {};
	ScoutInterfaceType interfaceType = ScoutInterfaceType::Unknown;

	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t lastConfirmedAtMs = 0;
	uint32_t observationSources = 0;
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

struct ScoutDeviceName {
	ScoutNameSource source = ScoutNameSource::None;
	char value[SCOUT_NAME_SIZE] = {};
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t expiresAtMs = 0;
};

struct ScoutServiceInfo {
	ScoutObservationSource source = ScoutObservationSource::None;
	char type[SCOUT_SERVICE_TYPE_SIZE] = {};
	char protocol[SCOUT_SERVICE_PROTO_SIZE] = {};
	char instanceName[SCOUT_SERVICE_INSTANCE_SIZE] = {};
	char hostname[SCOUT_HOSTNAME_SIZE] = {};
	uint16_t port = 0;
	uint8_t interfaceIndex = 0;
	uint32_t ttlSeconds = 0;
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t expiresAtMs = 0;
};

struct ScoutMetadataEntry {
	ScoutObservationSource source = ScoutObservationSource::None;
	char key[SCOUT_METADATA_KEY_SIZE] = {};
	char value[SCOUT_METADATA_VALUE_SIZE] = {};
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t expiresAtMs = 0;
};

struct ScoutVendorInfo {
	bool known = false;
	ScoutVendorSource source = ScoutVendorSource::None;
	char name[SCOUT_VENDOR_NAME_SIZE] = {};
	ScoutObservationSource observationSource = ScoutObservationSource::None;
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t expiresAtMs = 0;
};

struct ScoutPersistentIdentity {
	char nameSpace[SCOUT_PERSISTENT_NAMESPACE_SIZE] = {};
	char id[SCOUT_PERSISTENT_ID_SIZE] = {};
	ScoutObservationSource source = ScoutObservationSource::None;
	uint64_t firstSeenAtMs = 0;
	uint64_t lastSeenAtMs = 0;
	uint64_t expiresAtMs = 0;
};

struct ScoutDeviceDetails {
	ScoutDeviceName names[SCOUT_MAX_NAMES_PER_DEVICE]{};
	size_t nameCount = 0;

	ScoutServiceInfo services[SCOUT_MAX_SERVICES_PER_DEVICE]{};
	size_t serviceCount = 0;

	ScoutMetadataEntry metadata[SCOUT_MAX_METADATA_PER_DEVICE]{};
	size_t metadataCount = 0;

	ScoutVendorInfo vendor{};
	bool locallyAdministeredMac = false;
	bool multicastMac = false;

	ScoutPersistentIdentity persistentIdentities[SCOUT_MAX_PERSISTENT_IDENTITIES]{};
	size_t persistentIdentityCount = 0;

	char manufacturer[SCOUT_MANUFACTURER_SIZE] = {};
	char modelName[SCOUT_MODEL_SIZE] = {};
	char modelNumber[SCOUT_MODEL_SIZE] = {};
	char serialNumber[SCOUT_SERIAL_SIZE] = {};
	char persistentDeviceId[SCOUT_PERSISTENT_ID_SIZE] = {};
	char persistentDeviceNamespace[SCOUT_PERSISTENT_NAMESPACE_SIZE] = {};
	char upnpUdn[SCOUT_UPNP_UDN_SIZE] = {};

	ScoutObservationSource manufacturerSource = ScoutObservationSource::None;
	ScoutObservationSource modelNameSource = ScoutObservationSource::None;
	ScoutObservationSource modelNumberSource = ScoutObservationSource::None;
	ScoutObservationSource serialNumberSource = ScoutObservationSource::None;
	ScoutObservationSource persistentDeviceIdSource = ScoutObservationSource::None;
	ScoutObservationSource upnpUdnSource = ScoutObservationSource::None;

	uint64_t manufacturerExpiresAtMs = 0;
	uint64_t modelNameExpiresAtMs = 0;
	uint64_t modelNumberExpiresAtMs = 0;
	uint64_t serialNumberExpiresAtMs = 0;
	uint64_t persistentDeviceIdExpiresAtMs = 0;
	uint64_t upnpUdnExpiresAtMs = 0;

	uint64_t lastEnrichedAtMs = 0;
};

struct ScoutPreferredName {
	ScoutNameSource source = ScoutNameSource::None;
	char value[SCOUT_NAME_SIZE] = {};
};

struct ScoutIdentityEvidence {
	ScoutIdentityEvidenceType type = ScoutIdentityEvidenceType::None;
	ScoutIdentityConfidence confidence = ScoutIdentityConfidence::Weak;
	ScoutObservationSource source = ScoutObservationSource::None;
};

struct ScoutIdentityRelation {
	ScoutDeviceKey first{};
	ScoutDeviceKey second{};
	ScoutIdentityEvidence evidence{};
};

struct ScoutIdentityGroup {
	uint64_t runtimeId = 0;
	ScoutDeviceKey members[SCOUT_MAX_IDENTITY_GROUP_MEMBERS]{};
	size_t memberCount = 0;
	ScoutIdentityConfidence confidence = ScoutIdentityConfidence::Weak;
	ScoutIdentityEvidence evidence[SCOUT_MAX_IDENTITY_EVIDENCE]{};
	size_t evidenceCount = 0;
};

enum class ScoutEventType : uint8_t {
	ScanStarted,
	ScanCompleted,
	ScanSkipped,
	DeviceDiscovered,
	DeviceObserved,
	DeviceChanged,
	DeviceExpired,
	IdentityGroupChanged,
	CoverageLost,
	CoverageRestored,
	Error,
};

struct ScoutEvent {
	ScoutEventType type = ScoutEventType::ScanStarted;
	ScoutStatus status = ScoutStatus::Ok;
	uint64_t scanId = 0;
	ScoutObservationSource source = ScoutObservationSource::None;
	uint32_t changes = 0;
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

struct ScoutIcmpConfig {
	bool enabled = true;
	uint32_t intervalMs = 60U * 1000U;
	uint32_t timeoutMs = 150;
	uint32_t taskStackBytes = 3072;
	UBaseType_t taskPriority = 1;
	size_t maxTargetsPerRun = 16;
};

struct ScoutMdnsConfig {
	bool enabled = true;
	bool initializeIfNeeded = true;
	uint32_t intervalMs = 2U * 60U * 1000U;
	uint32_t queryTimeoutMs = 3000;
	size_t maxResults = 128;
	size_t maxServiceTypes = 64;
	size_t maxServiceQueriesPerRun = 24;
	uint64_t fallbackMaxAgeMs = 10ULL * 60ULL * 1000ULL;
};

struct ScoutSsdpConfig {
	bool enabled = true;
	uint32_t intervalMs = 5U * 60U * 1000U;
	uint32_t responseWindowMs = 800;
	bool fetchDeviceDescription = true;
	uint32_t httpTimeoutMs = 400;
	size_t maxDescriptionBytes = 32U * 1024U;
	size_t maxDescriptionFetchesPerRun = 8;
	uint64_t fallbackMaxAgeMs = 30ULL * 60ULL * 1000ULL;
};

struct ScoutNbnsConfig {
	bool enabled = false;
	uint32_t intervalMs = 10U * 60U * 1000U;
	uint32_t responseWindowMs = 600;
	size_t maxTargetsPerRun = 256;
	uint64_t maxAgeMs = 30ULL * 60ULL * 1000ULL;
};

struct ScoutReverseDnsConfig {
	bool enabled = false;
	uint32_t intervalMs = 10U * 60U * 1000U;
	uint32_t timeoutMs = 500;
	size_t maxTargetsPerRun = 16;
	uint64_t maxAgeMs = 30ULL * 60ULL * 1000ULL;
};

struct ScoutProviderConfig {
	ScoutIcmpConfig icmp{};
	ScoutMdnsConfig mdns{};
	ScoutSsdpConfig ssdp{};
	ScoutNbnsConfig nbns{};
	ScoutReverseDnsConfig reverseDns{};
	bool oui = true;
};

struct ScoutExecutionConfig {
	ScoutExecutionMode mode = ScoutExecutionMode::BackgroundTask;
	uint32_t workBudgetMs = 1000;
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
	size_t maxIdentityRelations = 512;

	uint32_t taskStackBytes = 32U * 1024U;
	UBaseType_t taskPriority = 2;
	BaseType_t taskCore = tskNO_AFFINITY;

	bool scanOnInit = true;
	ScoutExecutionConfig execution{};
	ScoutProviderConfig providers{};
};

struct ScoutProviderDiagnostics {
	uint64_t runs = 0;
	uint64_t observations = 0;
	uint64_t errors = 0;
	uint64_t transportErrors = 0;
	uint64_t descriptionErrors = 0;
	uint64_t timeouts = 0;
	uint64_t noRecords = 0;
	uint64_t malformedResponses = 0;
	uint64_t serverErrors = 0;
	uint64_t droppedObservations = 0;
	uint64_t resolverUnavailable = 0;
	uint64_t identityConflicts = 0;
	uint64_t budgetYields = 0;
	uint64_t cancellations = 0;
};

struct ScoutDiagnostics {
	ScoutState state = ScoutState::Stopped;
	bool coverageAvailable = false;
	size_t activeInterfaceCount = 0;
	size_t deviceCount = 0;
	size_t peakDeviceCount = 0;
	size_t identityGroupCount = 0;
	size_t identityRelationCount = 0;

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
	uint64_t interfaceLimitDrops = 0;
	uint64_t providerTopologyRestarts = 0;
	uint64_t ssdpIdentityConflicts = 0;
	uint64_t dnsResolverUnavailable = 0;
	uint64_t metadataLimitDrops = 0;
	uint64_t nameLimitDrops = 0;
	uint64_t serviceLimitDrops = 0;
	uint64_t identityRelationDrops = 0;
	uint64_t identityContradictionBlocks = 0;
	uint64_t identityGroupMemberLimitDrops = 0;
	uint64_t identityGroupChanges = 0;
	uint64_t enrichmentAllocationFailures = 0;
	uint64_t staleProviderObservations = 0;
	uint64_t lastScanDurationMs = 0;
	uint64_t processCalls = 0;
	uint64_t processBudgetYields = 0;
	uint64_t cancellationYields = 0;
	uint64_t lastProcessDurationMs = 0;
	uint64_t maxProcessDurationMs = 0;
	ScoutExecutionMode executionMode = ScoutExecutionMode::BackgroundTask;

	ScoutProviderDiagnostics icmp{};
	ScoutProviderDiagnostics mdns{};
	ScoutProviderDiagnostics ssdp{};
	ScoutProviderDiagnostics nbns{};
	ScoutProviderDiagnostics reverseDns{};
	ScoutProviderDiagnostics oui{};

	Strata::Placement allocationPlacement = Strata::Placement::PreferExternal;
	Strata::Placement taskStackPlacement = Strata::Placement::PreferExternal;
	Strata::Region registryRegion = Strata::Region::Unknown;
	Strata::Region targetBufferRegion = Strata::Region::Unknown;
	Strata::Region enrichmentRegion = Strata::Region::Unknown;
	Strata::Region taskStackRegion = Strata::Region::Unknown;
	size_t taskStackHighWaterMarkBytes = 0;
};

using ScoutOuiLookupCallback = std::function<bool(const ScoutMacAddress &, ScoutVendorInfo &)>;
using ScoutDnsServerLookupCallback =
    std::function<bool(const char *interfaceKey, ScoutIpv4Address &server)>;

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
	ScoutResult process(uint32_t budgetMs = 0);
	uint32_t timeUntilNextWork() const;
	ScoutExecutionMode executionMode() const;

	bool isInitialized() const;
	bool running() const;
	ScoutState state() const;

	size_t deviceCount() const;
	ScoutResult deviceAt(size_t index, ScoutDeviceInfo &out) const;
	ScoutResult findByMac(const ScoutMacAddress &mac, ScoutDeviceInfo &out) const;

	ScoutResult deviceDetailsAt(size_t index, ScoutDeviceDetails &out) const;
	ScoutResult findDetailsByMac(const ScoutMacAddress &mac, ScoutDeviceDetails &out) const;
	ScoutResult preferredName(const ScoutMacAddress &mac, ScoutPreferredName &out) const;

	size_t identityGroupCount() const;
	ScoutResult identityGroupAt(size_t index, ScoutIdentityGroup &out) const;
	size_t identityRelationCount() const;
	ScoutResult identityRelationAt(size_t index, ScoutIdentityRelation &out) const;

	ScoutDiagnostics diagnostics() const;
	void onEvent(ScoutEventCallback callback);
	void setOuiLookup(ScoutOuiLookupCallback callback);
	void setDnsServerLookup(ScoutDnsServerLookupCallback callback);

	const char *statusToString(ScoutStatus status) const;
	const char *stateToString(ScoutState state) const;
	const char *eventTypeToString(ScoutEventType type) const;

  private:
	Strata::UniquePtr<ScoutImpl> _impl;
};
