#include <Arduino.h>
#include <Scout.h>

Scout scout;

void printDiagnostics() {
	const ScoutDiagnostics diag = scout.diagnostics();

	Serial.printf(
	    "state=%s coverage=%s interfaces=%u devices=%u peakDevices=%u\n",
	    scout.stateToString(diag.state),
	    diag.coverageAvailable ? "yes" : "no",
	    static_cast<unsigned>(diag.activeInterfaceCount),
	    static_cast<unsigned>(diag.deviceCount),
	    static_cast<unsigned>(diag.peakDeviceCount)
	);

	Serial.printf(
	    "scans=%llu completed=%llu skipped=%llu duration=%llums hosts=%llu\n",
	    static_cast<unsigned long long>(diag.scanCount),
	    static_cast<unsigned long long>(diag.completedScanCount),
	    static_cast<unsigned long long>(diag.skippedScanCount),
	    static_cast<unsigned long long>(diag.lastScanDurationMs),
	    static_cast<unsigned long long>(diag.hostsConsidered)
	);

	Serial.printf(
	    "arp sent=%llu failures=%llu cacheHits=%llu probeDiscoveries=%llu drops=%llu\n",
	    static_cast<unsigned long long>(diag.arpRequestsSent),
	    static_cast<unsigned long long>(diag.arpRequestFailures),
	    static_cast<unsigned long long>(diag.arpCacheHits),
	    static_cast<unsigned long long>(diag.arpProbeDiscoveries),
	    static_cast<unsigned long long>(diag.deviceLimitDrops)
	);

	Serial.printf(
	    "allocation requested=%s registry=%s targets=%s\n",
	    Strata::toString(diag.allocationPlacement),
	    Strata::toString(diag.registryRegion),
	    Strata::toString(diag.targetBufferRegion)
	);

	Serial.printf(
	    "task stack requested=%s actual=%s highWater=%u bytes\n",
	    Strata::toString(diag.taskStackPlacement),
	    Strata::toString(diag.taskStackRegion),
	    static_cast<unsigned>(diag.taskStackHighWaterMarkBytes)
	);
}

void setup() {
	Serial.begin(115200);

	ScoutConfig config;
	config.memory.allocation = Strata::Placement::PreferExternal;
	config.memory.taskStack = Strata::Placement::PreferExternal;

	const ScoutResult result = scout.init(config);
	if (!result) {
		Serial.printf("Scout init failed: %s\n", result.message);
	}
}

void loop() {
	delay(10000);
	printDiagnostics();
}
