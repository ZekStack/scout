#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def require(path: str, needle: str, message: str) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    if needle not in text:
        raise SystemExit(message)


def reject_tree(needle: str, message: str) -> None:
    for path in SRC.rglob("*"):
        if not path.is_file() or path.suffix not in {".h", ".hpp", ".c", ".cc", ".cpp"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if needle in text:
            raise SystemExit(f"{message}: {path.relative_to(ROOT)}")


require(
    "library.json",
    '"Strata": "https://github.com/ZekStack/strata.git#v0.1.3"',
    "Scout must pin released Strata v0.1.3",
)
require(
    "src/Scout.h",
    ".allocation = Strata::Placement::PreferExternal",
    "Scout allocations must prefer external memory by default",
)
require(
    "src/Scout.h",
    ".taskStack = Strata::Placement::PreferExternal",
    "Scout task stack must prefer external memory by default",
)
require(
    "src/Scout.cpp",
    "Strata::FreeRTOS::Task::create(",
    "Scout task ownership must route through Strata",
)
require(
    "src/Scout.cpp",
    "Strata::allocateArray<ScoutDeviceRecord>",
    "Scout registry must route through Strata",
)
require(
    "src/internal/ScoutNetwork.cpp",
    "esp_netif_tcpip_exec(",
    "direct lwIP operations must execute through ESP-NETIF TCP/IP context",
)

for forbidden, message in (
    ("heap_caps_", "Scout must not call ESP-IDF heap capability allocation directly"),
    ("MALLOC_CAP_", "Scout must not encode ESP-IDF heap capabilities directly"),
    ("ps_malloc", "Scout must not allocate PSRAM directly"),
    ("xTaskCreate(", "Scout-owned task creation must not bypass Strata"),
    ("xTaskCreatePinnedToCore(", "Scout-owned pinned task creation must not bypass Strata"),
    ("xSemaphoreCreate", "Scout-owned synchronization creation must not bypass Strata"),
    ("xQueueCreate", "Scout-owned queue creation must not bypass Strata"),
):
    reject_tree(forbidden, message)

print("Scout Strata integration source contract is valid")
