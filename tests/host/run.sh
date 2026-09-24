#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/.host-test-build"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

CXX="${CXX:-g++}"
CXX_FLAGS=(
  -std=c++20
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -fsanitize=address,undefined
  -fno-omit-frame-pointer
  -I"${ROOT_DIR}/tests/host/stubs"
  -I"${ROOT_DIR}/src"
)

"${CXX}" \
  "${CXX_FLAGS[@]}" \
  "${ROOT_DIR}/src/internal/ScoutLogic.cpp" \
  "${ROOT_DIR}/src/internal/ScoutEnrichment.cpp" \
  "${ROOT_DIR}/src/internal/ScoutDns.cpp" \
  "${ROOT_DIR}/tests/host/test_scout_logic.cpp" \
  -o "${BUILD_DIR}/scout-host-tests"

ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 \
  "${BUILD_DIR}/scout-host-tests"

"${CXX}" -I"${ROOT_DIR}/tests/host/runtime_stubs" "${CXX_FLAGS[@]}" -pthread \
  "${ROOT_DIR}/src/internal/ScoutLogic.cpp" \
  "${ROOT_DIR}/src/internal/ScoutEnrichment.cpp" \
  "${ROOT_DIR}/tests/host/test_scout_runtime.cpp" \
  -o "${BUILD_DIR}/scout-runtime-tests"

ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 \
  "${BUILD_DIR}/scout-runtime-tests"
