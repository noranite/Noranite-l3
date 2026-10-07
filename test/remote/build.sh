#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
mkdir -p "${BIN_DIR}"
cd "${ROOT_DIR}"

build_flags=()
if [[ "${OL3_RACE:-0}" == "1" ]]; then
	build_flags=(-race)
	echo "race instrumentation enabled for Opaque binaries"
fi

echo "building Opaque remote-test binaries..."
go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-server" ./cmd/opaque-server
go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-client" ./cmd/opaque-client
go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-live-proxy" ./test/live/udp-proxy
go build -o "${BIN_DIR}/opaque-keygen" ./cmd/opaque-keygen
go build -o "${BIN_DIR}/opaque-trafficgen" ./test/traffic/trafficgen

# Build the exact wireguard-go revision selected by this module's go.mod. This
# keeps the reference implementation pinned to the same source revision used by
# the code review and avoids a floating system package.
echo "building pinned wireguard-go reference..."
go build -o "${BIN_DIR}/wireguard-go" golang.zx2c4.com/wireguard

echo "built remote-test binaries in ${BIN_DIR}"
