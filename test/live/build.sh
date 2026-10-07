#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"

mkdir -p "${BIN_DIR}"

cd "${ROOT_DIR}"

echo "building live-test binaries..."
build_flags=()
if [[ "${OL3_RACE:-0}" == "1" ]]; then
	build_flags=(-race)
	echo "race instrumentation enabled"
fi

go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-server" ./cmd/opaque-server
go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-client" ./cmd/opaque-client
go build "${build_flags[@]}" -o "${BIN_DIR}/opaque-live-proxy" ./test/live/udp-proxy
go build -o "${BIN_DIR}/opaque-keygen" ./cmd/opaque-keygen
go build -o "${BIN_DIR}/opaque-trafficgen" ./test/traffic/trafficgen

echo "built:"
echo "  ${BIN_DIR}/opaque-server"
echo "  ${BIN_DIR}/opaque-client"
echo "  ${BIN_DIR}/opaque-live-proxy"
echo "  ${BIN_DIR}/opaque-keygen"
echo "  ${BIN_DIR}/opaque-trafficgen"
