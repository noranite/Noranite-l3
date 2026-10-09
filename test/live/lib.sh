#!/usr/bin/env bash

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CLIENT_BIN="${CLIENT_BIN:-${ROOT_DIR}/bin/opaque-client}"
SERVER_BIN="${SERVER_BIN:-${ROOT_DIR}/bin/opaque-server}"
PROXY_BIN="${PROXY_BIN:-${ROOT_DIR}/bin/opaque-live-proxy}"
KEYGEN_BIN="${KEYGEN_BIN:-${ROOT_DIR}/bin/opaque-keygen}"

LIVE_ID="${OL3_LIVE_ID:-$$}"
NS_CLIENT="ol3c-${LIVE_ID}"
NS_SERVER="ol3s-${LIVE_ID}"
VETH_CLIENT="oc${LIVE_ID}"
VETH_SERVER="os${LIVE_ID}"
CLIENT_TUN="nrnt0"
SERVER_TUN="nrnt0"

CLIENT_OUTER="192.0.2.2"
SERVER_OUTER="192.0.2.1"
CLIENT_TUNNEL="10.66.0.2"
SERVER_TUNNEL="10.66.0.1"
SERVER_PORT="51820"
PROXY_PORT="51821"
MTU="${OL3_MTU:-1420}"

LOG_DIR=""
ROUTE_KEY_FILE=""
SERVER_PRIVATE_KEY_FILE=""
SERVER_PUBLIC_KEY_FILE=""
CLIENT_PRIVATE_KEY_FILE=""
CLIENT_PUBLIC_KEY_FILE=""
SERVER_PEERS_FILE=""
CLIENT_PID=""
SERVER_PID=""
PROXY_PID=""
CLIENT_NS_CREATED=0
SERVER_NS_CREATED=0

require_live_prerequisites() {
	if (( EUID != 0 )); then
		echo "error: live network-namespace tests must run as root" >&2
		echo "run test/live/build.sh first as your normal user, then:" >&2
		echo "  sudo test/live/run-basic.sh" >&2
		return 1
	fi

	local command_name
	for command_name in ip ping grep mktemp; do
		if ! command -v "${command_name}" >/dev/null 2>&1; then
			echo "error: required command not found: ${command_name}" >&2
			return 1
		fi
	done

	if [[ ! -x "${CLIENT_BIN}" ]]; then
		echo "error: client binary not found or not executable: ${CLIENT_BIN}" >&2
		echo "run test/live/build.sh first" >&2
		return 1
	fi
	if [[ ! -x "${SERVER_BIN}" ]]; then
		echo "error: server binary not found or not executable: ${SERVER_BIN}" >&2
		echo "run test/live/build.sh first" >&2
		return 1
	fi
	if [[ ! -x "${KEYGEN_BIN}" ]]; then
		echo "error: keygen binary not found or not executable: ${KEYGEN_BIN}" >&2
		echo "run test/live/build.sh first" >&2
		return 1
	fi

	if [[ -n "${OL3_GOMAXPROCS:-}" && ! "${OL3_GOMAXPROCS}" =~ ^[1-9][0-9]*$ ]]; then
		echo "error: OL3_GOMAXPROCS must be a positive integer" >&2
		return 1
	fi

	if ((${#VETH_CLIENT} > 15 || ${#VETH_SERVER} > 15)); then
		echo "error: OL3_LIVE_ID is too long for Linux interface names: ${LIVE_ID}" >&2
		return 1
	fi
}

require_live_proxy_prerequisite() {
	if [[ ! -x "${PROXY_BIN}" ]]; then
		echo "error: live fault proxy not found or not executable: ${PROXY_BIN}" >&2
		echo "run test/live/build.sh first" >&2
		return 1
	fi
}

start_live_proxy() {
	local mode="$1"
	local target_response="${2:-2}"

	ip netns exec "${NS_CLIENT}" \
		"${PROXY_BIN}" \
		-listen "${CLIENT_OUTER}:${PROXY_PORT}" \
		-server "${SERVER_OUTER}:${SERVER_PORT}" \
		-route-key-file "${ROUTE_KEY_FILE}" \
		-mode "${mode}" \
		-target-response "${target_response}" \
		>"${LOG_DIR}/proxy.log" 2>&1 &
	PROXY_PID=$!

	wait_for_log "${LOG_DIR}/proxy.log" "proxy started:" "${PROXY_PID}" "live UDP fault proxy startup"
}

create_live_topology() {
	LOG_DIR="$(mktemp -d /tmp/opaque-l3-live.XXXXXX)"
	ROUTE_KEY_FILE="${LOG_DIR}/route.key"
	printf '%s\n' 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=' >"${ROUTE_KEY_FILE}"
	chmod 600 "${ROUTE_KEY_FILE}"
	SERVER_PRIVATE_KEY_FILE="${LOG_DIR}/server.private"
	SERVER_PUBLIC_KEY_FILE="${LOG_DIR}/server.public"
	CLIENT_PRIVATE_KEY_FILE="${LOG_DIR}/client.private"
	CLIENT_PUBLIC_KEY_FILE="${LOG_DIR}/client.public"
	SERVER_PEERS_FILE="${LOG_DIR}/server.peers"

	"${KEYGEN_BIN}" \
		-private-out "${SERVER_PRIVATE_KEY_FILE}" \
		-public-out "${SERVER_PUBLIC_KEY_FILE}" \
		>/dev/null
	"${KEYGEN_BIN}" \
		-private-out "${CLIENT_PRIVATE_KEY_FILE}" \
		-public-out "${CLIENT_PUBLIC_KEY_FILE}" \
		>/dev/null
	printf '%s %s\n' \
		"${CLIENT_TUNNEL}" \
		"$(tr -d '\r\n' <"${CLIENT_PUBLIC_KEY_FILE}")" \
		>"${SERVER_PEERS_FILE}"

	ip netns add "${NS_CLIENT}"
	CLIENT_NS_CREATED=1
	ip netns add "${NS_SERVER}"
	SERVER_NS_CREATED=1

	ip link add "${VETH_CLIENT}" type veth peer name "${VETH_SERVER}"
	ip link set "${VETH_CLIENT}" netns "${NS_CLIENT}"
	ip link set "${VETH_SERVER}" netns "${NS_SERVER}"

	ip -n "${NS_CLIENT}" link set lo up
	ip -n "${NS_SERVER}" link set lo up

	ip -n "${NS_CLIENT}" addr add "${CLIENT_OUTER}/24" dev "${VETH_CLIENT}"
	ip -n "${NS_SERVER}" addr add "${SERVER_OUTER}/24" dev "${VETH_SERVER}"
	ip -n "${NS_CLIENT}" link set "${VETH_CLIENT}" up
	ip -n "${NS_SERVER}" link set "${VETH_SERVER}" up
}

start_live_server() {
	local -a process_env=()
	if [[ -n "${OL3_GOMAXPROCS:-}" ]]; then
		process_env=(env "GOMAXPROCS=${OL3_GOMAXPROCS}")
	fi

	ip netns exec "${NS_SERVER}" \
		"${process_env[@]}" \
		"${SERVER_BIN}" \
		-tun "${SERVER_TUN}" \
		-mtu "${MTU}" \
		-bind "${SERVER_OUTER}:${SERVER_PORT}" \
		-route-key-file "${ROUTE_KEY_FILE}" \
		-private-key-file "${SERVER_PRIVATE_KEY_FILE}" \
		-peers-file "${SERVER_PEERS_FILE}" \
		-control-socket "${LOG_DIR}/control.sock" \
		>"${LOG_DIR}/server.log" 2>&1 &
	SERVER_PID=$!

	wait_for_link "${NS_SERVER}" "${SERVER_TUN}" "${SERVER_PID}" "server TUN"

	ip -n "${NS_SERVER}" addr add "${SERVER_TUNNEL}/32" dev "${SERVER_TUN}"
	ip -n "${NS_SERVER}" link set "${SERVER_TUN}" up
	ip -n "${NS_SERVER}" route add "${CLIENT_TUNNEL}/32" dev "${SERVER_TUN}"

	wait_for_log "${LOG_DIR}/server.log" "server started:" "${SERVER_PID}" "server startup"
}

start_live_client() {
	local server_endpoint="${1:-${SERVER_OUTER}:${SERVER_PORT}}"
	local -a process_env=()
	if [[ -n "${OL3_GOMAXPROCS:-}" ]]; then
		process_env=(env "GOMAXPROCS=${OL3_GOMAXPROCS}")
	fi

	ip netns exec "${NS_CLIENT}" \
		"${process_env[@]}" \
		"${CLIENT_BIN}" \
		-tun "${CLIENT_TUN}" \
		-mtu "${MTU}" \
		-tunnel-ip "${CLIENT_TUNNEL}" \
		-bind "${CLIENT_OUTER}:0" \
		-server "${server_endpoint}" \
		-route-key-file "${ROUTE_KEY_FILE}" \
		-private-key-file "${CLIENT_PRIVATE_KEY_FILE}" \
		-server-public-key "$(tr -d '\r\n' <"${SERVER_PUBLIC_KEY_FILE}")" \
		>"${LOG_DIR}/client.log" 2>&1 &
	CLIENT_PID=$!

	wait_for_link "${NS_CLIENT}" "${CLIENT_TUN}" "${CLIENT_PID}" "client TUN"

	ip -n "${NS_CLIENT}" addr add "${CLIENT_TUNNEL}/32" dev "${CLIENT_TUN}"
	ip -n "${NS_CLIENT}" link set "${CLIENT_TUN}" up
	ip -n "${NS_CLIENT}" route add "${SERVER_TUNNEL}/32" dev "${CLIENT_TUN}"

	wait_for_log "${LOG_DIR}/client.log" "client started:" "${CLIENT_PID}" "client startup"
}

wait_for_link() {
	local namespace="$1"
	local interface_name="$2"
	local process_pid="$3"
	local description="$4"
	local attempt

	for ((attempt = 0; attempt < 200; attempt++)); do
		if ip -n "${namespace}" link show dev "${interface_name}" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "${process_pid}" >/dev/null 2>&1; then
			echo "error: process exited while waiting for ${description}" >&2
			return 1
		fi
		sleep 0.05
	done

	echo "error: timed out waiting for ${description}" >&2
	return 1
}

wait_for_log() {
	local log_file="$1"
	local pattern="$2"
	local process_pid="$3"
	local description="$4"
	local attempt

	for ((attempt = 0; attempt < 200; attempt++)); do
		if grep -Fq -- "${pattern}" "${log_file}" 2>/dev/null; then
			return 0
		fi
		if ! kill -0 "${process_pid}" >/dev/null 2>&1; then
			echo "error: process exited while waiting for ${description}" >&2
			return 1
		fi
		sleep 0.05
	done

	echo "error: timed out waiting for ${description}" >&2
	return 1
}

assert_live_processes() {
	if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
		echo "error: server process is not running" >&2
		return 1
	fi
	if ! kill -0 "${CLIENT_PID}" >/dev/null 2>&1; then
		echo "error: client process is not running" >&2
		return 1
	fi
	if [[ -n "${PROXY_PID}" ]] && ! kill -0 "${PROXY_PID}" >/dev/null 2>&1; then
		echo "error: live UDP fault proxy is not running" >&2
		return 1
	fi
}

dump_live_logs() {
	if [[ -z "${LOG_DIR}" || ! -d "${LOG_DIR}" ]]; then
		return
	fi

	echo >&2
	echo "===== server.log =====" >&2
	cat "${LOG_DIR}/server.log" >&2 2>/dev/null || true
	echo >&2
	echo "===== client.log =====" >&2
	cat "${LOG_DIR}/client.log" >&2 2>/dev/null || true
	if [[ -f "${LOG_DIR}/proxy.log" ]]; then
		echo >&2
		echo "===== proxy.log =====" >&2
		cat "${LOG_DIR}/proxy.log" >&2 2>/dev/null || true
	fi
	echo >&2
}

cleanup_live_topology() {
	if [[ -n "${CLIENT_PID}" ]]; then
		kill "${CLIENT_PID}" >/dev/null 2>&1 || true
		wait "${CLIENT_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${PROXY_PID}" ]]; then
		kill "${PROXY_PID}" >/dev/null 2>&1 || true
		wait "${PROXY_PID}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${SERVER_PID}" ]]; then
		kill "${SERVER_PID}" >/dev/null 2>&1 || true
		wait "${SERVER_PID}" >/dev/null 2>&1 || true
	fi

	if (( CLIENT_NS_CREATED )); then
		ip netns del "${NS_CLIENT}" >/dev/null 2>&1 || true
	fi
	if (( SERVER_NS_CREATED )); then
		ip netns del "${NS_SERVER}" >/dev/null 2>&1 || true
	fi
}
