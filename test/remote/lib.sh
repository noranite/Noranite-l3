#!/usr/bin/env bash

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CLIENT_BIN="${CLIENT_BIN:-${ROOT_DIR}/bin/opaque-client}"
SERVER_BIN="${SERVER_BIN:-${ROOT_DIR}/bin/opaque-server}"
KEYGEN_BIN="${KEYGEN_BIN:-${ROOT_DIR}/bin/opaque-keygen}"
PROXY_BIN="${PROXY_BIN:-${ROOT_DIR}/bin/opaque-live-proxy}"
TRAFFIC_BIN="${TRAFFIC_BIN:-${ROOT_DIR}/bin/opaque-trafficgen}"
WG_GO_BIN="${WG_GO_BIN:-${ROOT_DIR}/bin/wireguard-go}"

SERVER_SSH="${OL3_SERVER_SSH:-}"
SERVER_OUTER="${OL3_SERVER_OUTER:-}"
SERVER_BIND="${OL3_SERVER_BIND:-0.0.0.0}"
SERVER_PORT="${OL3_SERVER_PORT:-51820}"
WG_PORT="${OL3_WG_PORT:-51822}"
MTU="${OL3_MTU:-1420}"
NAMESPACE_PREFIX="${OL3_NAMESPACE_PREFIX:-198.18.77}"
SERVER_TUNNEL="${OL3_SERVER_TUNNEL:-10.88.0.1}"
TUNNEL_PREFIX="${OL3_TUNNEL_PREFIX:-10.88.0}"
OPAQUE_GODEBUG="${OL3_GODEBUG:-}"

REMOTE_ID="${OL3_REMOTE_ID:-$$}"
BRIDGE="ob${REMOTE_ID}"
REMOTE_DIR="/tmp/opaque-l3-remote.${REMOTE_ID}"
STATE_DIR=""
RESULT_DIR=""
EGRESS_IFACE=""
ORIGINAL_FORWARD=""
NAT_INSTALLED=0
FORWARD_INSTALLED=0
BRIDGE_CREATED=0
PEER_COUNT=0

REMOTE_SERVER_PID=""
REMOTE_WG_PID=""
PROXY_PID=""
declare -a CLIENT_PIDS=()
declare -a WG_CLIENT_PIDS=()
declare -a NAMESPACES=()
declare -a HOST_VETHS=()

remote() {
	ssh -o BatchMode=yes "${SERVER_SSH}" "$@"
}

remote_shell() {
	local command="$1"
	remote "bash -lc $(printf '%q' "${command}")"
}

client_namespace() {
	local index="$1"
	printf 'ol3r-%s-%02d' "${REMOTE_ID}" "${index}"
}

client_outer_ip() {
	local index="$1"
	printf '%s.%d' "${NAMESPACE_PREFIX}" "$((10 + index))"
}

client_tunnel_ip() {
	local index="$1"
	printf '%s.%d' "${TUNNEL_PREFIX}" "$((1 + index))"
}

wg_client_interface() {
	local index="$1"
	printf 'wgc%02d' "${index}"
}

require_remote_prerequisites() {
	if (( EUID != 0 )); then
		echo "error: remote tests must run as root on the client host" >&2
		return 1
	fi
	if [[ -z "${SERVER_SSH}" || -z "${SERVER_OUTER}" ]]; then
		echo "error: OL3_SERVER_SSH and OL3_SERVER_OUTER are required" >&2
		return 1
	fi
	if ((${#BRIDGE} > 15)); then
		echo "error: OL3_REMOTE_ID is too long for Linux interface names: ${REMOTE_ID}" >&2
		return 1
	fi

	local command_name
	for command_name in ip iptables ping ssh scp wg iperf3 python3 grep awk sed mktemp; do
		if ! command -v "${command_name}" >/dev/null 2>&1; then
			echo "error: required client-host command not found: ${command_name}" >&2
			return 1
		fi
	done
	for command_name in "${CLIENT_BIN}" "${SERVER_BIN}" "${KEYGEN_BIN}" "${PROXY_BIN}" "${TRAFFIC_BIN}" "${WG_GO_BIN}"; do
		if [[ ! -x "${command_name}" ]]; then
			echo "error: required binary not found or not executable: ${command_name}" >&2
			return 1
		fi
	done

	if ! remote_shell 'test "$(id -u)" -eq 0 && command -v ip >/dev/null && command -v ping >/dev/null && command -v iperf3 >/dev/null && command -v wg >/dev/null'; then
		echo "error: remote host must be root and provide ip, ping, iperf3, and wg" >&2
		return 1
	fi

	EGRESS_IFACE="${OL3_CLIENT_EGRESS_IFACE:-$(ip -o route get "${SERVER_OUTER}" | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')}"
	if [[ -z "${EGRESS_IFACE}" ]]; then
		echo "error: could not determine client egress interface to ${SERVER_OUTER}" >&2
		return 1
	fi
}

prepare_remote_workspace() {
	STATE_DIR="$(mktemp -d /tmp/opaque-l3-remote-state.XXXXXX)"
	RESULT_DIR="${OL3_RESULT_DIR:-${ROOT_DIR}/test-results/remote-${REMOTE_ID}}"
	mkdir -p "${RESULT_DIR}"

	remote_shell "rm -rf '${REMOTE_DIR}' && mkdir -p '${REMOTE_DIR}'"
	scp -q \
		"${SERVER_BIN}" \
		"${TRAFFIC_BIN}" \
		"${WG_GO_BIN}" \
		"${SERVER_SSH}:${REMOTE_DIR}/"
}

generate_opaque_keys() {
	local peers="$1"
	PEER_COUNT="${peers}"
	printf '%s\n' 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=' >"${STATE_DIR}/route.key"
	chmod 600 "${STATE_DIR}/route.key"
	"${KEYGEN_BIN}" \
		-private-out "${STATE_DIR}/server.private" \
		-public-out "${STATE_DIR}/server.public" \
		>/dev/null
	: >"${STATE_DIR}/server.peers"

	local index
	for ((index = 1; index <= peers; index++)); do
		"${KEYGEN_BIN}" \
			-private-out "${STATE_DIR}/client-${index}.private" \
			-public-out "${STATE_DIR}/client-${index}.public" \
			>/dev/null
		printf '%s %s\n' \
			"$(client_tunnel_ip "${index}")" \
			"$(tr -d '\r\n' <"${STATE_DIR}/client-${index}.public")" \
			>>"${STATE_DIR}/server.peers"
	done

	scp -q \
		"${STATE_DIR}/route.key" \
		"${STATE_DIR}/server.private" \
		"${STATE_DIR}/server.peers" \
		"${SERVER_SSH}:${REMOTE_DIR}/"
}

generate_wg_keys() {
	local peers="$1"
	umask 077
	wg genkey >"${STATE_DIR}/wg-server.private"
	wg pubkey <"${STATE_DIR}/wg-server.private" >"${STATE_DIR}/wg-server.public"
	local index
	for ((index = 1; index <= peers; index++)); do
		wg genkey >"${STATE_DIR}/wg-client-${index}.private"
		wg pubkey <"${STATE_DIR}/wg-client-${index}.private" >"${STATE_DIR}/wg-client-${index}.public"
	done
	scp -q "${STATE_DIR}/wg-server.private" "${SERVER_SSH}:${REMOTE_DIR}/"
}

create_client_outer_topology() {
	local peers="$1"
	PEER_COUNT="${peers}"
	ORIGINAL_FORWARD="$(sysctl -n net.ipv4.ip_forward)"
	sysctl -q -w net.ipv4.ip_forward=1

	ip link add "${BRIDGE}" type bridge
	BRIDGE_CREATED=1
	ip addr add "${NAMESPACE_PREFIX}.1/24" dev "${BRIDGE}"
	ip link set "${BRIDGE}" up

	iptables -t nat -A POSTROUTING -s "${NAMESPACE_PREFIX}.0/24" -o "${EGRESS_IFACE}" -j MASQUERADE
	NAT_INSTALLED=1
	iptables -A FORWARD -i "${BRIDGE}" -o "${EGRESS_IFACE}" -j ACCEPT
	iptables -A FORWARD -i "${EGRESS_IFACE}" -o "${BRIDGE}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	FORWARD_INSTALLED=1

	local index namespace host_veth
	for ((index = 1; index <= peers; index++)); do
		namespace="$(client_namespace "${index}")"
		host_veth="oh${REMOTE_ID}${index}"
		if ((${#host_veth} > 15)); then
			echo "error: generated veth name is too long: ${host_veth}" >&2
			return 1
		fi
		NAMESPACES+=("${namespace}")
		HOST_VETHS+=("${host_veth}")
		ip netns add "${namespace}"
		ip link add "${host_veth}" type veth peer name eth0 netns "${namespace}"
		ip link set "${host_veth}" master "${BRIDGE}"
		ip link set "${host_veth}" up
		ip -n "${namespace}" link set lo up
		ip -n "${namespace}" addr add "$(client_outer_ip "${index}")/24" dev eth0
		ip -n "${namespace}" link set eth0 up
		ip -n "${namespace}" route add default via "${NAMESPACE_PREFIX}.1"
	done
}

wait_local_link() {
	local namespace="$1"
	local interface_name="$2"
	local pid="$3"
	local attempt
	for ((attempt = 0; attempt < 200; attempt++)); do
		if ip -n "${namespace}" link show dev "${interface_name}" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "${pid}" >/dev/null 2>&1; then
			return 1
		fi
		sleep 0.05
	done
	return 1
}

wait_remote_link() {
	local interface_name="$1"
	local attempt
	for ((attempt = 0; attempt < 200; attempt++)); do
		if remote_shell "ip link show dev '${interface_name}' >/dev/null 2>&1"; then
			return 0
		fi
		sleep 0.05
	done
	return 1
}

start_opaque_server() {
	local env_prefix=""
	if [[ -n "${OPAQUE_GODEBUG}" ]]; then
		env_prefix="env GODEBUG=$(printf '%q' "${OPAQUE_GODEBUG}") "
	fi
	REMOTE_SERVER_PID="$(remote_shell "cd '${REMOTE_DIR}'; nohup ${env_prefix}./opaque-server -tun nrnt0 -mtu '${MTU}' -bind '${SERVER_BIND}:${SERVER_PORT}' -route-key-file route.key -private-key-file server.private -peers-file server.peers -control-socket '${REMOTE_DIR}/control.sock' >opaque-server.log 2>&1 < /dev/null & echo \$!")"
	if ! wait_remote_link nrnt0; then
		remote_shell "cat '${REMOTE_DIR}/opaque-server.log' >&2 || true"
		return 1
	fi
	remote_shell "ip addr add '${SERVER_TUNNEL}/24' dev nrnt0; ip link set dev nrnt0 mtu '${MTU}' up"
}

start_opaque_clients() {
	local peers="$1"
	local server_endpoint="${2:-${SERVER_OUTER}:${SERVER_PORT}}"
	CLIENT_PIDS=()
	local server_public
	server_public="$(tr -d '\r\n' <"${STATE_DIR}/server.public")"

	local index namespace pid
	for ((index = 1; index <= peers; index++)); do
		namespace="$(client_namespace "${index}")"
		local -a process_env=()
		if [[ -n "${OPAQUE_GODEBUG}" ]]; then
			process_env=(env "GODEBUG=${OPAQUE_GODEBUG}")
		fi
		ip netns exec "${namespace}" \
			"${process_env[@]}" \
			"${CLIENT_BIN}" \
			-tun nrnt0 \
			-mtu "${MTU}" \
			-tunnel-ip "$(client_tunnel_ip "${index}")" \
			-bind "$(client_outer_ip "${index}"):0" \
			-server "${server_endpoint}" \
			-route-key-file "${STATE_DIR}/route.key" \
			-private-key-file "${STATE_DIR}/client-${index}.private" \
			-server-public-key "${server_public}" \
			>"${STATE_DIR}/opaque-client-${index}.log" 2>&1 &
		pid=$!
		CLIENT_PIDS+=("${pid}")
		if ! wait_local_link "${namespace}" nrnt0 "${pid}"; then
			cat "${STATE_DIR}/opaque-client-${index}.log" >&2 || true
			return 1
		fi
		ip -n "${namespace}" addr add "$(client_tunnel_ip "${index}")/32" dev nrnt0
		ip -n "${namespace}" link set dev nrnt0 mtu "${MTU}" up
		ip -n "${namespace}" route add "${SERVER_TUNNEL}/32" dev nrnt0
	done
}

wait_opaque_ready() {
	local peers="$1"
	local index namespace
	for ((index = 1; index <= peers; index++)); do
		namespace="$(client_namespace "${index}")"
		ip netns exec "${namespace}" ping -n -c 2 -W 2 "${SERVER_TUNNEL}" >/dev/null
	done
	for ((index = 1; index <= peers; index++)); do
		remote_shell "ping -n -c 1 -W 2 '$(client_tunnel_ip "${index}")' >/dev/null"
	done
}

stop_opaque() {
	local pid
	for pid in "${CLIENT_PIDS[@]:-}"; do
		[[ -n "${pid}" ]] || continue
		kill "${pid}" >/dev/null 2>&1 || true
		wait "${pid}" >/dev/null 2>&1 || true
	done
	CLIENT_PIDS=()
	if [[ -n "${PROXY_PID}" ]]; then
		kill "${PROXY_PID}" >/dev/null 2>&1 || true
		wait "${PROXY_PID}" >/dev/null 2>&1 || true
		PROXY_PID=""
	fi
	if [[ -n "${REMOTE_SERVER_PID}" ]]; then
		remote_shell "kill '${REMOTE_SERVER_PID}' >/dev/null 2>&1 || true; sleep 0.1; ip link del nrnt0 >/dev/null 2>&1 || true"
		REMOTE_SERVER_PID=""
	fi
}

start_fault_proxy() {
	local mode="$1"
	local namespace
	namespace="$(client_namespace 1)"
	ip netns exec "${namespace}" \
		"${PROXY_BIN}" \
		-listen "$(client_outer_ip 1):51821" \
		-server "${SERVER_OUTER}:${SERVER_PORT}" \
		-route-key-file "${STATE_DIR}/route.key" \
		-mode "${mode}" \
		-target-response 2 \
		>"${STATE_DIR}/proxy.log" 2>&1 &
	PROXY_PID=$!
	local attempt
	for ((attempt = 0; attempt < 200; attempt++)); do
		if grep -Fq -- "proxy started:" "${STATE_DIR}/proxy.log" 2>/dev/null; then
			return 0
		fi
		if ! kill -0 "${PROXY_PID}" >/dev/null 2>&1; then
			return 1
		fi
		sleep 0.05
	done
	return 1
}

start_wg_server() {
	REMOTE_WG_PID="$(remote_shell "cd '${REMOTE_DIR}'; nohup ./wireguard-go -f wgs0 >wg-server.log 2>&1 < /dev/null & echo \$!")"
	if ! wait_remote_link wgs0; then
		remote_shell "cat '${REMOTE_DIR}/wg-server.log' >&2 || true"
		return 1
	fi
	remote_shell "wg set wgs0 private-key '${REMOTE_DIR}/wg-server.private' listen-port '${WG_PORT}'; ip addr add '${SERVER_TUNNEL}/24' dev wgs0; ip link set dev wgs0 mtu '${MTU}' up"
	local index peer_public
	for ((index = 1; index <= PEER_COUNT; index++)); do
		peer_public="$(tr -d '\r\n' <"${STATE_DIR}/wg-client-${index}.public")"
		remote_shell "wg set wgs0 peer '${peer_public}' allowed-ips '$(client_tunnel_ip "${index}")/32'"
	done
}

start_wg_clients() {
	local peers="$1"
	WG_CLIENT_PIDS=()
	local server_public
	server_public="$(tr -d '\r\n' <"${STATE_DIR}/wg-server.public")"
	local index namespace interface_name pid
	for ((index = 1; index <= peers; index++)); do
		namespace="$(client_namespace "${index}")"
		interface_name="$(wg_client_interface "${index}")"
		ip netns exec "${namespace}" \
			"${WG_GO_BIN}" -f "${interface_name}" \
			>"${STATE_DIR}/wg-client-${index}.log" 2>&1 &
		pid=$!
		WG_CLIENT_PIDS+=("${pid}")
		if ! wait_local_link "${namespace}" "${interface_name}" "${pid}"; then
			cat "${STATE_DIR}/wg-client-${index}.log" >&2 || true
			return 1
		fi
		ip netns exec "${namespace}" wg set "${interface_name}" \
			private-key "${STATE_DIR}/wg-client-${index}.private" \
			peer "${server_public}" \
			endpoint "${SERVER_OUTER}:${WG_PORT}" \
			allowed-ips "${SERVER_TUNNEL}/32"
		ip -n "${namespace}" addr add "$(client_tunnel_ip "${index}")/32" dev "${interface_name}"
		ip -n "${namespace}" link set dev "${interface_name}" mtu "${MTU}" up
		ip -n "${namespace}" route add "${SERVER_TUNNEL}/32" dev "${interface_name}"
	done
}

wait_wg_ready() {
	wait_opaque_ready "$1"
}

stop_wg() {
	local index pid namespace interface_name
	for ((index = 1; index <= ${#WG_CLIENT_PIDS[@]}; index++)); do
		pid="${WG_CLIENT_PIDS[$((index - 1))]}"
		kill "${pid}" >/dev/null 2>&1 || true
		wait "${pid}" >/dev/null 2>&1 || true
		namespace="$(client_namespace "${index}")"
		interface_name="$(wg_client_interface "${index}")"
		ip -n "${namespace}" link del "${interface_name}" >/dev/null 2>&1 || true
	done
	WG_CLIENT_PIDS=()
	if [[ -n "${REMOTE_WG_PID}" ]]; then
		remote_shell "kill '${REMOTE_WG_PID}' >/dev/null 2>&1 || true; sleep 0.1; ip link del wgs0 >/dev/null 2>&1 || true"
		REMOTE_WG_PID=""
	fi
}

cleanup_remote_test() {
	set +e
	stop_opaque
	stop_wg

	local namespace
	for namespace in "${NAMESPACES[@]:-}"; do
		[[ -n "${namespace}" ]] || continue
		ip netns del "${namespace}" >/dev/null 2>&1 || true
	done
	NAMESPACES=()

	if (( FORWARD_INSTALLED )); then
		iptables -D FORWARD -i "${BRIDGE}" -o "${EGRESS_IFACE}" -j ACCEPT >/dev/null 2>&1 || true
		iptables -D FORWARD -i "${EGRESS_IFACE}" -o "${BRIDGE}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || true
		FORWARD_INSTALLED=0
	fi
	if (( NAT_INSTALLED )); then
		iptables -t nat -D POSTROUTING -s "${NAMESPACE_PREFIX}.0/24" -o "${EGRESS_IFACE}" -j MASQUERADE >/dev/null 2>&1 || true
		NAT_INSTALLED=0
	fi
	if (( BRIDGE_CREATED )); then
		ip link del "${BRIDGE}" >/dev/null 2>&1 || true
		BRIDGE_CREATED=0
	fi
	if [[ -n "${ORIGINAL_FORWARD}" ]]; then
		sysctl -q -w "net.ipv4.ip_forward=${ORIGINAL_FORWARD}" >/dev/null 2>&1 || true
		ORIGINAL_FORWARD=""
	fi
	if [[ -n "${SERVER_SSH}" ]]; then
		remote_shell "rm -rf '${REMOTE_DIR}'" >/dev/null 2>&1 || true
	fi
	set -e
}
