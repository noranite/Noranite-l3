#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

REMOTE_PEERS="${OL3_ACCEPTANCE_PEERS:-10}"
if [[ "${REMOTE_PEERS}" != "10" ]]; then
	echo "error: OL3_ACCEPTANCE_PEERS currently must be 10" >&2
	exit 2
fi

finish() {
	local status=$?
	trap - EXIT INT TERM
	if (( status != 0 )) && [[ -n "${STATE_DIR}" ]]; then
		echo "acceptance state/logs: ${STATE_DIR}" >&2
		if [[ -f "${STATE_DIR}/proxy.log" ]]; then
			echo "===== proxy.log =====" >&2
			cat "${STATE_DIR}/proxy.log" >&2 || true
		fi
		local file
		for file in "${STATE_DIR}"/opaque-client-*.log; do
			[[ -e "${file}" ]] || continue
			echo "===== $(basename "${file}") =====" >&2
			cat "${file}" >&2 || true
		done
		remote_shell "cat '${REMOTE_DIR}/opaque-server.log' >&2 || true" || true
	fi
	cleanup_remote_test || true
	exit "${status}"
}
trap finish EXIT INT TERM

wait_for_file_log() {
	local file="$1"
	local pattern="$2"
	local pid="$3"
	local description="$4"
	local attempt
	for ((attempt = 0; attempt < 1600; attempt++)); do
		if grep -Fq -- "${pattern}" "${file}" 2>/dev/null; then
			return 0
		fi
		if [[ -n "${pid}" ]] && ! kill -0 "${pid}" >/dev/null 2>&1; then
			echo "error: process exited while waiting for ${description}" >&2
			return 1
		fi
		sleep 0.01
	done
	echo "error: timed out waiting for ${description}" >&2
	return 1
}

start_one_peer_case() {
	local mode="${1:-direct}"
	stop_opaque
	: >"${STATE_DIR}/proxy.log"
	start_opaque_server
	if [[ "${mode}" == "direct" ]]; then
		start_opaque_clients 1
	else
		start_fault_proxy "${mode}"
		start_opaque_clients 1 "$(client_outer_ip 1):51821"
	fi
	wait_opaque_ready 1
}

request_rekey_and_wait() {
	local expected_count="$1"
	local client_log="${STATE_DIR}/opaque-client-1.log"
	kill -USR1 "${CLIENT_PIDS[0]}"
	local attempt count
	for ((attempt = 0; attempt < 1600; attempt++)); do
		count="$(grep -Fc -- 'rekey completed:' "${client_log}" 2>/dev/null || true)"
		if (( count >= expected_count )); then
			return 0
		fi
		if ! kill -0 "${CLIENT_PIDS[0]}" >/dev/null 2>&1; then
			echo "error: client exited while waiting for rekey" >&2
			return 1
		fi
		sleep 0.01
	done
	echo "error: timed out waiting for rekey ${expected_count}" >&2
	return 1
}

case_basic_rekey() {
	echo "== remote basic + Noise rekey =="
	start_one_peer_case direct
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
	remote_shell "ping -n -c 5 -W 2 '$(client_tunnel_ip 1)'"
	request_rekey_and_wait 1
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
	remote_shell "ping -n -c 5 -W 2 '$(client_tunnel_ip 1)'"
}

case_lost_activation() {
	echo "== remote lost activation =="
	start_one_peer_case drop-first-transport-after-response
	request_rekey_and_wait 1
	wait_for_file_log \
		"${STATE_DIR}/proxy.log" \
		"client transport dropped after Noise RESPONSE ordinal=2" \
		"${PROXY_PID}" \
		"lost activation"
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
	remote_shell "ping -n -c 5 -W 2 '$(client_tunnel_ip 1)'"
}

case_lost_response() {
	echo "== remote lost Noise RESPONSE + retry =="
	start_one_peer_case drop-response
	ip netns exec "$(client_namespace 1)" ping -n -i 0.1 -c 60 -W 2 "${SERVER_TUNNEL}" >"${STATE_DIR}/lost-response.ping" 2>&1 &
	local ping_pid=$!
	sleep 0.2
	request_rekey_and_wait 1
	wait_for_file_log "${STATE_DIR}/proxy.log" "Noise RESPONSE ordinal=2 dropped" "${PROXY_PID}" "dropped response"
	wait_for_file_log "${STATE_DIR}/proxy.log" "Noise RESPONSE ordinal=3 forwarded" "${PROXY_PID}" "retry response"
	wait "${ping_pid}" || true
	if ! grep -Fq -- "bytes from ${SERVER_TUNNEL}" "${STATE_DIR}/lost-response.ping"; then
		echo "error: no DATA survived while the first rekey RESPONSE was lost" >&2
		return 1
	fi
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
}

case_persistent_response_loss() {
	echo "== remote persistent Noise RESPONSE loss =="
	start_one_peer_case drop-responses-from-target
	kill -USR1 "${CLIENT_PIDS[0]}"
	local ordinal
	for ordinal in 2 3 4; do
		wait_for_file_log \
			"${STATE_DIR}/proxy.log" \
			"Noise RESPONSE ordinal=${ordinal} dropped" \
			"${PROXY_PID}" \
			"persistent response loss ordinal ${ordinal}"
	done
	if grep -Fq -- "rekey completed:" "${STATE_DIR}/opaque-client-1.log"; then
		echo "error: client installed a generation while every rekey RESPONSE was dropped" >&2
		return 1
	fi
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
	remote_shell "ping -n -c 5 -W 2 '$(client_tunnel_ip 1)'"
}

case_chaos_rotation() {
	echo "== remote transport chaos + rapid Noise rotations =="
	start_one_peer_case chaos
	ip netns exec "$(client_namespace 1)" ping -n -i 0.05 -W 2 "${SERVER_TUNNEL}" >"${STATE_DIR}/chaos.ping" 2>&1 &
	local ping_pid=$!
	local index
	for index in 1 2 3; do
		request_rekey_and_wait "${index}"
	done
	wait_for_file_log "${STATE_DIR}/proxy.log" "chaos window complete packets=" "${PROXY_PID}" "chaos completion"
	kill -INT "${ping_pid}" >/dev/null 2>&1 || true
	wait "${ping_pid}" >/dev/null 2>&1 || true
	for mutation in "chaos transport dropped" "chaos transport duplicated" "chaos transport delayed"; do
		grep -Fq -- "${mutation}" "${STATE_DIR}/proxy.log" || {
			echo "error: remote chaos did not exercise ${mutation}" >&2
			return 1
		}
	done
	ip netns exec "$(client_namespace 1)" ping -n -c 5 -W 2 "${SERVER_TUNNEL}"
	remote_shell "ping -n -c 5 -W 2 '$(client_tunnel_ip 1)'"
}

case_ten_peer_rekey() {
	echo "== remote 10-peer shared-server traffic + concurrent rekey =="
	stop_opaque
	start_opaque_server
	start_opaque_clients 10
	wait_opaque_ready 10

	local index
	local -a ping_pids=()
	for index in $(seq 1 10); do
		ip netns exec "$(client_namespace "${index}")" \
			ping -n -i 0.05 -c 80 -W 2 "${SERVER_TUNNEL}" \
			>"${STATE_DIR}/ten-peer-${index}.ping" 2>&1 &
		ping_pids+=("$!")
	done
	sleep 0.2
	for index in $(seq 1 10); do
		kill -USR1 "${CLIENT_PIDS[$((index - 1))]}"
	done
	for index in $(seq 1 10); do
		wait_for_file_log \
			"${STATE_DIR}/opaque-client-${index}.log" \
			"rekey completed:" \
			"${CLIENT_PIDS[$((index - 1))]}" \
			"peer ${index} rekey"
	done
	local pid
	for pid in "${ping_pids[@]}"; do
		wait "${pid}" || true
	done
	for index in $(seq 1 10); do
		ip netns exec "$(client_namespace "${index}")" ping -n -c 2 -W 2 "${SERVER_TUNNEL}" >/dev/null
		remote_shell "ping -n -c 1 -W 2 '$(client_tunnel_ip "${index}")' >/dev/null"
	done
}

require_remote_prerequisites
prepare_remote_workspace
generate_opaque_keys 10
create_client_outer_topology 10

case_basic_rekey
case_lost_activation
case_lost_response
case_persistent_response_loss
case_chaos_rotation
case_ten_peer_rekey

echo "PASS: two-host production-Noise acceptance suite"
