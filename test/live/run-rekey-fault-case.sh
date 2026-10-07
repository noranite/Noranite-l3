#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

CASE="${1:-}"
PING_PID=""

finish() {
	local status=$?
	trap - EXIT INT TERM

	if [[ -n "${PING_PID}" ]]; then
		kill -INT "${PING_PID}" >/dev/null 2>&1 || true
		wait "${PING_PID}" >/dev/null 2>&1 || true
		PING_PID=""
	fi

	if (( status != 0 )); then
		if [[ -n "${LOG_DIR}" && -f "${LOG_DIR}/fault-ping.log" ]]; then
			echo >&2
			echo "===== fault-ping.log =====" >&2
			cat "${LOG_DIR}/fault-ping.log" >&2 || true
		fi
		dump_live_logs
		if [[ -n "${LOG_DIR}" ]]; then
			echo "live-test logs preserved in: ${LOG_DIR}" >&2
		fi
	fi

	cleanup_live_topology

	if (( status == 0 )) && [[ -n "${LOG_DIR}" ]]; then
		rm -rf "${LOG_DIR}"
	fi

	exit "${status}"
}
trap finish EXIT INT TERM

rekey_count() {
	grep -Fc -- "rekey completed:" "${LOG_DIR}/client.log" 2>/dev/null || true
}

wait_for_rekey_count() {
	local expected="$1"
	local attempt count

	for ((attempt = 0; attempt < 1000; attempt++)); do
		count="$(rekey_count)"
		if (( count >= expected )); then
			return 0
		fi
		if ! kill -0 "${CLIENT_PID}" >/dev/null 2>&1; then
			echo "error: client exited while waiting for rekey ${expected}" >&2
			return 1
		fi
		sleep 0.01
	done

	echo "error: timed out waiting for rekey ${expected}" >&2
	return 1
}

rekey_line() {
	local index="$1"
	grep -F -- "rekey completed:" "${LOG_DIR}/client.log" | sed -n "${index}p"
}

extract_field() {
	local line="$1"
	local name="$2"
	sed -n "s/.*${name}=\\([^ ]*\\).*/\\1/p" <<<"${line}"
}

assert_zero_loss_ping_log() {
	if ! grep -Fq -- ", 0% packet loss" "${LOG_DIR}/fault-ping.log"; then
		echo "error: packet loss occurred while the old current generation should remain usable" >&2
		return 1
	fi
}

start_fault_topology() {
	local mode="$1"

	create_live_topology
	start_live_server
	start_live_proxy "${mode}" 2
	start_live_client "${CLIENT_OUTER}:${PROXY_PORT}"
	assert_live_processes

	echo "baseline client -> server tunnel ping"
	ip netns exec "${NS_CLIENT}" ping -n -c 2 -W 1 "${SERVER_TUNNEL}"
}

case_lost_activation() {
	start_fault_topology "drop-first-transport-after-response"

	echo "requesting A -> B rekey; proxy will drop B activation transport"
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 1
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"client transport dropped after Noise RESPONSE ordinal=2" \
		"${PROXY_PID}" \
		"dropped B activation transport"

	line="$(rekey_line 1)"
	echo "${line}"

	echo "sending DATA(B); it must promote server pending B without activation KEEPALIVE"
	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"

	echo "verifying reverse DATA after DATA-driven promotion"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"

	assert_live_processes
	echo "PASS: lost activation KEEPALIVE recovered through ordinary DATA(B)"
}

case_lost_response() {
	start_fault_topology "drop-response"

	echo "starting continuous DATA on A while first rekey Noise RESPONSE is lost"
	ip netns exec "${NS_CLIENT}" \
		ping -n -i 0.05 -W 1 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/fault-ping.log" 2>&1 &
	PING_PID=$!

	sleep 0.2

	echo "requesting rekey; proxy will drop Noise RESPONSE ordinal 2"
	kill -USR1 "${CLIENT_PID}"
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"Noise RESPONSE ordinal=2 dropped" \
		"${PROXY_PID}" \
		"dropped first rekey Noise RESPONSE"
	wait_for_rekey_count 1
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"Noise RESPONSE ordinal=3 forwarded" \
		"${PROXY_PID}" \
		"forwarded retry Noise RESPONSE"

	kill -INT "${PING_PID}" >/dev/null 2>&1 || true
	wait "${PING_PID}" >/dev/null 2>&1 || true
	PING_PID=""
	assert_zero_loss_ping_log

	line="$(rekey_line 1)"
	latency_ns="$(extract_field "${line}" "latency_ns")"
	if ! [[ "${latency_ns}" =~ ^[0-9]+$ ]]; then
		echo "error: malformed rekey latency: ${line}" >&2
		return 1
	fi
	if (( latency_ns < 2500000000 || latency_ns >= 5500000000 )); then
		echo "error: one dropped Noise RESPONSE should cause one ~3s retry; latency_ns=${latency_ns}" >&2
		return 1
	fi

	echo "${line}"
	echo "retry path latency is consistent with one establishment retry"

	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes

	echo "PASS: lost Noise RESPONSE retried without disrupting DATA on A"
}

case_superseded_pending() {
	start_fault_topology "block-transport-until-next-response"

	echo "requesting B; proxy will block all B transport after Noise RESPONSE(B)"
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 1
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"client transport dropped while blocked after Noise RESPONSE ordinal=2" \
		"${PROXY_PID}" \
		"blocked B activation transport"

	b_line="$(rekey_line 1)"
	b_previous="$(extract_field "${b_line}" "previous")"
	b_current="$(extract_field "${b_line}" "current")"
	if [[ -z "${b_previous}" || -z "${b_current}" || "${b_current}" == "${b_previous}" ]]; then
		echo "error: malformed A -> B client transition: ${b_line}" >&2
		return 1
	fi
	echo "${b_line}"

	echo "requesting C before any B transport reaches the server"
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 2
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"client transport blocking disabled by Noise RESPONSE ordinal=3" \
		"${PROXY_PID}" \
		"C Noise RESPONSE superseding pending B"

	c_line="$(rekey_line 2)"
	c_previous="$(extract_field "${c_line}" "previous")"
	c_current="$(extract_field "${c_line}" "current")"
	if [[ "${c_previous}" != "${b_current}" || -z "${c_current}" || "${c_current}" == "${b_current}" ]]; then
		echo "error: malformed B -> C client transition: ${c_line}" >&2
		return 1
	fi
	echo "${c_line}"

	echo "verifying C transport after server pending B was superseded"
	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes

	echo "PASS: unactivated pending B was superseded by C and transport recovered on C"
}

require_live_prerequisites
require_live_proxy_prerequisite

case "${CASE}" in
lost-activation)
	case_lost_activation
	;;
lost-response)
	case_lost_response
	;;
superseded-pending)
	case_superseded_pending
	;;
*)
	echo "usage: $0 {lost-activation|lost-response|superseded-pending}" >&2
	exit 2
	;;
esac
