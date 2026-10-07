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
		if [[ -n "${LOG_DIR}" && -d "${LOG_DIR}" ]]; then
			local file
			for file in "${LOG_DIR}"/*.test.log; do
				[[ -e "${file}" ]] || continue
				echo >&2
				echo "===== $(basename "${file}") =====" >&2
				cat "${file}" >&2 || true
			done
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

	for ((attempt = 0; attempt < 1200; attempt++)); do
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

assert_zero_loss_file() {
	local file="$1"
	if ! grep -Fq -- ", 0% packet loss" "${file}"; then
		echo "error: packet loss observed in $(basename "${file}")" >&2
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

start_direct_topology() {
	create_live_topology
	start_live_server
	start_live_client
	assert_live_processes

	echo "baseline client -> server tunnel ping"
	ip netns exec "${NS_CLIENT}" ping -n -c 2 -W 1 "${SERVER_TUNNEL}"
}

stop_background_ping() {
	if [[ -z "${PING_PID}" ]]; then
		return
	fi
	kill -INT "${PING_PID}" >/dev/null 2>&1 || true
	wait "${PING_PID}" >/dev/null 2>&1 || true
	PING_PID=""
}

case_old_generation_grace() {
	start_fault_topology "delay-old-generation"

	echo "requesting B; Noise RESPONSE(B) will be delayed so four DATA(A) packets can be captured"
	kill -USR1 "${CLIENT_PID}"
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"old-generation delay armed after Noise INIT ordinal=2" \
		"${PROXY_PID}" \
		"old-generation delay arming"

	ip netns exec "${NS_CLIENT}" \
		ping -n -c 4 -i 0.05 -W 8 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/old-generation.test.log" 2>&1 &
	PING_PID=$!

	wait_for_rekey_count 1
	line="$(rekey_line 1)"
	echo "${line}"

	echo "forcing ordinary DATA(B) after client install"
	ip netns exec "${NS_CLIENT}" ping -n -c 2 -i 0.05 -W 1 "${SERVER_TUNNEL}"

	# Exactly four A packets were emitted while Noise RESPONSE(B) was held for
	# 500ms. The proxy releases two at ~1s (inside the 5s previous grace) and two
	# at ~7s (after grace). Packet loss is therefore expected and diagnostic.
	if wait "${PING_PID}"; then
		:
	else
		:
	fi
	PING_PID=""

	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"old-generation delayed packet released class=late index=4" \
		"${PROXY_PID}" \
		"late old-generation release"

	if ! grep -Fq -- "4 packets transmitted, 2 received" "${LOG_DIR}/old-generation.test.log"; then
		echo "error: expected exactly two in-grace A packets to survive and two post-grace A packets to be rejected" >&2
		return 1
	fi

	for expected in \
		"old-generation client transport delayed class=early index=1" \
		"old-generation client transport delayed class=early index=2" \
		"old-generation client transport delayed class=late index=3" \
		"old-generation client transport delayed class=late index=4"
	do
		if ! grep -Fq -- "${expected}" "${LOG_DIR}/proxy.log"; then
			echo "error: missing proxy event: ${expected}" >&2
			return 1
		fi
	done

	echo "verifying B remains healthy after post-grace A delivery"
	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes

	echo "PASS: previous generation accepted only inside grace and late A could not disturb B"
}

case_duplicate_replay() {
	start_fault_topology "duplicate-replay"

	echo "requesting B; proxy duplicates B activation KEEPALIVE and matching ACK"
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 1
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"client transport duplicated response_ordinal=2 transport_ordinal=1" \
		"${PROXY_PID}" \
		"duplicated activation KEEPALIVE"
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"server transport duplicated response_ordinal=2 transport_ordinal=1" \
		"${PROXY_PID}" \
		"duplicated activation ACK"

	echo "sending one DATA(B); exact encrypted request and response are duplicated"
	ip netns exec "${NS_CLIENT}" \
		ping -n -c 1 -W 2 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/duplicate-replay.test.log" 2>&1

	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"client transport duplicated response_ordinal=2 transport_ordinal=2" \
		"${PROXY_PID}" \
		"duplicated DATA(B)"
	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"server transport duplicated response_ordinal=2 transport_ordinal=2" \
		"${PROXY_PID}" \
		"duplicated DATA response"

	if grep -Fq -- "DUP!" "${LOG_DIR}/duplicate-replay.test.log"; then
		echo "error: duplicated encrypted datagram escaped replay protection and reached ICMP" >&2
		return 1
	fi
	if ! grep -Fq -- "1 packets transmitted, 1 received, 0% packet loss" "${LOG_DIR}/duplicate-replay.test.log"; then
		echo "error: one logical DATA request did not produce exactly one logical reply" >&2
		return 1
	fi

	ip netns exec "${NS_SERVER}" ping -n -c 2 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes
	echo "PASS: duplicate CONTROL and DATA ciphertext was suppressed by replay handling"
}

case_chaos_rapid_rotation() {
	start_fault_topology "chaos"
	expected_previous=""

	echo "starting continuous DATA; first rekey arms deterministic drop/duplicate/delay/reorder window"
	ip netns exec "${NS_CLIENT}" \
		ping -n -i 0.01 -W 1 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/chaos.test.log" 2>&1 &
	PING_PID=$!
	sleep 0.1

	local index line previous current
	for index in 1 2 3; do
		echo "requesting rapid rekey ${index}/3"
		kill -USR1 "${CLIENT_PID}"
		wait_for_rekey_count "${index}"
		line="$(rekey_line "${index}")"
		previous="$(extract_field "${line}" "previous")"
		current="$(extract_field "${line}" "current")"
		if [[ -z "${previous}" || -z "${current}" || "${current}" == "${previous}" ]]; then
			echo "error: malformed rapid rotation chain at ${index}: ${line}" >&2
			return 1
		fi
		if [[ -n "${expected_previous}" && "${previous}" != "${expected_previous}" ]]; then
			echo "error: rapid rotation chain broke at ${index}: expected previous=${expected_previous}, got ${previous}" >&2
			return 1
		fi
		echo "${line}"
		expected_previous="${current}"
	done

	wait_for_log \
		"${LOG_DIR}/proxy.log" \
		"chaos window complete packets=" \
		"${PROXY_PID}" \
		"chaos window completion"

	stop_background_ping
	if ! grep -Fq -- "bytes from ${SERVER_TUNNEL}" "${LOG_DIR}/chaos.test.log"; then
		echo "error: no DATA replies survived the chaos window" >&2
		return 1
	fi

	for mutation in "chaos transport dropped" "chaos transport duplicated" "chaos transport delayed"; do
		if ! grep -Fq -- "${mutation}" "${LOG_DIR}/proxy.log"; then
			echo "error: chaos window did not exercise: ${mutation}" >&2
			return 1
		fi
	done

	echo "chaos window is over; latest generation must converge cleanly"
	ip netns exec "${NS_CLIENT}" ping -n -c 5 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 5 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes

	echo "PASS: rapid rotations converged under deterministic loss, duplication, delay, and reorder"
}

case_persistent_establishment_loss() {
	start_fault_topology "drop-responses-from-target"

	echo "starting DATA(A), then blackholing every rekey Noise RESPONSE for multiple retry intervals"
	ip netns exec "${NS_CLIENT}" \
		ping -n -i 0.05 -W 1 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/establishment-loss.test.log" 2>&1 &
	PING_PID=$!
	sleep 0.2

	kill -USR1 "${CLIENT_PID}"
	for ordinal in 2 3 4; do
		wait_for_log \
			"${LOG_DIR}/proxy.log" \
			"Noise RESPONSE ordinal=${ordinal} dropped" \
			"${PROXY_PID}" \
			"dropped Noise RESPONSE ordinal ${ordinal}"
	done

	stop_background_ping
	assert_zero_loss_file "${LOG_DIR}/establishment-loss.test.log"

	if (( $(rekey_count) != 0 )); then
		echo "error: client installed a generation despite every rekey Noise RESPONSE being dropped" >&2
		return 1
	fi

	echo "A must still carry traffic after repeated pending generations were installed only on the server"
	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes

	echo "PASS: persistent establishment loss did not disturb the active generation"
}

case_mtu_boundary() {
	start_direct_topology

	local payload oversized
	payload=$((MTU - 28))
	oversized=$((payload + 1))
	if (( payload <= 0 )); then
		echo "error: MTU ${MTU} is too small for IPv4/ICMP boundary test" >&2
		return 1
	fi

	echo "checking exact inner MTU=${MTU} in both directions (ICMP payload=${payload})"
	ip netns exec "${NS_CLIENT}" ping -n -M do -s "${payload}" -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -M do -s "${payload}" -c 3 -W 1 "${CLIENT_TUNNEL}"

	echo "rotating while maximum-size DATA is continuously crossing the tunnel"
	ip netns exec "${NS_CLIENT}" \
		ping -n -M do -s "${payload}" -c 30 -i 0.02 -W 1 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/mtu-rekey.test.log" 2>&1 &
	PING_PID=$!
	sleep 0.1
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 1
	wait "${PING_PID}"
	PING_PID=""
	assert_zero_loss_file "${LOG_DIR}/mtu-rekey.test.log"

	echo "verifying one-byte-oversized inner IPv4 packet is rejected by the TUN MTU boundary"
	if ip netns exec "${NS_CLIENT}" \
		ping -n -M do -s "${oversized}" -c 1 -W 1 "${SERVER_TUNNEL}" \
		>"${LOG_DIR}/mtu-oversized.test.log" 2>&1
	then
		echo "error: packet larger than configured TUN MTU unexpectedly crossed the tunnel" >&2
		return 1
	fi

	ip netns exec "${NS_SERVER}" ping -n -M do -s "${payload}" -c 2 -W 1 "${CLIENT_TUNNEL}"
	assert_live_processes
	echo "PASS: maximum-size DATA survives rekey and oversized inner packets stay outside the protocol path"
}

wait_for_client_tun_removed() {
	local attempt
	for ((attempt = 0; attempt < 200; attempt++)); do
		if ! ip -n "${NS_CLIENT}" link show dev "${CLIENT_TUN}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.05
	done
	echo "error: client TUN remained after client process exit" >&2
	return 1
}

case_client_restart() {
	start_direct_topology

	echo "stopping client process while keeping server/core alive"
	kill -TERM "${CLIENT_PID}"
	wait "${CLIENT_PID}" >/dev/null 2>&1 || true
	CLIENT_PID=""
	wait_for_client_tun_removed

	echo "starting a fresh client process against the same live server"
	start_live_client
	assert_live_processes
	ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"
	ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"

	echo "requesting one rekey after restart to prove the fresh Noise controller is live"
	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count 1
	rekey_line 1
	assert_live_processes

	echo "PASS: client process restart bootstrapped Noise, relearned the endpoint, and rekeyed"
}

require_live_prerequisites
require_live_proxy_prerequisite

case "${CASE}" in
old-generation-grace)
	case_old_generation_grace
	;;
duplicate-replay)
	case_duplicate_replay
	;;
chaos-rapid-rotation)
	case_chaos_rapid_rotation
	;;
persistent-establishment-loss)
	case_persistent_establishment_loss
	;;
mtu-boundary)
	case_mtu_boundary
	;;
client-restart)
	case_client_restart
	;;
*)
	echo "usage: $0 {old-generation-grace|duplicate-replay|chaos-rapid-rotation|persistent-establishment-loss|mtu-boundary|client-restart}" >&2
	exit 2
	;;
esac
