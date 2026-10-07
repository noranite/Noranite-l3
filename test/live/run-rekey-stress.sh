#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

REKEY_COUNT="${OL3_REKEY_COUNT:-100}"
REKEY_SETTLE="${OL3_REKEY_SETTLE:-0.02}"
MAX_LATENCY_MS="${OL3_REKEY_MAX_LATENCY_MS:-1000}"
PING_PID=""
LATENCY_FILE=""

finish() {
	local status=$?
	trap - EXIT INT TERM

	if [[ -n "${PING_PID}" ]]; then
		kill -INT "${PING_PID}" >/dev/null 2>&1 || true
		wait "${PING_PID}" >/dev/null 2>&1 || true
		PING_PID=""
	fi

	if (( status != 0 )); then
		if [[ -n "${LOG_DIR}" && -f "${LOG_DIR}/stress-ping.log" ]]; then
			echo >&2
			echo "===== stress-ping.log =====" >&2
			cat "${LOG_DIR}/stress-ping.log" >&2 || true
		fi
		if [[ -n "${LATENCY_FILE}" && -f "${LATENCY_FILE}" ]]; then
			echo >&2
			echo "===== rekey latency samples (ns) =====" >&2
			cat "${LATENCY_FILE}" >&2 || true
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

wait_for_rekey_count() {
	local expected="$1"
	local attempt count

	# 8 seconds permits one or two 3s establishment retries to become visible in
	# the latency sample instead of turning the harness itself into the timeout.
	for ((attempt = 0; attempt < 800; attempt++)); do
		count="$(grep -Fc -- "rekey completed:" "${LOG_DIR}/client.log" 2>/dev/null || true)"
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

extract_field() {
	local line="$1"
	local name="$2"
	sed -n "s/.*${name}=\\([^ ]*\\).*/\\1/p" <<<"${line}"
}

require_live_prerequisites
for command_name in awk sed sort tail wc; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		echo "error: required command not found: ${command_name}" >&2
		exit 1
	fi
done

if ! [[ "${REKEY_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: OL3_REKEY_COUNT must be a positive integer" >&2
	exit 1
fi
if ! [[ "${MAX_LATENCY_MS}" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: OL3_REKEY_MAX_LATENCY_MS must be a positive integer" >&2
	exit 1
fi

create_live_topology
LATENCY_FILE="${LOG_DIR}/rekey-latency-ns.log"
: >"${LATENCY_FILE}"
start_live_server
start_live_client
assert_live_processes

expected_current=""

echo "baseline client -> server tunnel ping"
ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"

echo "starting continuous bidirectional DATA traffic"
# Every ICMP echo request traverses client -> server and its reply traverses
# server -> client, so one ping stream continuously exercises both directions.
ip netns exec "${NS_CLIENT}" \
	ping -n -i 0.02 -W 1 "${SERVER_TUNNEL}" \
	>"${LOG_DIR}/stress-ping.log" 2>&1 &
PING_PID=$!

sleep 0.2

echo "running ${REKEY_COUNT} sequential live rekeys"
for ((i = 1; i <= REKEY_COUNT; i++)); do
	before_count="$(grep -Fc -- "rekey completed:" "${LOG_DIR}/client.log" 2>/dev/null || true)"

	kill -USR1 "${CLIENT_PID}"
	wait_for_rekey_count "$((before_count + 1))"

	line="$(grep -F -- "rekey completed:" "${LOG_DIR}/client.log" | tail -n 1)"
	previous="$(extract_field "${line}" "previous")"
	current="$(extract_field "${line}" "current")"
	latency_ns="$(extract_field "${line}" "latency_ns")"

	if [[ -z "${previous}" || -z "${current}" || -z "${latency_ns}" ]]; then
		echo "error: malformed rekey completion line: ${line}" >&2
		false
	fi
	if [[ -n "${expected_current}" && "${previous}" != "${expected_current}" ]]; then
		echo "error: rekey ${i} previous SessionID mismatch: expected=${expected_current} got=${previous}" >&2
		false
	fi
	if [[ "${current}" == "${previous}" ]]; then
		echo "error: rekey ${i} did not change SessionID: ${current}" >&2
		false
	fi
	if ! [[ "${latency_ns}" =~ ^[0-9]+$ ]]; then
		echo "error: rekey ${i} latency is not an integer: ${latency_ns}" >&2
		false
	fi

	echo "${latency_ns}" >>"${LATENCY_FILE}"
	expected_current="${current}"

	if (( i == 1 || i % 10 == 0 || i == REKEY_COUNT )); then
		latency_ms="$(awk -v ns="${latency_ns}" 'BEGIN { printf "%.3f", ns / 1000000 }')"
		printf 'rekey %d/%d: current=%s latency=%sms\n' "${i}" "${REKEY_COUNT}" "${current}" "${latency_ms}"
	fi

	sleep "${REKEY_SETTLE}"
done

kill -INT "${PING_PID}" >/dev/null 2>&1 || true
wait "${PING_PID}" >/dev/null 2>&1 || true
PING_PID=""

if ! grep -Fq -- ", 0% packet loss" "${LOG_DIR}/stress-ping.log"; then
	echo "error: packet loss occurred during repeated live rekey" >&2
	false
fi

assert_live_processes

echo "final client -> server tunnel ping"
ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"

echo "final server -> client tunnel ping"
ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"

samples="$(wc -l <"${LATENCY_FILE}")"
if (( samples != REKEY_COUNT )); then
	echo "error: expected ${REKEY_COUNT} latency samples, got ${samples}" >&2
	false
fi

sort -n "${LATENCY_FILE}" >"${LATENCY_FILE}.sorted"

read -r min_ns avg_ns p50_ns p95_ns p99_ns max_ns over_limit <<EOF_STATS
$(awk -v limit_ms="${MAX_LATENCY_MS}" '
{
	v[NR] = $1
	sum += $1
	if ($1 >= limit_ms * 1000000) over++
}
END {
	if (NR == 0) exit 1
	p50 = int((NR - 1) * 0.50) + 1
	p95 = int((NR - 1) * 0.95) + 1
	p99 = int((NR - 1) * 0.99) + 1
	printf "%d %.0f %d %d %d %d %d", v[1], sum / NR, v[p50], v[p95], v[p99], v[NR], over + 0
}' "${LATENCY_FILE}.sorted")
EOF_STATS

awk \
	-v n="${samples}" \
	-v min="${min_ns}" \
	-v avg="${avg_ns}" \
	-v p50="${p50_ns}" \
	-v p95="${p95_ns}" \
	-v p99="${p99_ns}" \
	-v max="${max_ns}" \
	-v over="${over_limit}" \
	-v limit="${MAX_LATENCY_MS}" \
	'BEGIN {
		printf "rekey latency: n=%d min=%.3fms avg=%.3fms p50=%.3fms p95=%.3fms p99=%.3fms max=%.3fms >=%dms=%d\n",
			n, min/1e6, avg/1e6, p50/1e6, p95/1e6, p99/1e6, max/1e6, limit, over
	}'

if (( over_limit != 0 )); then
	echo "error: ${over_limit} rekey(s) exceeded ${MAX_LATENCY_MS}ms; retry-sized stalls are unexpected on the local live topology" >&2
	false
fi

echo "PASS: ${REKEY_COUNT} sequential live rekeys completed with zero packet loss"
