#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

PING_PID=""

finish() {
	local status=$?
	trap - EXIT INT TERM

	if [[ -n "${PING_PID}" ]]; then
		kill "${PING_PID}" >/dev/null 2>&1 || true
		wait "${PING_PID}" >/dev/null 2>&1 || true
	fi

	if (( status != 0 )); then
		if [[ -n "${LOG_DIR}" && -f "${LOG_DIR}/rekey-ping.log" ]]; then
			echo >&2
			echo "===== rekey-ping.log =====" >&2
			cat "${LOG_DIR}/rekey-ping.log" >&2 || true
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

require_live_prerequisites
create_live_topology
start_live_server
start_live_client
assert_live_processes

echo "baseline client -> server tunnel ping"
ip netns exec "${NS_CLIENT}" ping -n -c 2 -W 1 "${SERVER_TUNNEL}"

echo "starting continuous traffic across A -> B rekey"
ip netns exec "${NS_CLIENT}" \
	ping -n -i 0.05 -c 80 -W 1 "${SERVER_TUNNEL}" \
	>"${LOG_DIR}/rekey-ping.log" 2>&1 &
PING_PID=$!

sleep 0.2

echo "requesting rekey with SIGUSR1"
kill -USR1 "${CLIENT_PID}"

wait_for_log \
	"${LOG_DIR}/client.log" \
	"rekey completed:" \
	"${CLIENT_PID}" \
	"A -> B rekey completion"

wait "${PING_PID}"
PING_PID=""

if ! grep -Fq -- ", 0% packet loss" "${LOG_DIR}/rekey-ping.log"; then
	echo "error: packet loss occurred while rotating A -> B" >&2
	false
fi

rekey_line="$(grep -F -- "rekey completed:" "${LOG_DIR}/client.log" | tail -n 1)"
echo "${rekey_line}"

echo "client -> server tunnel ping on the rotated generation"
ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"

# Client ReceiveGrace is currently 5s in the test executable. The
# client->server ping above produces authenticated reverse DATA on B, so after
# this delay the old A receive slot is no longer required for the final check.
echo "waiting for old-generation receive grace to expire"
sleep 6

echo "server -> client tunnel ping after old-generation grace"
ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"

assert_live_processes

echo "PASS: live A -> B rekey completed with zero packet loss"
