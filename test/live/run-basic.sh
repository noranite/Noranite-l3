#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

finish() {
	local status=$?
	trap - EXIT INT TERM

	if (( status != 0 )); then
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

echo "client -> server tunnel ping"
ip netns exec "${NS_CLIENT}" ping -n -c 3 -W 1 "${SERVER_TUNNEL}"

echo "server -> client tunnel ping"
ip netns exec "${NS_SERVER}" ping -n -c 3 -W 1 "${CLIENT_TUNNEL}"

assert_live_processes

echo "PASS: basic live tunnel works in both directions"
