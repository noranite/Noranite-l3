#!/usr/bin/env bash
set -Eeuo pipefail

export OL3_GODEBUG="${OL3_GODEBUG:-gctrace=1}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

DURATION="${OL3_GC_DURATION:-45}"
PORT="${OL3_GC_PORT:-6301}"

finish() {
	local status=$?
	trap - EXIT INT TERM
	if [[ -n "${RESULT_DIR}" && -n "${STATE_DIR}" ]]; then
		cp -f "${STATE_DIR}/opaque-client-1.log" "${RESULT_DIR}/gc-client.log" 2>/dev/null || true
		remote_shell "cat '${REMOTE_DIR}/opaque-server.log'" >"${RESULT_DIR}/gc-server.log" 2>/dev/null || true
	fi
	cleanup_remote_test || true
	if [[ -n "${RESULT_DIR}" ]]; then
		echo "GC logs: ${RESULT_DIR}" >&2
	fi
	exit "${status}"
}
trap finish EXIT INT TERM

require_remote_prerequisites
prepare_remote_workspace
generate_opaque_keys 1
create_client_outer_topology 1
start_opaque_server
start_opaque_clients 1
wait_opaque_ready 1

namespace="$(client_namespace 1)"

echo "forward zero-payload UDP for ${DURATION}s with GODEBUG=${OL3_GODEBUG}"
remote_shell "'${REMOTE_DIR}/opaque-trafficgen' recv -listen '${SERVER_TUNNEL}:${PORT}' -duration '${DURATION}s'" \
	>"${RESULT_DIR}/gc-zero-fwd.recv.json" 2>"${RESULT_DIR}/gc-zero-fwd.recv.err" &
receiver_pid=$!
sleep 0.2
ip netns exec "${namespace}" "${TRAFFIC_BIN}" send \
	-target "${SERVER_TUNNEL}:${PORT}" \
	-mode zero \
	-duration "${DURATION}s" \
	>"${RESULT_DIR}/gc-zero-fwd.send.json" 2>"${RESULT_DIR}/gc-zero-fwd.send.err"
wait "${receiver_pid}"

echo "reverse zero-payload UDP for ${DURATION}s"
ip netns exec "${namespace}" "${TRAFFIC_BIN}" recv \
	-listen "0.0.0.0:${PORT}" \
	-duration "${DURATION}s" \
	>"${RESULT_DIR}/gc-zero-rev.recv.json" 2>"${RESULT_DIR}/gc-zero-rev.recv.err" &
receiver_pid=$!
sleep 0.2
remote_shell "'${REMOTE_DIR}/opaque-trafficgen' send -target '$(client_tunnel_ip 1):${PORT}' -mode zero -duration '${DURATION}s'" \
	>"${RESULT_DIR}/gc-zero-rev.send.json" 2>"${RESULT_DIR}/gc-zero-rev.send.err"
wait "${receiver_pid}"

remote_shell "cat '${REMOTE_DIR}/opaque-server.log'" >"${RESULT_DIR}/gc-server.log"
cp "${STATE_DIR}/opaque-client-1.log" "${RESULT_DIR}/gc-client.log"

client_gc="$(grep -c '^gc ' "${RESULT_DIR}/gc-client.log" || true)"
server_gc="$(grep -c '^gc ' "${RESULT_DIR}/gc-server.log" || true)"
echo "client GC trace lines: ${client_gc}"
echo "server GC trace lines: ${server_gc}"
echo "PASS: Opaque GC pressure check complete"
