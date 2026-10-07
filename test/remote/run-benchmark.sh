#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

PEERS="${OL3_PEERS:-1}"
REPETITIONS="${OL3_REPETITIONS:-3}"
TCP_DURATION="${OL3_TCP_DURATION:-15}"
TCP_OMIT="${OL3_TCP_OMIT:-2}"
UDP_DURATION="${OL3_UDP_DURATION:-15}"
UDP_WARMUP="${OL3_UDP_WARMUP:-2}"
UDP_FIXED_SIZE="${OL3_UDP_FIXED_SIZE:-1350}"
RANDOM_MIN="${OL3_RANDOM_MIN:-16}"
RANDOM_MAX="${OL3_RANDOM_MAX:-$((MTU - 28))}"

if [[ "${PEERS}" != "1" && "${PEERS}" != "10" ]]; then
	echo "error: OL3_PEERS must be 1 or 10" >&2
	exit 2
fi
if ! [[ "${REPETITIONS}" =~ ^[1-9][0-9]*$ ]]; then
	echo "error: OL3_REPETITIONS must be positive" >&2
	exit 2
fi
if (( RANDOM_MIN < 0 || RANDOM_MAX < RANDOM_MIN || RANDOM_MAX > MTU - 28 )); then
	echo "error: random UDP payload range must fit the tunnel MTU (max $((MTU - 28)))" >&2
	exit 2
fi

finish() {
	local status=$?
	trap - EXIT INT TERM
	cleanup_remote_test || true
	if [[ -n "${RESULT_DIR}" ]]; then
		echo "results: ${RESULT_DIR}" >&2
	fi
	exit "${status}"
}
trap finish EXIT INT TERM

start_remote_iperf_server() {
	local port="$1"
	local output="$2"
	remote_shell "iperf3 -s -1 -p '${port}'" >"${output}" 2>&1 &
	LAST_REMOTE_JOB_PID=$!
}

run_tcp_group() {
	local implementation="$1"
	local repetition="$2"
	local direction="$3"
	local parallel="$4"
	local base_port=5200
	local -a server_ssh_pids=()
	local -a client_pids=()
	local index namespace port reverse_arg client_output server_output

	for ((index = 1; index <= PEERS; index++)); do
		port=$((base_port + index))
		server_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-tcp-${direction}-p${parallel}-peer${index}.server.log"
		start_remote_iperf_server "${port}" "${server_output}"
		server_ssh_pids+=("${LAST_REMOTE_JOB_PID}")
	done
	sleep 0.2

	reverse_arg=()
	if [[ "${direction}" == "rev" ]]; then
		reverse_arg=(-R)
	fi
	for ((index = 1; index <= PEERS; index++)); do
		namespace="$(client_namespace "${index}")"
		port=$((base_port + index))
		client_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-tcp-${direction}-p${parallel}-peer${index}.json"
		ip netns exec "${namespace}" iperf3 \
			-c "${SERVER_TUNNEL}" \
			-p "${port}" \
			-t "${TCP_DURATION}" \
			-O "${TCP_OMIT}" \
			-P "${parallel}" \
			-J \
			"${reverse_arg[@]}" \
			>"${client_output}" 2>"${client_output%.json}.err" &
		client_pids+=("$!")
	done

	local pid
	for pid in "${client_pids[@]}"; do
		wait "${pid}"
	done
	for pid in "${server_ssh_pids[@]}"; do
		wait "${pid}"
	done
}

traffic_mode_args() {
	local profile="$1"
	local index="$2"
	case "${profile}" in
	fixed)
		printf '%q ' -mode fixed -size "${UDP_FIXED_SIZE}"
		;;
	random)
		printf '%q ' -mode random -min "${RANDOM_MIN}" -max "${RANDOM_MAX}" -seed "$((12345 + index))"
		;;
	zero)
		printf '%q ' -mode zero
		;;
	*)
		return 1
		;;
	esac
}

run_udp_group() {
	local implementation="$1"
	local repetition="$2"
	local direction="$3"
	local profile="$4"
	local duration="$5"
	local keep_results="$6"
	local base_port=6200
	local -a receiver_pids=()
	local -a sender_pids=()
	local index namespace port mode_args recv_output send_output

	if [[ "${direction}" == "fwd" ]]; then
		for ((index = 1; index <= PEERS; index++)); do
			port=$((base_port + index))
			recv_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-udp-${direction}-${profile}-peer${index}.recv.json"
			if [[ "${keep_results}" != "1" ]]; then
				recv_output="${STATE_DIR}/warmup-${implementation}-${direction}-${index}.recv"
			fi
			remote_shell "'${REMOTE_DIR}/opaque-trafficgen' recv -listen '${SERVER_TUNNEL}:${port}' -duration '${duration}s'" >"${recv_output}" 2>"${recv_output}.err" &
			receiver_pids+=("$!")
		done
		sleep 0.2
		for ((index = 1; index <= PEERS; index++)); do
			namespace="$(client_namespace "${index}")"
			port=$((base_port + index))
			mode_args="$(traffic_mode_args "${profile}" "${index}")"
			send_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-udp-${direction}-${profile}-peer${index}.send.json"
			if [[ "${keep_results}" != "1" ]]; then
				send_output="${STATE_DIR}/warmup-${implementation}-${direction}-${index}.send"
			fi
			# shellcheck disable=SC2086
			ip netns exec "${namespace}" "${TRAFFIC_BIN}" send \
				-target "${SERVER_TUNNEL}:${port}" \
				-duration "${duration}s" \
				${mode_args} \
				>"${send_output}" 2>"${send_output}.err" &
			sender_pids+=("$!")
		done
	else
		for ((index = 1; index <= PEERS; index++)); do
			namespace="$(client_namespace "${index}")"
			port=$((base_port + index))
			recv_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-udp-${direction}-${profile}-peer${index}.recv.json"
			if [[ "${keep_results}" != "1" ]]; then
				recv_output="${STATE_DIR}/warmup-${implementation}-${direction}-${index}.recv"
			fi
			ip netns exec "${namespace}" "${TRAFFIC_BIN}" recv \
				-listen "0.0.0.0:${port}" \
				-duration "${duration}s" \
				>"${recv_output}" 2>"${recv_output}.err" &
			receiver_pids+=("$!")
		done
		sleep 0.2
		for ((index = 1; index <= PEERS; index++)); do
			port=$((base_port + index))
			mode_args="$(traffic_mode_args "${profile}" "${index}")"
			send_output="${RESULT_DIR}/${implementation}-${PEERS}p-r${repetition}-udp-${direction}-${profile}-peer${index}.send.json"
			if [[ "${keep_results}" != "1" ]]; then
				send_output="${STATE_DIR}/warmup-${implementation}-${direction}-${index}.send"
			fi
			# mode_args is generated only from numeric/test-controlled values.
			remote_shell "'${REMOTE_DIR}/opaque-trafficgen' send -target '$(client_tunnel_ip "${index}"):${port}' -duration '${duration}s' ${mode_args}" >"${send_output}" 2>"${send_output}.err" &
			sender_pids+=("$!")
		done
	fi

	local pid
	for pid in "${sender_pids[@]}"; do
		wait "${pid}"
	done
	for pid in "${receiver_pids[@]}"; do
		wait "${pid}"
	done
}

run_implementation_benchmarks() {
	local implementation="$1"
	local repetition parallel direction profile

	if [[ "${PEERS}" == "1" ]]; then
		for repetition in $(seq 1 "${REPETITIONS}"); do
			for direction in fwd rev; do
				for parallel in 1 4 8; do
					echo "${implementation}: TCP ${direction} P=${parallel} repetition ${repetition}/${REPETITIONS}"
					run_tcp_group "${implementation}" "${repetition}" "${direction}" "${parallel}"
				done
			done
		done
	else
		for repetition in $(seq 1 "${REPETITIONS}"); do
			for direction in fwd rev; do
				echo "${implementation}: TCP ${direction} 10xP1 repetition ${repetition}/${REPETITIONS}"
				run_tcp_group "${implementation}" "${repetition}" "${direction}" 1
			done
		done
	fi

	if (( UDP_WARMUP > 0 )); then
		echo "${implementation}: UDP warmup"
		run_udp_group "${implementation}" 0 fwd fixed "${UDP_WARMUP}" 0
		run_udp_group "${implementation}" 0 rev fixed "${UDP_WARMUP}" 0
	fi

	for repetition in $(seq 1 "${REPETITIONS}"); do
		for direction in fwd rev; do
			for profile in fixed random zero; do
				echo "${implementation}: UDP ${profile} ${direction} repetition ${repetition}/${REPETITIONS}"
				run_udp_group "${implementation}" "${repetition}" "${direction}" "${profile}" "${UDP_DURATION}" 1
			done
		done
	done
}

require_remote_prerequisites
prepare_remote_workspace
generate_opaque_keys "${PEERS}"
generate_wg_keys "${PEERS}"
create_client_outer_topology "${PEERS}"

cat >"${RESULT_DIR}/metadata.txt" <<EOF_META
server_ssh=${SERVER_SSH}
server_outer=${SERVER_OUTER}
peers=${PEERS}
mtu=${MTU}
repetitions=${REPETITIONS}
tcp_duration=${TCP_DURATION}
tcp_omit=${TCP_OMIT}
udp_duration=${UDP_DURATION}
udp_fixed_size=${UDP_FIXED_SIZE}
random_min=${RANDOM_MIN}
random_max=${RANDOM_MAX}
EOF_META

if [[ "${OL3_RAW_SANITY:-0}" == "1" ]]; then
	echo "raw physical-path TCP sanity"
	start_remote_iperf_server 5199 "${RESULT_DIR}/raw.server.log"
	server_pid="${LAST_REMOTE_JOB_PID}"
	sleep 0.2
	iperf3 -c "${SERVER_OUTER}" -p 5199 -t "${TCP_DURATION}" -O "${TCP_OMIT}" -P 1 -J >"${RESULT_DIR}/raw-tcp.json"
	wait "${server_pid}"
fi

echo "starting Opaque (${PEERS} peer(s))"
start_opaque_server
start_opaque_clients "${PEERS}"
wait_opaque_ready "${PEERS}"
run_implementation_benchmarks opaque
stop_opaque

echo "starting pinned wireguard-go (${PEERS} peer(s))"
start_wg_server
start_wg_clients "${PEERS}"
wait_wg_ready "${PEERS}"
run_implementation_benchmarks wg-go
stop_wg

python3 "${SCRIPT_DIR}/summarize.py" "${RESULT_DIR}" | tee "${RESULT_DIR}/summary.txt"
echo "PASS: remote benchmark complete"
