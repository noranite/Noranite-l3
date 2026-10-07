#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

IPERF_PORT="${OL3_IPERF_PORT:-5201}"
TCP_DURATION="${OL3_THROUGHPUT_DURATION:-8}"
TCP_OMIT="${OL3_THROUGHPUT_OMIT:-2}"
TCP_STREAMS="${OL3_THROUGHPUT_STREAMS:-1 2 4 8 16}"
RAW_DURATION="${OL3_RAW_DURATION:-4}"
RAW_STREAMS="${OL3_RAW_STREAMS:-4}"
UDP_DURATION="${OL3_UDP_DURATION:-6}"
UDP_RATE="${OL3_UDP_RATE:-2G}"
UDP_LENGTH="${OL3_UDP_LENGTH:-1350}"

IPERF_PID=""
RESULTS_FILE=""
CLK_TCK="$(getconf CLK_TCK)"

finish() {
	local status=$?
	trap - EXIT INT TERM

	if [[ -n "${IPERF_PID}" ]]; then
		kill "${IPERF_PID}" >/dev/null 2>&1 || true
		wait "${IPERF_PID}" >/dev/null 2>&1 || true
		IPERF_PID=""
	fi

	if (( status != 0 )); then
		if [[ -n "${LOG_DIR}" && -d "${LOG_DIR}" ]]; then
			local file
			for file in "${LOG_DIR}"/iperf-*.log "${LOG_DIR}"/iperf-*.json; do
				[[ -e "${file}" ]] || continue
				echo >&2
				echo "===== $(basename "${file}") =====" >&2
				cat "${file}" >&2 || true
			done
		fi
		dump_live_logs
		if [[ -n "${LOG_DIR}" ]]; then
			echo "throughput-test logs preserved in: ${LOG_DIR}" >&2
		fi
	fi

	cleanup_live_topology

	if (( status == 0 )) && [[ -n "${LOG_DIR}" ]]; then
		rm -rf "${LOG_DIR}"
	fi

	exit "${status}"
}
trap finish EXIT INT TERM

require_benchmark_prerequisites() {
	require_live_prerequisites

	local command_name
	for command_name in iperf3 python3 ss awk getconf date; do
		if ! command -v "${command_name}" >/dev/null 2>&1; then
			echo "error: required benchmark command not found: ${command_name}" >&2
			return 1
		fi
	done

	local value
	for value in "${TCP_DURATION}" "${TCP_OMIT}" "${RAW_DURATION}" "${RAW_STREAMS}" "${UDP_DURATION}" "${UDP_LENGTH}"; do
		if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
			echo "error: benchmark numeric values must be positive integers" >&2
			return 1
		fi
	done

	if [[ ! "${IPERF_PORT}" =~ ^[1-9][0-9]*$ ]] || (( IPERF_PORT > 65535 )); then
		echo "error: invalid OL3_IPERF_PORT=${IPERF_PORT}" >&2
		return 1
	fi

	for value in ${TCP_STREAMS}; do
		if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
			echo "error: OL3_THROUGHPUT_STREAMS must contain positive integers" >&2
			return 1
		fi
	done
}

process_ticks() {
	local pid="$1"
	awk '{print $14 + $15}' "/proc/${pid}/stat"
}

cpu_percent() {
	local before_ticks="$1"
	local after_ticks="$2"
	local elapsed_ns="$3"
	python3 - "${before_ticks}" "${after_ticks}" "${elapsed_ns}" "${CLK_TCK}" <<'PY'
import sys
before, after, elapsed_ns, hz = map(float, sys.argv[1:])
elapsed = elapsed_ns / 1e9
if elapsed <= 0:
    print("0.0")
else:
    print(f"{((after-before)/hz)/elapsed*100:.1f}")
PY
}

wait_for_iperf_server() {
	local bind_address="$1"
	local attempt

	for ((attempt = 0; attempt < 100; attempt++)); do
		if ip netns exec "${NS_SERVER}" ss -ltn "sport = :${IPERF_PORT}" 2>/dev/null | grep -Fq LISTEN; then
			return 0
		fi
		if ! kill -0 "${IPERF_PID}" >/dev/null 2>&1; then
			echo "error: iperf3 server exited before listening on ${bind_address}:${IPERF_PORT}" >&2
			return 1
		fi
		sleep 0.02
	done

	echo "error: timed out waiting for iperf3 server on ${bind_address}:${IPERF_PORT}" >&2
	return 1
}

start_iperf_server() {
	local bind_address="$1"
	local label="$2"
	local log_file="${LOG_DIR}/iperf-server-${label}.log"

	ip netns exec "${NS_SERVER}" \
		iperf3 -s -1 -B "${bind_address}" -p "${IPERF_PORT}" \
		>"${log_file}" 2>&1 &
	IPERF_PID=$!
	wait_for_iperf_server "${bind_address}"
}

finish_iperf_server() {
	local status=0
	if [[ -n "${IPERF_PID}" ]]; then
		wait "${IPERF_PID}" || status=$?
		IPERF_PID=""
	fi
	return "${status}"
}

json_tcp_summary() {
	local json_file="$1"
	python3 - "${json_file}" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    d = json.load(f)
if d.get('error'):
    raise SystemExit(f"iperf3 error: {d['error']}")
end = d.get('end', {})
summary = end.get('sum_received') or end.get('sum') or end.get('sum_sent') or {}
bps = float(summary.get('bits_per_second') or 0.0)
sent = end.get('sum_sent') or {}
retrans = int(sent.get('retransmits') or 0)
print(f"{bps/1e6:.3f} {retrans}")
PY
}

json_udp_summary() {
	local json_file="$1"
	python3 - "${json_file}" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    d = json.load(f)
if d.get('error'):
    raise SystemExit(f"iperf3 error: {d['error']}")
end = d.get('end', {})
summary = end.get('sum_received') or end.get('sum') or end.get('sum_sent') or {}
bps = float(summary.get('bits_per_second') or 0.0)
loss = float(summary.get('lost_percent') or 0.0)
jitter = float(summary.get('jitter_ms') or 0.0)
packets = int(summary.get('packets') or 0)
lost = int(summary.get('lost_packets') or 0)
print(f"{bps/1e6:.3f} {loss:.3f} {jitter:.3f} {packets} {lost}")
PY
}

run_raw_baseline() {
	local json_file="${LOG_DIR}/iperf-raw.json"
	start_iperf_server "${SERVER_OUTER}" "raw"
	ip netns exec "${NS_CLIENT}" \
		iperf3 -c "${SERVER_OUTER}" -p "${IPERF_PORT}" \
		-P "${RAW_STREAMS}" -t "${RAW_DURATION}" -J \
		>"${json_file}"
	finish_iperf_server

	local mbps retrans
	read -r mbps retrans < <(json_tcp_summary "${json_file}")
	printf 'raw veth baseline: %.1f Mbit/s (P=%s, retrans=%s)\n' "${mbps}" "${RAW_STREAMS}" "${retrans}"
}

run_raw_udp_baseline() {
	local json_file="${LOG_DIR}/iperf-raw-udp.json"
	start_iperf_server "${SERVER_OUTER}" "raw-udp"
	ip netns exec "${NS_CLIENT}" \
		iperf3 -c "${SERVER_OUTER}" -p "${IPERF_PORT}" \
		-u -b "${UDP_RATE}" -l "${UDP_LENGTH}" -t "${UDP_DURATION}" -J \
		>"${json_file}"
	finish_iperf_server

	local mbps loss jitter packets lost
	read -r mbps loss jitter packets lost < <(json_udp_summary "${json_file}")
	printf 'raw UDP baseline:  %.1f Mbit/s at target=%s, loss=%.2f%%, jitter=%.3fms\n' \
		"${mbps}" "${UDP_RATE}" "${loss}" "${jitter}"
}

run_tcp_case() {
	local direction="$1"
	local streams="$2"
	local reverse_arg=()
	local label="tcp-${direction}-p${streams}"
	local json_file="${LOG_DIR}/iperf-${label}.json"

	if [[ "${direction}" == "reverse" ]]; then
		reverse_arg=(-R)
	fi

	start_iperf_server "${SERVER_TUNNEL}" "${label}"

	local client_before server_before client_after server_after started ended elapsed_ns
	client_before="$(process_ticks "${CLIENT_PID}")"
	server_before="$(process_ticks "${SERVER_PID}")"
	started="$(date +%s%N)"

	ip netns exec "${NS_CLIENT}" \
		iperf3 -c "${SERVER_TUNNEL}" -p "${IPERF_PORT}" \
		-P "${streams}" -O "${TCP_OMIT}" -t "${TCP_DURATION}" \
		"${reverse_arg[@]}" -J \
		>"${json_file}"

	ended="$(date +%s%N)"
	client_after="$(process_ticks "${CLIENT_PID}")"
	server_after="$(process_ticks "${SERVER_PID}")"
	finish_iperf_server

	elapsed_ns=$((ended - started))
	local client_cpu server_cpu mbps retrans
	client_cpu="$(cpu_percent "${client_before}" "${client_after}" "${elapsed_ns}")"
	server_cpu="$(cpu_percent "${server_before}" "${server_after}" "${elapsed_ns}")"
	read -r mbps retrans < <(json_tcp_summary "${json_file}")

	printf 'tcp %-7s P=%-2s %9.1f Mbit/s  clientCPU=%6s%% serverCPU=%6s%% retrans=%s\n' \
		"${direction}" "${streams}" "${mbps}" "${client_cpu}" "${server_cpu}" "${retrans}"
	printf 'tcp\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"${direction}" "${streams}" "${mbps}" "${client_cpu}" "${server_cpu}" "${retrans}" \
		>>"${RESULTS_FILE}"
}

run_udp_case() {
	local direction="$1"
	local reverse_arg=()
	local label="udp-${direction}"
	local json_file="${LOG_DIR}/iperf-${label}.json"

	if [[ "${direction}" == "reverse" ]]; then
		reverse_arg=(-R)
	fi

	start_iperf_server "${SERVER_TUNNEL}" "${label}"

	local client_before server_before client_after server_after started ended elapsed_ns
	client_before="$(process_ticks "${CLIENT_PID}")"
	server_before="$(process_ticks "${SERVER_PID}")"
	started="$(date +%s%N)"

	ip netns exec "${NS_CLIENT}" \
		iperf3 -c "${SERVER_TUNNEL}" -p "${IPERF_PORT}" \
		-u -b "${UDP_RATE}" -l "${UDP_LENGTH}" -t "${UDP_DURATION}" \
		"${reverse_arg[@]}" -J \
		>"${json_file}"

	ended="$(date +%s%N)"
	client_after="$(process_ticks "${CLIENT_PID}")"
	server_after="$(process_ticks "${SERVER_PID}")"
	finish_iperf_server

	elapsed_ns=$((ended - started))
	local client_cpu server_cpu mbps loss jitter packets lost
	client_cpu="$(cpu_percent "${client_before}" "${client_after}" "${elapsed_ns}")"
	server_cpu="$(cpu_percent "${server_before}" "${server_after}" "${elapsed_ns}")"
	read -r mbps loss jitter packets lost < <(json_udp_summary "${json_file}")

	printf 'udp %-7s target=%-5s %9.1f Mbit/s  loss=%6.2f%% jitter=%6.3fms clientCPU=%6s%% serverCPU=%6s%%\n' \
		"${direction}" "${UDP_RATE}" "${mbps}" "${loss}" "${jitter}" "${client_cpu}" "${server_cpu}"
	printf 'udp\t%s\t1\t%s\t%s\t%s\t%s\n' \
		"${direction}" "${mbps}" "${client_cpu}" "${server_cpu}" "${loss}" \
		>>"${RESULTS_FILE}"
}

print_peak_summary() {
	python3 - "${RESULTS_FILE}" <<'PY'
import sys
rows = []
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 7 or parts[0] != 'tcp':
            continue
        kind, direction, streams, mbps, ccpu, scpu, retrans = parts
        rows.append((direction, int(streams), float(mbps), float(ccpu), float(scpu), int(retrans)))
for direction in ('forward', 'reverse'):
    candidates = [r for r in rows if r[0] == direction]
    if not candidates:
        continue
    best = max(candidates, key=lambda r: r[2])
    print(f"peak TCP {direction}: {best[2]:.1f} Mbit/s at P={best[1]} "
          f"(clientCPU={best[3]:.1f}%, serverCPU={best[4]:.1f}%, retrans={best[5]})")
PY
}

require_benchmark_prerequisites
create_live_topology
start_live_server
start_live_client
assert_live_processes
RESULTS_FILE="${LOG_DIR}/throughput.tsv"
: >"${RESULTS_FILE}"

echo "=== host / benchmark configuration ==="
echo "kernel: $(uname -r)"
echo "iperf3: $(iperf3 --version 2>&1 | head -n 1)"
echo "logical CPUs: $(nproc)"
if command -v lscpu >/dev/null 2>&1; then
	lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print "CPU: " $2; exit}'
fi
echo "GOMAXPROCS override: ${OL3_GOMAXPROCS:-default (Go runtime CPU count)}"
echo "tunnel MTU: ${MTU}"
echo "TCP duration: ${TCP_DURATION}s + ${TCP_OMIT}s omit"
echo "TCP streams: ${TCP_STREAMS}"
echo "UDP offered load: ${UDP_RATE}, payload=${UDP_LENGTH}, duration=${UDP_DURATION}s"
echo

echo "baseline tunnel ping"
ip netns exec "${NS_CLIENT}" ping -n -c 2 -W 1 "${SERVER_TUNNEL}" >/dev/null
ip netns exec "${NS_SERVER}" ping -n -c 2 -W 1 "${CLIENT_TUNNEL}" >/dev/null

echo "=== raw namespace/veth ceiling (tunnel bypassed) ==="
run_raw_baseline
run_raw_udp_baseline

echo
echo "=== encrypted tunnel TCP sweep ==="
for streams in ${TCP_STREAMS}; do
	run_tcp_case forward "${streams}"
done
for streams in ${TCP_STREAMS}; do
	run_tcp_case reverse "${streams}"
done

echo
echo "=== encrypted tunnel UDP overload probe ==="
run_udp_case forward
run_udp_case reverse

echo
echo "=== peak summary ==="
print_peak_summary

assert_live_processes

echo
echo "DONE: throughput benchmark completed"
