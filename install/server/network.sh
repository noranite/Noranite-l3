#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${NORANITE_SERVER_ENV:-/etc/noranite/server.env}"
TUN_IFACE="nrnt0"
INPUT_CHAIN="NORANITE-IN"
FORWARD_CHAIN="NORANITE-FWD"
NAT_CHAIN="NORANITE-NAT"

ipt() {
	iptables -w 5 "$@"
}

remove_jump() {
	local table="$1" parent="$2" chain="$3"
	while ipt -t "${table}" -C "${parent}" -j "${chain}" >/dev/null 2>&1; do
		ipt -t "${table}" -D "${parent}" -j "${chain}"
	done
}

network_down() {
	remove_jump filter INPUT "${INPUT_CHAIN}"
	remove_jump filter FORWARD "${FORWARD_CHAIN}"
	remove_jump nat POSTROUTING "${NAT_CHAIN}"

	ipt -t filter -F "${INPUT_CHAIN}" >/dev/null 2>&1 || true
	ipt -t filter -X "${INPUT_CHAIN}" >/dev/null 2>&1 || true
	ipt -t filter -F "${FORWARD_CHAIN}" >/dev/null 2>&1 || true
	ipt -t filter -X "${FORWARD_CHAIN}" >/dev/null 2>&1 || true
	ipt -t nat -F "${NAT_CHAIN}" >/dev/null 2>&1 || true
	ipt -t nat -X "${NAT_CHAIN}" >/dev/null 2>&1 || true
}

load_config() {
	# shellcheck disable=SC1090
	source "${CONFIG_FILE}"
	: "${NRNT_EGRESS_IFACE:?NRNT_EGRESS_IFACE is required}"
	: "${NRNT_TUNNEL_ADDRESS:?NRNT_TUNNEL_ADDRESS is required}"
	: "${NRNT_BIND:?NRNT_BIND is required}"
	: "${NRNT_MTU:?NRNT_MTU is required}"
	NRNT_LOCAL_ACCESS="${NRNT_LOCAL_ACCESS:-deny}"
	case "${NRNT_LOCAL_ACCESS}" in
		deny|allow) ;;
		*)
			echo "error: NRNT_LOCAL_ACCESS must be 'deny' or 'allow'" >&2
			return 1
			;;
	esac
	if [[ "${NRNT_TUNNEL_ADDRESS}" != */16 ]]; then
		echo "error: NRNT_TUNNEL_ADDRESS must use /16" >&2
		return 1
	fi

	local address="${NRNT_TUNNEL_ADDRESS%/*}"
	local a b _c _d
	IFS=. read -r a b _c _d <<<"${address}"
	NRNT_TUNNEL_SUBNET="${a}.${b}.0.0/16"
	NRNT_UDP_PORT="${NRNT_BIND##*:}"
}

reject_local_forwarding() {
	local destination

	# These address families are never treated as Internet egress. The final
	# nrnt0 reject below is still required because host routing may expose other
	# local/private networks through interfaces other than the configured egress.
	for destination in \
		10.0.0.0/8 \
		100.64.0.0/10 \
		169.254.0.0/16 \
		172.16.0.0/12 \
		192.168.0.0/16; do
		ipt -t filter -A "${FORWARD_CHAIN}" \
			-i "${TUN_IFACE}" -s "${NRNT_TUNNEL_SUBNET}" \
			-d "${destination}" -j REJECT
	done

	# A LAN can use public address space. Reject every directly connected IPv4
	# network on the Internet-facing interface before the general egress ACCEPT.
	while read -r destination; do
		[[ -n "${destination}" && "${destination}" != "default" ]] || continue
		ipt -t filter -A "${FORWARD_CHAIN}" \
			-i "${TUN_IFACE}" -s "${NRNT_TUNNEL_SUBNET}" \
			-d "${destination}" -j REJECT
	done < <(ip -4 route show dev "${NRNT_EGRESS_IFACE}" scope link | awk '{print $1}')
}

network_up() {
	load_config
	ip link show dev "${NRNT_EGRESS_IFACE}" >/dev/null
	sysctl -q -w net.ipv4.ip_forward=1

	# Remove our old entry points first. A failed rebuild may interrupt VPN
	# forwarding, but it cannot leave host traffic trapped in a partial ruleset.
	network_down

	ipt -t filter -N "${INPUT_CHAIN}"
	ipt -t filter -N "${FORWARD_CHAIN}"
	ipt -t nat -N "${NAT_CHAIN}"

	ipt -t filter -A "${INPUT_CHAIN}" \
		-i "${NRNT_EGRESS_IFACE}" -p udp --dport "${NRNT_UDP_PORT}" -j ACCEPT

	if [[ "${NRNT_LOCAL_ACCESS}" == "deny" ]]; then
		# Noranite owns this boundary in deny mode: VPN clients cannot reach
		# services on the VPN host itself.
		ipt -t filter -A "${INPUT_CHAIN}" \
			-i "${TUN_IFACE}" -s "${NRNT_TUNNEL_SUBNET}" -j REJECT
	fi

	ipt -t filter -A "${FORWARD_CHAIN}" \
		-i "${NRNT_EGRESS_IFACE}" -o "${TUN_IFACE}" \
		-d "${NRNT_TUNNEL_SUBNET}" \
		-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

	if [[ "${NRNT_LOCAL_ACCESS}" == "deny" ]]; then
		reject_local_forwarding
	fi

	ipt -t filter -A "${FORWARD_CHAIN}" \
		-i "${TUN_IFACE}" -o "${NRNT_EGRESS_IFACE}" \
		-s "${NRNT_TUNNEL_SUBNET}" -j ACCEPT

	if [[ "${NRNT_LOCAL_ACCESS}" == "deny" ]]; then
		# Do not let unmatched VPN traffic fall through to the host FORWARD
		# policy. In allow mode this RETURN behavior is intentional.
		ipt -t filter -A "${FORWARD_CHAIN}" \
			-i "${TUN_IFACE}" -s "${NRNT_TUNNEL_SUBNET}" -j REJECT
	fi

	ipt -t nat -A "${NAT_CHAIN}" \
		-s "${NRNT_TUNNEL_SUBNET}" -o "${NRNT_EGRESS_IFACE}" -j MASQUERADE

	# Publish only the complete chains.
	ipt -t filter -I INPUT 1 -j "${INPUT_CHAIN}"
	ipt -t filter -I FORWARD 1 -j "${FORWARD_CHAIN}"
	ipt -t nat -I POSTROUTING 1 -j "${NAT_CHAIN}"
}

tun_up() {
	load_config
	local attempt
	for ((attempt = 0; attempt < 100; attempt++)); do
		if ip link show dev "${TUN_IFACE}" >/dev/null 2>&1; then
			ip address replace "${NRNT_TUNNEL_ADDRESS}" dev "${TUN_IFACE}"
			ip link set dev "${TUN_IFACE}" mtu "${NRNT_MTU}" up
			return 0
		fi
		sleep 0.05
	done
	return 1
}

case "${1:-}" in
	up) network_up ;;
	down) network_down ;;
	tun-up) tun_up ;;
	*) echo "usage: $0 {up|down|tun-up}" >&2; exit 2 ;;
esac
