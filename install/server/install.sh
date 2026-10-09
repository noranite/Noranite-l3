#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
CONFIG_DIR="/etc/noranite"
CONFIG_FILE="${CONFIG_DIR}/server.env"
INSTALL_STATE_FILE="${CONFIG_DIR}/install.state"
LIBEXEC_DIR="/usr/local/libexec/noranite"
SYSTEMD_DIR="/etc/systemd/system"

EGRESS_IFACE=""
TUNNEL_ADDRESS="10.66.0.1/16"
BIND_ADDRESS="0.0.0.0:41675"
MTU="1380"
LOCAL_ACCESS="deny"
NETWORK_OPTION_SEEN=0
FIRST_INSTALL=0

usage() {
	cat <<USAGE
usage: $0 [options]

Installs a Noranite server from prebuilt binaries in ./bin.
Existing /etc/noranite/server.env and keys are preserved on upgrade.

options:
  --bin-dir DIR              directory containing built Noranite binaries
  --egress-interface IFACE   Internet-facing interface (auto-detected initially)
  --tunnel-address IP/16     server tunnel address (default: 10.66.0.1/16)
  --bind IPv4:PORT           UDP listen address (default: 0.0.0.0:41675)
  --mtu MTU                  tunnel MTU (default: 1380)
  --local-access MODE        local/LAN access: deny or allow (default: deny)
  -h, --help                 show this help
USAGE
}

while (($#)); do
	case "$1" in
		--bin-dir)
			BIN_DIR="$2"
			shift 2
			;;
		--egress-interface)
			EGRESS_IFACE="$2"
			NETWORK_OPTION_SEEN=1
			shift 2
			;;
		--tunnel-address)
			TUNNEL_ADDRESS="$2"
			NETWORK_OPTION_SEEN=1
			shift 2
			;;
		--bind)
			BIND_ADDRESS="$2"
			NETWORK_OPTION_SEEN=1
			shift 2
			;;
		--mtu)
			MTU="$2"
			NETWORK_OPTION_SEEN=1
			shift 2
			;;
		--local-access)
			LOCAL_ACCESS="$2"
			NETWORK_OPTION_SEEN=1
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "error: unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

case "${LOCAL_ACCESS}" in
	deny|allow) ;;
	*)
		echo "error: --local-access must be deny or allow" >&2
		exit 2
		;;
esac

if (( EUID != 0 )); then
	echo "error: installer must run as root" >&2
	exit 1
fi

for command_name in install ip iptables sysctl systemctl awk head base64 tr; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		echo "error: required command not found: ${command_name}" >&2
		exit 1
	fi
done

for binary in opaque-server noranitectl noranite-peer opaque-keygen; do
	if [[ ! -x "${BIN_DIR}/${binary}" ]]; then
		echo "error: required binary not found or not executable: ${BIN_DIR}/${binary}" >&2
		exit 1
	fi
done

if [[ -e "${CONFIG_FILE}" ]] && (( NETWORK_OPTION_SEEN )); then
	echo "error: ${CONFIG_FILE} already exists; edit it explicitly instead of overwriting it during upgrade" >&2
	exit 1
fi

if [[ ! -e "${CONFIG_FILE}" ]]; then
	FIRST_INSTALL=1
fi

install -d -m 0700 "${CONFIG_DIR}"
install -d -m 0755 /usr/local/bin
install -d -m 0755 "${LIBEXEC_DIR}"

install -m 0755 "${BIN_DIR}/opaque-server" /usr/local/bin/opaque-server
install -m 0755 "${BIN_DIR}/noranitectl" /usr/local/bin/noranitectl
install -m 0755 "${BIN_DIR}/noranite-peer" /usr/local/bin/noranite-peer
install -m 0755 "${BIN_DIR}/opaque-keygen" /usr/local/bin/opaque-keygen
install -m 0755 "${SCRIPT_DIR}/network.sh" "${LIBEXEC_DIR}/server-network"
install -m 0644 "${SCRIPT_DIR}/noranite-server-network.service" "${SYSTEMD_DIR}/noranite-server-network.service"
install -m 0644 "${SCRIPT_DIR}/noranite-server.service" "${SYSTEMD_DIR}/noranite-server.service"

if [[ -e "${CONFIG_FILE}" ]]; then
	echo "preserving existing ${CONFIG_FILE}"
else
	if [[ -z "${EGRESS_IFACE}" ]]; then
		EGRESS_IFACE="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
	fi
	if [[ -z "${EGRESS_IFACE}" ]]; then
		EGRESS_IFACE="$(ip -4 route show default | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
	fi
	if [[ -z "${EGRESS_IFACE}" ]]; then
		echo "error: could not auto-detect Internet egress interface; use --egress-interface" >&2
		exit 1
	fi
	if ! ip link show dev "${EGRESS_IFACE}" >/dev/null 2>&1; then
		echo "error: egress interface does not exist: ${EGRESS_IFACE}" >&2
		exit 1
	fi

	umask 077
	cat >"${CONFIG_FILE}" <<CONFIG
NRNT_EGRESS_IFACE='${EGRESS_IFACE}'
NRNT_TUNNEL_ADDRESS='${TUNNEL_ADDRESS}'
NRNT_BIND='${BIND_ADDRESS}'
NRNT_MTU='${MTU}'
NRNT_LOCAL_ACCESS='${LOCAL_ACCESS}'
CONFIG
	echo "created ${CONFIG_FILE}"
fi

if [[ ! -e "${CONFIG_DIR}/route.key" ]]; then
	umask 077
	head -c 32 /dev/urandom | base64 >"${CONFIG_DIR}/route.key"
	echo "generated ${CONFIG_DIR}/route.key"
fi

if [[ ! -e "${CONFIG_DIR}/server.private" ]]; then
	/usr/local/bin/opaque-keygen \
		-private-out "${CONFIG_DIR}/server.private" \
		-public-out "${CONFIG_DIR}/server.public" \
		>/dev/null
	echo "generated server keypair"
elif [[ ! -e "${CONFIG_DIR}/server.public" ]]; then
	echo "warning: server.private exists but server.public is missing; private key was preserved" >&2
fi

if [[ ! -e "${CONFIG_DIR}/server.peers" ]]; then
	install -m 0600 /dev/null "${CONFIG_DIR}/server.peers"
fi

if (( FIRST_INSTALL )) && [[ ! -e "${INSTALL_STATE_FILE}" ]]; then
	original_ip_forward="$(sysctl -n net.ipv4.ip_forward)"
	case "${original_ip_forward}" in
		0|1) ;;
		*)
		echo "error: unexpected net.ipv4.ip_forward value: ${original_ip_forward}" >&2
		exit 1
		;;
	esac
	umask 077
	printf 'NRNT_ORIGINAL_IP_FORWARD=%s\n' "${original_ip_forward}" >"${INSTALL_STATE_FILE}"
fi

systemctl daemon-reload

# Network rules are persistent machine configuration, not daemon lifetime state.
# Reconcile them without tearing them down during an ordinary server upgrade.
systemctl start noranite-server-network.service
"${LIBEXEC_DIR}/server-network" up
systemctl enable noranite-server.service >/dev/null
systemctl restart noranite-server.service

if ! systemctl is-active --quiet noranite-server.service; then
	systemctl --no-pager --full status noranite-server.service >&2 || true
	exit 1
fi

echo "Noranite server is active"
echo "  TUN:            nrnt0"
echo "  control socket: /run/noranite/control.sock"
echo "  config:         ${CONFIG_FILE}"
if [[ -r "${CONFIG_DIR}/server.public" ]]; then
	echo "  server public:  $(tr -d '\r\n' <"${CONFIG_DIR}/server.public")"
fi
