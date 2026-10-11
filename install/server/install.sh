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
ROUTE_KEY=""
SERVER_PRIVATE_KEY=""
SERVER_PUBLIC_KEY=""
NETWORK_OPTION_SEEN=0
FIRST_INSTALL=0

usage() {
	cat <<USAGE
usage: $0 [options]

Installs a Noranite server from prebuilt binaries in ./bin.
Existing /etc/noranite/server.env is preserved on upgrade. Existing keys are preserved unless an explicit complete key set is supplied.

options:
  --bin-dir DIR              directory containing built Noranite binaries
  --egress-interface IFACE   Internet-facing interface (auto-detected initially)
  --tunnel-address IP/16     server tunnel address (default: 10.66.0.1/16)
  --bind IPv4:PORT           UDP listen address (default: 0.0.0.0:41675)
  --mtu MTU                  tunnel MTU (default: 1380)
  --local-access MODE        local/LAN access: deny or allow (default: deny)
  --route-key BASE64         32-byte route key in standard Base64
  --server-private-key BASE64
                              32-byte server X25519 private key in standard Base64
  --server-public-key BASE64
                              32-byte server X25519 public key in standard Base64
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
		--route-key)
			ROUTE_KEY="$2"
			shift 2
			;;
		--server-private-key)
			SERVER_PRIVATE_KEY="$2"
			shift 2
			;;
		--server-public-key)
			SERVER_PUBLIC_KEY="$2"
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


validate_key32() {
	local option_name="$1"
	local value="$2"

	# Standard Base64 for exactly 32 bytes is always 44 characters with one '=' padding byte.
	if [[ ! "${value}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
		echo "error: ${option_name} must be standard Base64 encoding exactly 32 bytes" >&2
		exit 2
	fi
}

key_option_count=0
[[ -n "${ROUTE_KEY}" ]] && ((key_option_count += 1))
[[ -n "${SERVER_PRIVATE_KEY}" ]] && ((key_option_count += 1))
[[ -n "${SERVER_PUBLIC_KEY}" ]] && ((key_option_count += 1))

if (( key_option_count != 0 && key_option_count != 3 )); then
	echo "error: --route-key, --server-private-key and --server-public-key must be supplied together" >&2
	exit 2
fi

if (( key_option_count == 3 )); then
	validate_key32 --route-key "${ROUTE_KEY}"
	validate_key32 --server-private-key "${SERVER_PRIVATE_KEY}"
	validate_key32 --server-public-key "${SERVER_PUBLIC_KEY}"
fi

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

for command_name in install ip iptables sysctl systemctl awk tr; do
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

if (( FIRST_INSTALL && key_option_count != 3 )); then
	echo "error: first install requires --route-key, --server-private-key and --server-public-key" >&2
	exit 2
fi

install -d -m 0700 "${CONFIG_DIR}"
install -d -m 0755 /usr/local/bin
install -d -m 0755 "${LIBEXEC_DIR}"

install -m 0755 "${BIN_DIR}/opaque-server" /usr/local/bin/opaque-server
install -m 0755 "${BIN_DIR}/noranitectl" /usr/local/bin/noranitectl
install -m 0755 "${BIN_DIR}/noranite-peer" /usr/local/bin/noranite-peer
install -m 0755 "${BIN_DIR}/opaque-keygen" /usr/local/bin/opaque-keygen
install -m 0755 "${ROOT_DIR}/uninstall" /usr/local/bin/noranite-uninstall
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

if (( key_option_count == 3 )); then
	umask 077
	printf '%s\n' "${ROUTE_KEY}" >"${CONFIG_DIR}/route.key"
	printf '%s\n' "${SERVER_PRIVATE_KEY}" >"${CONFIG_DIR}/server.private"
	printf '%s\n' "${SERVER_PUBLIC_KEY}" >"${CONFIG_DIR}/server.public"
	chmod 0600 "${CONFIG_DIR}/route.key" "${CONFIG_DIR}/server.private"
	chmod 0644 "${CONFIG_DIR}/server.public"
	echo "installed supplied route key and server keypair"
else
	for key_file in route.key server.private server.public; do
		if [[ ! -r "${CONFIG_DIR}/${key_file}" ]]; then
			echo "error: existing installation is missing ${CONFIG_DIR}/${key_file}; supply a complete key set" >&2
			exit 1
		fi
	done
	echo "preserving existing route key and server keypair"
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
