# Usage

## Installation and administration

The server installer targets Linux systems using systemd and `iptables`. It installs prebuilt binaries from `./bin`, creates keys and configuration under `/etc/noranite`, configures `nrnt0`, forwarding/NAT, and starts the service.

On Debian/Ubuntu, the server can be installed with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/noranite/Noranite-l3/main/quick-install | sudo bash
```

The quick installer downloads the source from GitHub into a temporary directory, uses a temporary Go toolchain of the required version when necessary, builds the server binaries, and runs the standard installer. On first install it automatically detects the Internet-facing interface and asks for the tunnel address, UDP port, MTU (1380 or lower is recommended), and local-network access mode. On subsequent runs, existing `/etc/noranite/server.env`, keys, and peers are preserved.

For a manual installation, first build the required binaries from the repository root:

```bash
mkdir -p bin
go build -o bin/opaque-server ./cmd/opaque-server
go build -o bin/noranitectl ./cmd/noranitectl
go build -o bin/noranite-peer ./cmd/noranite-peer
go build -o bin/opaque-keygen ./cmd/opaque-keygen
```

Basic installation:

```bash
sudo ./install/server/install.sh
```

The defaults are tunnel `10.66.0.1/16`, UDP bind `0.0.0.0:41675`, and MTU `1380`; the Internet-facing interface is detected from the default route. On first install, the main parameters can be specified explicitly:

```bash
sudo ./install/server/install.sh \
  --egress-interface eth0 \
  --tunnel-address 10.66.0.1/16 \
  --bind 0.0.0.0:41675 \
  --mtu 1380 \
  --local-access deny
```

`--local-access deny` is the default: VPN peers receive Internet egress but cannot access the VPN server itself or local networks. `--local-access allow` removes this additional isolation; further access is then controlled by the host's own routing and firewall configuration.

After installation, the main files live under `/etc/noranite`:

```text
server.env       network/runtime parameters
install.state     host state needed for clean uninstall
route.key        shared K_route
server.private   server X25519 private key
server.public    server X25519 public key
server.peers     persistent bootstrap peers
```

Service status and logs:

```bash
sudo systemctl status noranite-server
sudo systemctl restart noranite-server
sudo journalctl -u noranite-server -f
```

To completely remove the server, including keys, persistent peers, systemd units, firewall rules, and installed binaries:

```bash
sudo ./uninstall
```

`uninstall` asks for explicit confirmation before removing `/etc/noranite`. For non-interactive use, run `sudo ./uninstall --yes`. It does not remove OS packages that may have existed before Noranite or may be used by other software.

### Peers

`/etc/noranite/server.peers` is loaded on every process start. Each line has the following format:

```text
<tunnel-ipv4> <client-public-key> [name]
```

For example:

```text
10.66.0.2 BASE64_KEY alice
```

Peers loaded from the file go through the same runtime Controller used by dynamic operations. If the file is invalid or contains conflicting IPs or keys, the server refuses to start.

A running server is managed through the local Unix socket `/run/noranite/control.sock`, created with mode `0600`. There is no remote management API; SSH plus `sudo noranitectl` is sufficient for remote administration.

`noranitectl` is the low-level runtime control interface:

```bash
sudo noranitectl peer list
sudo noranitectl peer set --ip 10.66.0.2 --public-key BASE64_KEY
sudo noranitectl peer remove --public-key BASE64_KEY
sudo noranitectl peer sync --file /etc/noranite/server.peers
```

`peer list`, `peer set`, and `peer remove` operate on the running server only and do not modify `server.peers`. `peer set` is idempotent. Repeating the same pair changes nothing; setting the same public key with a different IP replaces the runtime peer and drops its active sessions. An IP already assigned to another public key cannot be reused.

`peer sync --file FILE` loads the complete peer set from `FILE` and replaces the runtime peer configuration with that snapshot. It does not modify the file. This is the machine-oriented entry point for workflows that manage the peer file themselves. For example, after editing `/etc/noranite/server.peers` directly, apply the complete desired state without restarting the server:

```bash
sudo noranitectl peer sync --file /etc/noranite/server.peers
```

For normal client provisioning, use `noranite-peer`. It manages the persistent peer file and keeps the running server in sync with it. `add` generates a client X25519 keypair, selects the first free address in the configured `/16`, writes the peer to `server.peers`, and applies it to the running server:

```bash
sudo noranite-peer add \
  --tunnel-address 10.66.0.1/16 \
  --private-key-out ./alice.key \
  --public-key-out ./alice.pub
```

To remove a provisioned peer from both the persistent configuration and the running server:

```bash
sudo noranite-peer remove --public-key BASE64_KEY
```

Both commands use `/etc/noranite/server.peers` by default; use `--peers-file PATH` to select another persistent peer file. The persistent file is updated before the runtime operation. If the point runtime update fails, `noranite-peer` attempts a full runtime reconciliation from the peer file.

On process restart, the server loads `server.peers` again, so the persistent file remains the desired peer set across restarts.

## Client based on sing-box

To use Noranite as an endpoint in a full TUN/proxy client, build sing-box with the Noranite reference integration.

The integration targets **sing-box v1.13.15** and is provided as a standalone patch:

```text
integrations/sing-box/sing-box-1.13.15-noranite-integration.patch
```

### Build

1. Clone the sing-box source and check out `v1.13.15`:

```bash
git clone https://github.com/SagerNet/sing-box.git
cd sing-box
git checkout v1.13.15
```

2. Apply the Noranite patch:

```bash
git apply /path/to/Noranite-l3/integrations/sing-box/sing-box-1.13.15-noranite-integration.patch
```

3. Point the sing-box module at your local Noranite-l3 checkout:

```bash
go mod edit \
  -require=github.com/noranite/Noranite-l3@v0.0.0 \
  -replace=github.com/noranite/Noranite-l3=/path/to/Noranite-l3

go mod tidy
```

4. Build sing-box using its normal build process, adding the `with_noranite` build tag.

On Linux/macOS:

```bash
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_noranite"
make build TAGS="$TAGS"
```

On Windows, use the build-tag set from:

```text
release/DEFAULT_BUILD_TAGS_WINDOWS
```

and add:

```text
with_noranite
```

The integration requires `with_gvisor`; that tag is already included in the standard sing-box v1.13.15 build-tag sets.

After building, a `noranite` endpoint becomes available in the configuration:

```json
{
  "type": "noranite",
  "tag": "noranite",
  "server": "203.0.113.1",
  "server_port": 443,
  "address": "10.0.0.2",
  "mtu": 1380,
  "route_key": "<base64>",
  "private_key": "<base64>",
  "server_public_key": "<base64>"
}
```

The patch is a reference integration of Noranite with sing-box, not a separate sing-box distribution.

sing-box is distributed separately by its authors and is used here as a third-party platform. Noranite is not affiliated with SagerNet or the sing-box maintainers.