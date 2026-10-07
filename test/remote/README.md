# Two-host acceptance and benchmark harness

This harness is for the physical two-server tests. Run it on the **client
host** as root; it controls the second host over root SSH.

The client host creates 1 or 10 network namespaces behind a temporary bridge
and NAT. Each namespace owns one tunnel client. The server host always runs one
server instance/interface with all configured peers, so the 10-peer run tests
shared server queues/workers rather than ten independent servers.

Opaque always uses production Noise IK. The reference implementation is
`wireguard-go` built from the exact module revision pinned in this repository's
`go.mod` (`ecfc5a8d5446` at the time this harness was added).

## Prerequisites

On the client host:

- Linux, root, TUN support;
- `ip`, `iptables`, `ping`, `ssh`, `scp`, `wg`, `iperf3`, `python3`;
- passwordless/root SSH to the server host.

On the server host:

- Linux, root, TUN support;
- `ip`, `ping`, `wg`, `iperf3`.

The harness copies `opaque-server`, `opaque-trafficgen`, and the pinned
`wireguard-go` binary to a temporary directory on the server. Both machines
must therefore use a compatible Linux architecture/ABI.

Outer UDP ports default to 51820 for Opaque and 51822 for wireguard-go. They
must be reachable from the client host. Tunnel benchmarking itself does not
require exposing iperf TCP ports on the physical interface: iperf listens on
the inner tunnel address.

Build locally with the repository toolchain:

```bash
./test/remote/build.sh
```

## Environment

Required:

```bash
export OL3_SERVER_SSH=root@server-b
export OL3_SERVER_OUTER=203.0.113.20
```

`opaque-server` binds `0.0.0.0` by default, so `OL3_SERVER_OUTER` may be a
public/NAT address that is not assigned directly to the server interface. Set
`OL3_SERVER_BIND` when a specific local bind address is required.

Useful overrides:

```bash
export OL3_CLIENT_EGRESS_IFACE=eth0   # otherwise detected with `ip route get`
export OL3_MTU=1420
export OL3_RESULT_DIR=/var/tmp/ol3-results/run-001
```

The client namespaces use `198.18.77.0/24` by default and the inner tunnel uses
`10.88.0.0/24`. Override `OL3_NAMESPACE_PREFIX`, `OL3_SERVER_TUNNEL`, and
`OL3_TUNNEL_PREFIX` if those ranges conflict with the hosts.

## Production-Noise acceptance

```bash
sudo -E ./test/remote/run-acceptance.sh
```

This uses one physical server pair and runs:

1. bidirectional bootstrap traffic and live Noise rekey;
2. lost activation transport after a valid RESPONSE;
3. lost Noise RESPONSE followed by establishment retry;
4. persistent rekey RESPONSE loss while the active generation remains usable;
5. finite transport loss/duplication/delay/reordering during rapid rotations;
6. ten clients carrying traffic through one server process while all ten rekey
   concurrently.

The fault proxy sees only the opaque route header. It does not know Noise
session material or plaintext handshake fields.

## Performance comparison

Run the 1-peer matrix:

```bash
sudo -E OL3_PEERS=1 ./test/remote/run-benchmark.sh
```

Run the 10-peer matrix:

```bash
sudo -E OL3_PEERS=10 ./test/remote/run-benchmark.sh
```

Defaults are three repetitions and medians. Each implementation runs on the
same namespace topology, tunnel MTU, physical path, and test binaries.

For one peer, TCP tests `P=1`, `P=4`, and `P=8` in both directions. For ten
peers, ten simultaneous `P=1` flows are aggregated. UDP tests run in both
directions with:

- `fixed`: 1350-byte application payloads;
- `random`: deterministic per-packet sizes from 16 bytes through the largest
  non-fragmenting UDP payload for the configured inner MTU;
- `zero`: zero-byte UDP application payload, i.e. a 28-byte inner IPv4+UDP
  packet, intended to stress packet rate and per-packet bookkeeping.

`opaque-trafficgen` uses Linux batch UDP I/O through `ipv4.PacketConn`. Its
receiver reports delivered inner IPv4 Mbps and packet rate. Sender/receiver
packet counts are paired to report loss. The final summary prints medians and
an Opaque / wireguard-go throughput ratio.

Useful overrides:

```bash
sudo -E \
  OL3_PEERS=10 \
  OL3_REPETITIONS=5 \
  OL3_TCP_DURATION=20 \
  OL3_UDP_DURATION=20 \
  ./test/remote/run-benchmark.sh
```

`OL3_RAW_SANITY=1` additionally runs one direct physical-path TCP iperf test.
It is disabled by default because many remote hosts expose SSH/UDP while
firewalling arbitrary outer TCP ports.

## GC pressure check

The performance comparison intentionally does not instrument CPU or GC. The
client GC refactor has a separate worst-case packet-rate check:

```bash
sudo -E ./test/remote/run-gc-check.sh
```

It runs zero-payload UDP in both directions with `GODEBUG=gctrace=1` and saves
the endpoint GC logs. Override `OL3_GC_DURATION` for a longer sample. This is an
Opaque-only diagnostic, not part of the wireguard-go score.

## Notes

- Do not use `OL3_RACE=1` binaries for performance. Race builds are for the
  local/live correctness suite.
- The harness temporarily enables IPv4 forwarding and installs exact iptables
  NAT/FORWARD rules on the client host. Cleanup restores the previous forwarding
  setting and removes the namespaces/rules.
- A benchmark failure preserves the result directory. Endpoint test keys are
  ephemeral and live only in the local temporary state directory for that run.
