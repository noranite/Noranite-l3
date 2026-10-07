# Opaque-L3 live tests

These tests exercise the real Linux path:

```text
TUN -> runtime -> session/core -> UDP -> session/core -> runtime -> TUN
```

They use two Linux network namespaces connected by a veth pair. Establishment is
always the production `Noise_IK_25519_ChaChaPoly_BLAKE2s` path; there is no
plaintext development handshake or static traffic-session shortcut in the live
harness.

## Build and prerequisites

Linux with `iproute2`, `ping`, TUN support, and permission to create network
namespaces and TUN devices is required.

Build as the normal user:

```bash
./test/live/build.sh
```

For a correctness-only race-instrumented build:

```bash
OL3_RACE=1 ./test/live/build.sh
```

Do not use race binaries for throughput measurements.

## Basic and rekey regression

Run as root:

```bash
sudo ./test/live/run-basic.sh
sudo ./test/live/run-rekey.sh
sudo ./test/live/run-rekey-stress.sh
```

`run-basic.sh` creates isolated namespaces, generates ephemeral Noise static
identities, starts `opaque-server` and `opaque-client`, configures their TUN
interfaces, verifies tunnel ICMP in both directions, and removes the
namespaces/processes on exit.

`run-rekey.sh` keeps ICMP traffic flowing while it requests rekey with
`SIGUSR1`, waits until the client reports a different current Session ID,
requires zero packet loss during the local A -> B transition, then verifies both
tunnel directions after old-generation receive grace has elapsed.

`run-rekey-stress.sh` performs 100 sequential rekeys by default while one
continuous ICMP stream exercises both directions. Each observed transition must
form one monotonic `previous -> current` chain and stay below the configured
local latency threshold.

Useful overrides:

```bash
sudo OL3_REKEY_COUNT=1000 ./test/live/run-rekey-stress.sh
sudo OL3_REKEY_MAX_LATENCY_MS=2000 ./test/live/run-rekey-stress.sh
sudo OL3_REKEY_SETTLE=0 ./test/live/run-rekey-stress.sh
```

## Noise-aware fault injection

The test-only UDP proxy knows only `K_route` and therefore only the opaque route
header. It never decrypts or parses the Noise payload. `session_id == 0`
identifies establishment traffic; direction distinguishes client INIT from
server RESPONSE. Traffic-session IDs are learned later from the first client
transport route observed after a forwarded RESPONSE.

Run the targeted lifecycle fault suite:

```bash
sudo ./test/live/run-rekey-faults.sh
```

It covers:

- `lost-activation`: forward Noise RESPONSE(B), then drop the first client
  transport datagram. Ordinary DATA(B) must still promote server pending B.
- `lost-response`: drop the first rekey Noise RESPONSE. DATA(A) remains usable
  while the client retries establishment and installs the retry generation.
- `superseded-pending`: block all B transport after RESPONSE(B), then request C.
  RESPONSE(C) must supersede unactivated pending B and transport must recover on
  C.

Individual cases:

```bash
sudo ./test/live/run-rekey-fault-case.sh lost-activation
sudo ./test/live/run-rekey-fault-case.sh lost-response
sudo ./test/live/run-rekey-fault-case.sh superseded-pending
```

Run the broader adversarial suite:

```bash
sudo ./test/live/run-adversarial.sh
```

The cases are:

- `old-generation-grace`: hold four real DATA(A) datagrams across B activation;
  two are released inside previous-generation grace and two after it.
- `duplicate-replay`: duplicate exact encrypted activation/DATA datagrams and
  their replies; replay handling must suppress duplicate logical delivery.
- `chaos-rapid-rotation`: deterministic finite loss/duplicate/delay/reorder while
  the client performs rapid A -> B -> C -> D rotations.
- `persistent-establishment-loss`: drop every rekey Noise RESPONSE across
  multiple retry intervals while DATA(A) remains usable.
- `mtu-boundary`: exercise exact inner MTU in both directions and through a
  rekey, then verify a one-byte-oversized DF packet stays outside the tunnel.
- `client-restart`: restart the client while the server remains alive, require a
  fresh Noise bootstrap, then require another live rekey.

## Local throughput diagnostic

`run-throughput.sh` remains a one-host namespace diagnostic. It measures the
current production Noise/runtime implementation only; it is not the two-host
reference benchmark.

```bash
sudo ./test/live/run-throughput.sh
```

Use `test/remote/` for physical-host acceptance, 1-peer/10-peer performance,
random/minimum-packet traffic, and the pinned `wireguard-go` comparison.
