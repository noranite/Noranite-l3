#!/usr/bin/env python3
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

TCP_RE = re.compile(
    r"^(opaque|wg-go)-(\d+)p-r(\d+)-tcp-(fwd|rev)-p(\d+)-peer(\d+)\.json$"
)
UDP_RE = re.compile(
    r"^(opaque|wg-go)-(\d+)p-r(\d+)-udp-(fwd|rev)-(fixed|random|zero)-peer(\d+)\.(send|recv)\.json$"
)


def load_json(path: Path):
    text = path.read_text().strip()
    if not text:
        raise ValueError(f"empty result file: {path}")
    return json.loads(text.splitlines()[-1])


def iperf_receiver_mbps(data):
    end = data.get("end", {})
    for key in ("sum_received", "sum"):
        value = end.get(key)
        if isinstance(value, dict) and "bits_per_second" in value:
            return float(value["bits_per_second"]) / 1_000_000.0
    raise ValueError("iperf result has no receiver bits_per_second")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} RESULT_DIR")
    root = Path(sys.argv[1])

    tcp_by_rep = defaultdict(float)
    udp_peer = {}

    for path in root.iterdir():
        match = TCP_RE.match(path.name)
        if match:
            impl, peers, rep, direction, parallel, _peer = match.groups()
            key = (impl, int(peers), int(rep), f"tcp-p{parallel}", direction)
            tcp_by_rep[key] += iperf_receiver_mbps(load_json(path))
            continue

        match = UDP_RE.match(path.name)
        if match:
            impl, peers, rep, direction, profile, peer, role = match.groups()
            key = (impl, int(peers), int(rep), profile, direction, int(peer))
            udp_peer.setdefault(key, {})[role] = load_json(path)

    samples = defaultdict(list)
    for (impl, peers, rep, profile, direction), mbps in tcp_by_rep.items():
        samples[(impl, peers, profile, direction)].append((rep, mbps, None, None))

    udp_by_rep = defaultdict(lambda: {"mbps": 0.0, "pps": 0.0, "sent": 0, "recv": 0})
    for (impl, peers, rep, profile, direction, _peer), roles in udp_peer.items():
        if "send" not in roles or "recv" not in roles:
            raise ValueError(
                f"missing UDP sender/receiver result for {impl} {peers}p r{rep} {direction} {profile}"
            )
        receiver = roles["recv"]
        sender = roles["send"]
        group = udp_by_rep[(impl, peers, rep, f"udp-{profile}", direction)]
        group["mbps"] += float(receiver["inner_mbps"])
        group["pps"] += float(receiver["pps"])
        group["sent"] += int(sender["packets"])
        group["recv"] += int(receiver["packets"])

    for (impl, peers, rep, profile, direction), value in udp_by_rep.items():
        sent = value["sent"]
        loss = 0.0 if sent == 0 else max(0.0, 100.0 * (sent - value["recv"]) / sent)
        samples[(impl, peers, profile, direction)].append(
            (rep, value["mbps"], value["pps"], loss)
        )

    if not samples:
        raise SystemExit("no benchmark result files found")

    print("implementation peers profile direction median_mbps median_kpps median_loss_pct")
    for key in sorted(samples, key=lambda k: (k[1], k[2], k[3], k[0])):
        impl, peers, profile, direction = key
        rows = sorted(samples[key])
        mbps = statistics.median(row[1] for row in rows)
        pps_values = [row[2] for row in rows if row[2] is not None]
        loss_values = [row[3] for row in rows if row[3] is not None]
        kpps = "-" if not pps_values else f"{statistics.median(pps_values) / 1000.0:.3f}"
        loss = "-" if not loss_values else f"{statistics.median(loss_values):.4f}"
        print(f"{impl:14s} {peers:5d} {profile:10s} {direction:9s} {mbps:11.3f} {kpps:>11s} {loss:>15s}")

    print()
    print("Opaque / wg-go median throughput ratio")
    medians = {}
    for key, rows in samples.items():
        medians[key] = statistics.median(row[1] for row in rows)
    reference_keys = sorted(
        {(peers, profile, direction) for impl, peers, profile, direction in medians if impl == "opaque"}
    )
    for peers, profile, direction in reference_keys:
        opaque = medians.get(("opaque", peers, profile, direction))
        wg = medians.get(("wg-go", peers, profile, direction))
        if opaque is None or wg is None or wg == 0:
            continue
        print(f"{peers}p {profile:10s} {direction:3s}: {opaque / wg:.3f}x")


if __name__ == "__main__":
    main()
