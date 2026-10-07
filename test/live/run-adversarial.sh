#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

for case_name in \
	old-generation-grace \
	duplicate-replay \
	chaos-rapid-rotation \
	persistent-establishment-loss \
	mtu-boundary \
	client-restart
do
	echo
	echo "=== live adversarial case: ${case_name} ==="
	"${SCRIPT_DIR}/run-adversarial-case.sh" "${case_name}"
done

echo
echo "PASS: all live adversarial session/runtime cases completed"
