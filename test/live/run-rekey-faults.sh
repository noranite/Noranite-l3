#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

for case_name in \
	lost-activation \
	lost-response \
	superseded-pending
do
	echo
	echo "=== live rekey fault case: ${case_name} ==="
	"${SCRIPT_DIR}/run-rekey-fault-case.sh" "${case_name}"
done

echo
echo "PASS: all live rekey fault-injection cases completed"
