#!/usr/bin/env bash
# All tests of this repository: one run.sh per area (docs/CONTRACT.md §6).
# Needs: docker, python3 >= 3.12, yq, syft (area release), yamllint, shellcheck.
# Usage: tests/run.sh [area ...]   (default: every area)
# Exit: 0 all areas passed, 1 at least one failed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
areas=("$@")
if ((${#areas[@]} == 0)); then
	areas=(net platform updater console publicsite ops egress release)
fi

failed=()
for area in "${areas[@]}"; do
	runner="$here/$area/run.sh"
	if [[ ! -x "$runner" ]]; then
		echo "FAIL $area: missing $runner" >&2
		failed+=("$area")
		continue
	fi
	echo "== $area"
	if "$runner"; then echo "PASS $area"; else echo "FAIL $area" >&2; failed+=("$area"); fi
done

if ((${#failed[@]})); then
	echo "failed areas: ${failed[*]}" >&2
	exit 1
fi
echo "tests: PASS (${areas[*]})"
