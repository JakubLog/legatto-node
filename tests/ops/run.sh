#!/usr/bin/env bash
# tests/ops/run.sh — tests of the ops host tools. Exit 0 = PASS.
# Runs on a workstation from a plain legatto-node checkout; no server, no secrets; Docker required.
#
#   contract   tool constants and lists vs contract/contract.yml
#   health     legatto-health --dry-run allowlist and expressions, PII negative tests,
#              down conditions, push through a CONNECT proxy to TLS Kuma
#   recovery   legatto-recovery-pack generate -> verify, card QR/text decoding
#   backup     legatto-pgdump + legatto-restore-test on the pinned supabase/postgres image
#
# LEGATTO_OPS_TESTS="health backup" runs a subset.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SUITES=${LEGATTO_OPS_TESTS:-contract health recovery backup}
IMAGE=legatto-ops-test:local
failed=()

py_in_image() {
	docker run --rm -v "$REPO:/repo:ro" -e REPO=/repo -e PYTHONDONTWRITEBYTECODE=1 -w /repo "$IMAGE" \
		python3 -W error::ResourceWarning "$@"
}

command -v docker >/dev/null 2>&1 || { echo "tests/ops: docker is required" >&2; exit 1; }
docker build -q -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE" >/dev/null || { echo "tests/ops: image build failed" >&2; exit 1; }

for suite in $SUITES; do
	echo "== ops/$suite"
	case $suite in
	contract) py_in_image tests/ops/test_contract.py ;;
	health) py_in_image tests/ops/test_health.py ;;
	recovery) py_in_image tests/ops/test_recovery_pack.py ;;
	backup) bash "$HERE/test_backup.sh" ;;
	*) echo "unknown suite $suite" >&2; false ;;
	esac
	rc=$?
	if ((rc == 0)); then echo "PASS ops/$suite"; else echo "FAIL ops/$suite (exit $rc)"; failed+=("$suite"); fi
done

if ((${#failed[@]})); then
	echo "tests/ops: FAILED: ${failed[*]}"
	exit 1
fi
echo "tests/ops: all suites passed ($SUITES)"
