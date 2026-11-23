#!/usr/bin/env bash
# Tests of the net host tools (legatto-audit, -policy, -breakglass, -tailnet,
# -fw-*) with fake system binaries in an Ubuntu 24.04 container, plus the
# `# contract:` constants of the tools against contract/contract.yml.
# Needs: docker. Exit 0 = PASS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
image="legatto-net-unit:test"

command -v docker >/dev/null 2>&1 || { echo "tests/net: missing tool: docker" >&2; exit 1; }

echo "== net: unit tests in Ubuntu 24.04 (tools, contract constants)"
docker build --quiet -t "$image" -f "$here/Dockerfile.unit" "$here" >/dev/null
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$repo:/repo:ro" -w /repo/tests/net/unit "$image" \
  python3 -W error::SyntaxWarning -m unittest -v \
    test_contract test_audit test_policy test_breakglass test_tailnet test_fw

echo "PASS net (node)"
