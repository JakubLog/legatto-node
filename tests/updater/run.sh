#!/usr/bin/env bash
# Tests of legatto-update (updater/): the updater on a local release mirror
# with programmatic ed25519 keys, and its constants against contract.yml.
# Runs on any machine (macOS or Linux, bash 3.2+) from a plain legatto-node
# checkout; no server, no secrets, no Ansible.
#
# Stages:
#   1. contract constants (yq + python)
#   2. unit/end-to-end suite with the host Python >= 3.12 and OpenSSH
#   3. the same suite inside Ubuntu 24.04 (server Python + OpenSSH), when Docker
#      is available (LEGATTO_TEST_SKIP_DOCKER=1 skips it)
#   4. shellcheck
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/legatto-updater-tests.XXXXXX")"
trap 'rm -rf "${TMP}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }

find_python() {
  local candidate
  for candidate in "${LEGATTO_TEST_PYTHON:-}" python3.13 python3.12 "${HOME}/.local/bin/python3.12" python3; do
    [ -n "${candidate}" ] || continue
    command -v "${candidate}" >/dev/null 2>&1 || continue
    if "${candidate}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
      command -v "${candidate}"
      return 0
    fi
  done
  return 1
}

make_fakebin() {
  local dir="$1" tool
  mkdir -p "${dir}"
  for tool in docker systemctl systemd-analyze apt-get dpkg-query legatto-audit legatto-egress legatto-stack \
      legatto-secrets legatto-worker-deploy; do
    ln -s "${HERE}/fakebin/fake.py" "${dir}/${tool}"
  done
}

PYTHON="$(find_python)" || fail "Python >= 3.12 not found (set LEGATTO_TEST_PYTHON)"
command -v yq >/dev/null 2>&1 || fail "yq not found"

step "contract constants"
yq -o=json '.' "${REPO}/contract/contract.yml" > "${TMP}/contract.json"
"${PYTHON}" "${HERE}/check_contract.py" "${TMP}/contract.json"

export PYTHONDONTWRITEBYTECODE=1

step "python syntax"
"${PYTHON}" -c 'import ast, sys
for f in sys.argv[1:]:
    with open(f, encoding="utf-8") as fh:
        ast.parse(fh.read(), f)' "${REPO}"/updater/legatto_update/*.py "${REPO}/updater/bin/legatto-update" \
  "${HERE}"/*.py "${HERE}"/lib/*.py "${HERE}/fakebin/fake.py"

step "end-to-end suite (host: $("${PYTHON}" --version), $(ssh -V 2>&1))"
make_fakebin "${TMP}/fakebin"
LEGATTO_TEST_FAKEBIN="${TMP}/fakebin" LEGATTO_TEST_PYTHON="${PYTHON}" \
  "${PYTHON}" -W error::ResourceWarning "${HERE}/test_updater.py"

if [ "${LEGATTO_TEST_SKIP_DOCKER:-0}" != "1" ] && docker info >/dev/null 2>&1; then
  step "end-to-end suite in Ubuntu 24.04 (server Python and OpenSSH)"
  docker build -q -t legatto-updater-test:noble -f "${HERE}/Dockerfile.unit" "${HERE}" >/dev/null
  docker run --rm -v "${REPO}:/src:ro" legatto-updater-test:noble bash -c '
    set -euo pipefail
    fb=$(mktemp -d)
    for t in docker systemctl systemd-analyze apt-get dpkg-query legatto-audit legatto-egress legatto-stack \
        legatto-secrets legatto-worker-deploy; do ln -s /src/tests/updater/fakebin/fake.py "$fb/$t"; done
    python3 --version; ssh -V
    cd /tmp
    LEGATTO_TEST_FAKEBIN="$fb" LEGATTO_TEST_PYTHON=python3 PYTHONDONTWRITEBYTECODE=1 \
      python3 /src/tests/updater/test_updater.py'
else
  echo "Docker unavailable or skipped: Ubuntu 24.04 stage not run" >&2
fi

step "shellcheck"
shellcheck --severity=style -x "${HERE}/run.sh"

echo "PASS: updater (node)"
