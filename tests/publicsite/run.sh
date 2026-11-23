#!/usr/bin/env bash
# tests/publicsite/run.sh — tests of the public-site code (worker/, site-publisher/):
#   1. Worker (vitest in workerd/Miniflare) in Node 22 by digest, as in
#      .github/workflows/worker.yml: npm ci from the lockfile, typecheck, build,
#      fixed envelope size, Turnstile with Cloudflare test keys, Worker
#      signature, self-test; server tools (Pages Direct Upload, Worker
#      deploy/rollback, egress proxy, pinned CA). Writes worker/dist (gitignored).
#   2. Host tools (Python) on the host interpreter: two-process intake on a fake
#      queue (duplicate rejected, bad signature quarantined, ack only after the
#      write), zero-address guard, publisher pipeline, Worker deploy,
#      cf_bootstrap against a fake Cloudflare API, contract constants.
#   3. The same suite on the server interpreter (Ubuntu 24.04, Python 3.12).
#   4. shellcheck, gitleaks (image by digest).
# No office server, no Cloudflare account, no secrets. Needs docker, python >= 3.12,
# yq, shellcheck. Exit 0 = PASS.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
node_image=node:22-bookworm@sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb
gitleaks_image=ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
work=$(mktemp -d "${TMPDIR:-/tmp}/legatto-publicsite.XXXXXX")
trap 'rm -rf "$work"' EXIT
step() { printf '\n=== %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "run.sh: $1 is required" >&2; exit 1; }; }

need docker
need yq
need shellcheck
python=""
for candidate in python3.12 python3.13 python3.14 python3.15 python3; do
  if command -v "$candidate" >/dev/null 2>&1 \
    && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    python=$(command -v "$candidate")
    break
  fi
done
[ -n "$python" ] || { echo "run.sh: python >= 3.12 is required" >&2; exit 1; }

# Python suite filter: unittest prints ResourceWarnings of the fake servers' threads.
quiet() { grep -v -e ResourceWarning -e 'Enable tracemalloc' -e 'self._target' -e 'return self.run'; }
modules="test_contract test_intake test_publish test_worker_deploy test_cf_bootstrap"

step "worker: npm ci, typecheck, build, vitest (Worker in workerd + server tools; $node_image)"
# Sources are copied inside the container so the host node_modules stay untouched;
# only dist/ is written back (the release build and pack.sh read it).
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CI=true -e LEGATTO_VECTOR_OUT=/out/vectors.json \
  -v "$repo/worker:/worker" -v "$work:/out" -w /tmp "$node_image" sh -euc '
    mkdir /tmp/w
    tar -C /worker --exclude=./node_modules --exclude=./dist --exclude=./.wrangler -cf - . | tar -C /tmp/w -xf -
    cd /tmp/w
    npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
    npm run --silent typecheck
    npm run --silent build
    npm test
    rm -rf /worker/dist
    cp -R dist /worker/dist'
[ -s "$work/vectors.json" ] || { echo "run.sh: the Worker tests did not write vectors.json" >&2; exit 1; }

step "host tools: python unit tests (host $("$python" -c 'import sys; print(sys.version.split()[0])'))"
yq -o=json "$repo/contract/contract.yml" >"$work/contract.json"
# shellcheck disable=SC2086 # word splitting of the module list is intended
(cd "$here/py" && LEGATTO_CONTRACT_JSON="$work/contract.json" LEGATTO_VECTOR_FILE="$work/vectors.json" \
  PYTHONDONTWRITEBYTECODE=1 "$python" -m unittest -v $modules 2>&1) | quiet

step "host tools: python unit tests (Ubuntu 24.04)"
image=legatto-publicsite-unit:$(shasum -a 256 "$here/Dockerfile.unit" | cut -c1-12)
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -q -t "$image" -f "$here/Dockerfile.unit" "$here" >/dev/null
fi
docker run --rm --network none -v "$repo:/src:ro" -v "$work:/work:ro" -w /src/tests/publicsite/py \
  -e LEGATTO_CONTRACT_JSON=/work/contract.json -e LEGATTO_VECTOR_FILE=/work/vectors.json -e PYTHONDONTWRITEBYTECODE=1 \
  "$image" sh -c "python3 --version && python3 -m unittest $modules 2>&1" | quiet

step "lint: shellcheck, gitleaks"
shellcheck --severity=style -x "$here/run.sh" "$repo/worker/scripts/pack.sh"
for path in worker/src worker/tools worker/test worker/scripts site-publisher tests/publicsite; do
  docker run --rm --network none -v "$repo:/repo:ro" "$gitleaks_image" \
    dir --no-banner --redact --exit-code 1 --config /repo/.gitleaks.toml "/repo/$path" >"$work/gitleaks.log" 2>&1 \
    || { cat "$work/gitleaks.log" >&2; echo "gitleaks: finding in $path" >&2; exit 1; }
done
echo "lint OK"

printf '\npublicsite (node): PASS\n'
