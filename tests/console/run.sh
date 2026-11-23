#!/usr/bin/env bash
# Console tests (office-console/): shellcheck of the scripts here, then the
# Python suite as root in an Ubuntu 24.04 container (users legatto-console/
# caddy, spool permissions, executor, panel over its unix socket, constants
# against contract/contract.yml). Needs docker and shellcheck. Exit 0 = PASS.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

step() { printf '\n== %s\n' "$*"; }
need() { command -v "$1" > /dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 1; }; }

need docker
need shellcheck

step "shellcheck"
shellcheck --severity=style "$here/run.sh" "$here/inner.sh"

step "test image"
image_tag="legatto-console-test:$(shasum -a 256 "$here/Dockerfile" | cut -c1-12)"
if ! docker image inspect "$image_tag" > /dev/null 2>&1; then
  docker build --quiet -t "$image_tag" "$here" > /dev/null
fi

step "python suite (container, root)"
docker run --rm --network none \
  -v "$repo:/src:ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  "$image_tag" /src/tests/console/inner.sh

echo
echo "console: PASS"
