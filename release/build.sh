#!/usr/bin/env bash
# Assemble the unsigned release bundle release/out/<version>/ (docs/CONTRACT.md §4.7, R6).
#
# Usage: release/build.sh --version x.y.z [--out DIR] [--app-src DIR] [--no-reuse-published]
#   --out DIR      output directory (default release/out/<version>; must not exist)
#   --app-src DIR  local legatto-app checkout at the commit pinned in release/app.lock
#                  (default: fresh clone of the pinned commit)
#   --no-reuse-published
#                  take unchanged image archives only from release/out/.cache,
#                  never from published releases (CI reference build)
#
# Needs a clean committed legatto-node tree, docker (buildx, containerd image
# store), syft, yq, git and network access to the pinned upstream images and
# downloads. Inputs, determinism and the output layout: release/lib/build.py.
# The same command builds the CI reference (.github/workflows/release-build.yml).
# Exit: 0 bundle written, 1 failure, 2 bad arguments, 4 missing tool.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=release/lib/python.sh
. "$here/lib/python.sh"
exec "$LEGATTO_PYTHON" "$here/lib/build.py" "$@"
