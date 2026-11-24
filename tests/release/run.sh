#!/usr/bin/env bash
# tests/release/run.sh — release tools of this repository (docs/CONTRACT.md §6). Exit 0 = PASS.
#
#  1. good and bad documents for every schema in release/schema/ (+ reference jsonschema when importable)
#  2. release/lib/relcore.py: transparency log, semver, allowed_signers, file and R2 (fake S3) stores
#     with HEAD, server-side copy and the bucket lock
#  3. release/build.sh on a fixture checkout: full bundle, reference rebuild without cache,
#     image archive reuse from the cache and from a published release, refusals
#
# Needs: bash, python3 >= 3.9, docker (buildx, containerd image store), syft, yq, git,
# OpenSSH ssh-keygen ($LEGATTO_SSH_KEYGEN, default /opt/homebrew/bin/ssh-keygen, else PATH).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=release/lib/python.sh
. "$repo/release/lib/python.sh"
py="$LEGATTO_PYTHON"
failed=()

section() { printf '\n== %s\n' "$1"; }
run() {
	local name="$1"
	shift
	set +e
	"$@"
	local rc=$?
	set -e
	if ((rc != 0)); then failed+=("$name"); fi
}

section "schemas"
ref_py=""
for candidate in "$py" /opt/legatto-tools/venv/bin/python; do
	if [[ -x "$candidate" ]] && "$candidate" -c 'import jsonschema' 2>/dev/null; then ref_py="$candidate"; break; fi
done
if [[ -z "$ref_py" ]] && command -v ansible-lint >/dev/null 2>&1; then
	# Homebrew wraps ansible-lint in a shell script; its venv has jsonschema.
	lint_bin="$(command -v ansible-lint)"
	for candidate in "$(dirname "$(sed -n '1s/^#!//p' "$lint_bin")")/python" \
		"$(grep -o '/[^" ]*/libexec/bin' "$lint_bin" | head -n 1)/python"; do
		if [[ -x "$candidate" ]] && "$candidate" -c 'import jsonschema' 2>/dev/null; then ref_py="$candidate"; break; fi
	done
fi
run schemas "$py" "$here/test_schemas.py" ${ref_py:+--reference-python "$ref_py"}

section "release/lib/relcore.py"
run relcore "$py" "$here/test_relcore.py"

section "release/build.sh"
run builder "$py" "$here/test_build.py"

echo
if ((${#failed[@]})); then
	echo "release: FAIL (${failed[*]})"
	exit 1
fi
echo "release: PASS"
