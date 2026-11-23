#!/usr/bin/env bash
# Tests of the platform lane in legatto-node: the release bundle (bundle/compose:
# unchanged upstream Supabase copy + docker-compose.legatto.yml, bundle/env templates,
# bundle/systemd units, bundle/caddy/sites.d) and the host tools legatto-secrets,
# -acme, -stack, -studio (sbin/). `docker compose config` of upstream + override with
# env files rendered by legatto-secrets, the updater's compose/unit/caddy-site
# validators, `# contract:` constants against contract/contract.yml and
# `systemd-analyze verify` of the release units.
#
# Needs: docker (with compose >= 2.24 and linux/amd64 emulation), python3, yq,
# the linter shellcheck and network access to build the test image. No secrets, no Ansible.
# Optional: LEGATTO_PLATFORM_WORK=<existing dir> runs in that work directory and
# keeps it (the caller removes it; files under env/ are owned by root of the test
# container). Exit 0 = PASS. Works with bash 3.2 and 5.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
image="legatto-platform-test:local"
if [[ -n "${LEGATTO_PLATFORM_WORK:-}" ]]; then
	work="$(cd "$LEGATTO_PLATFORM_WORK" && pwd)"
	keep_work=1
else
	work="$(mktemp -d "${TMPDIR:-/tmp}/legatto-platform.XXXXXX")"
	keep_work=0
fi

cleanup() {
	[[ "$keep_work" -eq 0 ]] || return 0
	# Files created as root inside the test container are removed from there.
	docker run --rm -v "$work:/work" --entrypoint /bin/rm "$image" -rf /work/env >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

log() { printf '== %s\n' "$*"; }
die() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

for tool in docker python3 yq shellcheck; do
	command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

log "shellcheck"
shellcheck --severity=style -x "$here/run.sh"

log "contract and versions as JSON"
yq -o=json '.' "$repo/contract/contract.yml" >"$work/contract.json"
yq -o=json '.' "$repo/contract/versions.yml" >"$work/versions.json"

log "test image (Ubuntu 24.04, linux/amd64)"
docker build --platform linux/amd64 -q -t "$image" "$here" >/dev/null

log "root tests in the test image (secrets, acme, stack, studio, release units)"
docker run --rm --platform linux/amd64 \
	--cap-add NET_ADMIN \
	--sysctl net.ipv6.conf.all.disable_ipv6=0 \
	--sysctl net.ipv6.conf.lo.disable_ipv6=0 \
	-e PYTHONDONTWRITEBYTECODE=1 \
	-v "$repo:/repo:ro" -v "$work:/work" \
	"$image" python3 /repo/tests/platform/in_container.py

log "host checks (upstream copy, compose, contract, updater validators, templates)"
LEGATTO_TEST_WORK="$work" PYTHONDONTWRITEBYTECODE=1 python3 "$here/host_checks.py"

log "PASS platform (node)"
