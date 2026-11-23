#!/usr/bin/env bash
# tests/egress/run.sh — tests of legatto-egress and the egress proxy image.
# Exit 0 = PASS.
#
#  1. static: shellcheck, yamllint (bundle/egress), image pins in
#     egress/image/Dockerfile equal contract/versions.yml;
#  2. tests/egress/test_egress.py in a privileged Ubuntu 24.04 container, on
#     the role-rendered config of the example office (fixtures/role):
#     allowlist validation (IP entries rejected), render of ACLs and nft
#     against golden files, diff (host/port/role/wildcard = widening,
#     removal = no widening, pinned removal = 41), apply with real nft
#     (per-user rules, observe vs enforce, counters, status, audit),
#     config.json consistent with contract/contract.yml;
#  3. the real Smokescreen image built from egress/image/Dockerfile:
#     check_config on every rendered config, allow/deny through a proxy in
#     enforce and observe mode, decision log format.
#
# UPDATE_GOLDEN=1 rewrites tests/egress/golden (the run then fails, review the diff).
# Needs: docker (with linux/amd64 emulation on arm64), yq, yamllint, shellcheck.
# No access to any office server.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LANE_DIR="$REPO/tests/egress"
RUNNER_IMAGE="legatto-egress-test-runner:local"
PROXY_IMAGE="legatto-egress-proxy:test"
NET="legatto-egress-test-$$"
PREFIX="legatto-egress-test-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/legatto-egress-test.XXXXXX")"

cleanup() {
	docker ps -aq --filter "name=^${PREFIX}-" | while read -r id; do docker rm -f "$id" >/dev/null 2>&1 || true; done
	docker network rm "$NET" >/dev/null 2>&1 || true
	# Files written as root inside the containers.
	docker run --rm -v "$WORK:/work" "$RUNNER_IMAGE" sh -c 'rm -rf /work/* /work/.[!.]*' >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

for tool in docker yq yamllint shellcheck; do
	command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

# --- 1. static -------------------------------------------------------------------------
step "static checks"
shellcheck --severity=style -x "$LANE_DIR/run.sh"
yamllint --strict -c "$REPO/.yamllint" "$REPO/bundle/egress"

versions="$REPO/contract/versions.yml"
dockerfile="$REPO/egress/image/Dockerfile"
golang_ref="$(yq -r '.legatto_images.golang_build.ref' "$versions")"
golang_digest="$(yq -r '.legatto_images.golang_build.index_digest' "$versions")"
distroless_ref="$(yq -r '.legatto_images.distroless_static.ref' "$versions")"
distroless_digest="$(yq -r '.legatto_images.distroless_static.digest' "$versions")"
src_commit="$(yq -r '.legatto_egress_proxy_source.commit' "$versions")"
src_repo="$(yq -r '.legatto_egress_proxy_source.repo' "$versions")"
grep -qx "FROM --platform=\$BUILDPLATFORM ${golang_ref}@${golang_digest} AS build" "$dockerfile" \
	|| fail "Dockerfile build stage is not ${golang_ref}@${golang_digest}"
grep -qx "FROM ${distroless_ref}@${distroless_digest}" "$dockerfile" \
	|| fail "Dockerfile final stage is not ${distroless_ref}@${distroless_digest}"
grep -qx "ARG SMOKESCREEN_COMMIT=${src_commit}" "$dockerfile" || fail "Dockerfile commit differs from versions.yml"
grep -qx "ARG SMOKESCREEN_REPO=https://${src_repo}.git" "$dockerfile" || fail "Dockerfile repo differs from versions.yml"
for f in "$dockerfile" "$LANE_DIR/image/Dockerfile"; do
	if grep -E '^FROM ' "$f" | grep -v '@sha256:[0-9a-f]\{64\}' >/dev/null; then
		fail "$f has a FROM without digest"
	fi
done
echo "image pins match versions.yml"

yq -o=json '.' "$REPO/contract/contract.yml" >"$WORK/contract.json"
yq -o=json '.' "$REPO/bundle/egress/base.yml" >"$WORK/base.json"
yq -o=json '.' "$REPO/bundle/egress/features.yml" >"$WORK/features.json"

# --- 2. unit and nft tests in Ubuntu 24.04 -----------------------------------------------------
step "build test runner and proxy images"
docker build -q -t "$RUNNER_IMAGE" "$LANE_DIR/image" >/dev/null
docker buildx build -q --platform linux/amd64 --load -t "$PROXY_IMAGE" "$REPO/egress/image" >/dev/null
docker network create "$NET" >/dev/null

docker run -d --name "$PREFIX-target" --network "$NET" "$RUNNER_IMAGE" python3 -c '
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, _ = s.accept(); c.close()
for p in (443, 8080):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
' >/dev/null
target_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$PREFIX-target")"
[[ -n "$target_ip" ]] || fail "helper container has no address"

step "legatto-egress tests (privileged container, nft)"
golden_mount=()
if [[ "${UPDATE_GOLDEN:-0}" == 1 ]]; then
	mkdir -p "$LANE_DIR/golden"
	golden_mount=(-v "$LANE_DIR/golden:/repo/tests/egress/golden")
fi
docker run --rm --name "$PREFIX-runner" --privileged --network "$NET" \
	-v "$REPO:/repo:ro" ${golden_mount[@]+"${golden_mount[@]}"} -v "$WORK:/work" \
	-e REPO=/repo -e WORK=/work -e TARGET_IP="$target_ip" -e UPDATE_GOLDEN="${UPDATE_GOLDEN:-0}" \
	"$RUNNER_IMAGE" sh -c 'python3 -c "import sys; [compile(open(f).read(), f, \"exec\") for f in sys.argv[1:]]" \
			/repo/egress/legatto-egress /repo/tests/egress/test_egress.py /repo/tests/egress/proxy_probe.py \
		&& python3 /repo/egress/legatto-egress --version \
		&& python3 -B /repo/tests/egress/test_egress.py'

# --- 3. Smokescreen built from the pinned commit ---------------------------------------------------
step "Smokescreen check_config on rendered configs"
proxy_dir="$(cat "$WORK/e2e/proxy_dir")"
for mode in observe enforce; do
	for role in host app auth functions intake publish; do
		dir="$WORK/e2e/$mode/proxy/$role"
		if [[ "$role" == host ]]; then mount_at="$proxy_dir/host"; else mount_at=/etc/smokescreen; fi
		docker run --rm --platform linux/amd64 -v "$dir:$mount_at:ro" \
			--entrypoint /usr/local/bin/smokescreen-check-config "$PROXY_IMAGE" "$mount_at/smokescreen.yaml" \
			>"$WORK/check-$mode-$role.log" 2>&1 || {
			cat "$WORK/check-$mode-$role.log" >&2
			fail "check_config rejected $mode/$role"
		}
	done
done
echo "check_config: 12 configs accepted"

probe() { # probe <proxy-container> <target> -> status code
	docker run --rm --network "$NET" -v "$LANE_DIR:/t:ro" "$RUNNER_IMAGE" \
		python3 /t/proxy_probe.py "$1" 4750 "$2"
}
start_proxy() { # start_proxy <name> <mode> <role>
	docker run -d --name "$1" --platform linux/amd64 --network "$NET" --read-only --cap-drop ALL \
		--security-opt no-new-privileges -v "$WORK/e2e/$2/proxy/$3:/etc/smokescreen:ro" "$PROXY_IMAGE" >/dev/null
	local i
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		[[ "$(probe "$1" "selftest.legatto.invalid:443")" != none ]] && return 0
		sleep "$i"
	done
	docker logs "$1" >&2
	fail "proxy $1 did not start"
}

step "Smokescreen allow/deny (role app)"
start_proxy "$PREFIX-enforce" enforce app
code="$(probe "$PREFIX-enforce" example.com:443)"
[[ "$code" == 407 ]] || fail "enforce: example.com not denied (got $code)"
code="$(probe "$PREFIX-enforce" 198.51.100.7:443)"
[[ "$code" == 407 ]] || fail "enforce: IP literal not denied (got $code)"
code="$(probe "$PREFIX-enforce" api.resend.com:443)"
[[ "$code" != 407 && "$code" != none ]] || fail "enforce: allowlisted api.resend.com denied (got $code)"
echo "enforce: example.com -> 407, IP -> 407, api.resend.com -> $code (not denied)"
docker logs "$PREFIX-enforce" 2>&1 | grep '"msg":"CANONICAL-PROXY-DECISION"' | grep '"enforce_would_deny":true' \
	| grep -q '"requested_host":"example.com:443"' || fail "deny decision not logged as JSON"

start_proxy "$PREFIX-observe" observe app
code="$(probe "$PREFIX-observe" example.com:443)"
[[ "$code" != 407 && "$code" != none ]] || fail "observe: example.com blocked (got $code)"
docker logs "$PREFIX-observe" 2>&1 | grep '"msg":"CANONICAL-PROXY-DECISION"' | grep '"enforce_would_deny":true' \
	| grep -q '"allow":true' || fail "observe: would-deny decision not logged"
echo "observe: example.com -> $code (reported, not denied)"

step "PASS egress (node)"
