#!/usr/bin/env bash
# Supply-chain pinning and workflow policy check (Aneks 1 pkt 4; PLAN F5b).
#
# Fails when, under ROOT:
#   GitHub workflows / composite actions (.github/workflows/*.y*ml, .github/actions/**/action.y*ml)
#     - `uses:` is not `owner/repo[/path]@<40-hex commit>`, `./local` or `docker://image@sha256:<64-hex>`
#     - `image:` / `container: <image>` has no `@sha256:<64-hex>`
#     - a `docker run|create|pull` command (also `docker container run|create`) has no image `@sha256:<64-hex>`
#     - `pull_request_target` is used
#     - a workflow has no top-level `permissions:`
#     - `secrets.<NAME>` other than secrets.GITHUB_TOKEN, or `secrets: inherit`, is referenced
#   .pre-commit-config.yaml
#     - a remote hook `rev:` is not a 40-hex commit
#   Dockerfiles (Dockerfile, *.Dockerfile, Dockerfile.*)
#     - `FROM` without `@sha256:<64-hex>` (except `scratch` and earlier build stages)
#
# Usage: scripts/check-actions-pinned.sh [--root DIR] [-q]
#   --root DIR  repository to check (default: this repository); works on any
#               checkout, e.g. legatto-app
#   -q          print only violations
# Exit: 0 clean, 1 violations found, 2 bad arguments.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
quiet=0
while (($#)); do
	case "$1" in
	--root) root="${2:?--root needs a directory}"; shift 2 ;;
	-q) quiet=1; shift ;;
	-h | --help) sed -n '2,23p' "$0"; exit 0 ;;
	*) echo "check-actions-pinned: unknown argument: $1" >&2; exit 2 ;;
	esac
done
if [[ ! -d "$root" ]]; then
	echo "check-actions-pinned: no such directory: $root" >&2
	exit 2
fi
root="$(cd "$root" && pwd)"

# Paths never checked: vendored or generated trees, and test fixtures that
# exist to contain violations.
prune=(-path "$root/.git" -o -path "$root/node_modules" -o -path '*/node_modules' -o -path "$root/ansible/collections"
	-o -path "$root/release/out" -o -path '*/.wrangler' -o -path "$root/bundle/compose/supabase" -o -path "$root/tests/*/fixtures")

workflow_files=()
while IFS= read -r f; do workflow_files+=("$f"); done < <(
	find "$root/.github" \( "${prune[@]}" \) -prune -o -type f \
		\( -path "$root/.github/workflows/*.yml" -o -path "$root/.github/workflows/*.yaml" \
		-o -name action.yml -o -name action.yaml \) -print 2>/dev/null | LC_ALL=C sort
)
dockerfiles=()
while IFS= read -r f; do dockerfiles+=("$f"); done < <(
	find "$root" \( "${prune[@]}" \) -prune -o -type f \
		\( -name Dockerfile -o -name '*.Dockerfile' -o -name 'Dockerfile.*' \) -print | LC_ALL=C sort
)

violations=0
report() {
	# report <file> <line> <message>
	printf '%s:%s: %s\n' "${1#"$root"/}" "$2" "$3"
	violations=$((violations + 1))
}

# --- workflows and composite actions -------------------------------------------
# The awk program prints "<line>\t<message>" for each violation.
read -r -d '' workflow_awk <<'AWK' || true
function strip_comment(s,    i, c, q) {
	q = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (q == "" && (c == "\"" || c == "'")) { q = c; continue }
		if (q != "" && c == q) { q = ""; continue }
		if (q == "" && c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) return substr(s, 1, i - 1)
	}
	return s
}
function unquote(v) {
	gsub(/^[ \t]+|[ \t]+$/, "", v)
	if (v ~ /^".*"$/ || v ~ /^'.*'$/) v = substr(v, 2, length(v) - 2)
	return v
}
# Interval expressions ({n}) are avoided: mawk and BSD awk differ on them.
function has_digest(s) { return match(s, /@sha256:[0-9a-f]+/) && RLENGTH == 72 }
function is_sha1(s) { return s ~ /^[0-9a-f]+$/ && length(s) == 40 }
function check_docker(cmd, ln) {
	if (cmd ~ /(^|[^A-Za-z0-9_.-])docker[ \t]+(container[ \t]+)?(run|create|pull)([ \t]|$)/ && !has_digest(cmd))
		printf "%d\t%s\n", ln, "docker run/create/pull without an image digest (@sha256:...): " substr(cmd, 1, 160)
}
# Shell lines of `run:` steps, joined across backslash continuations.
function shell_line(s, ln) {
	if (cont != "") { cmd = cont " " s } else { cmd = s; cont_line = ln }
	if (cmd ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, "", cmd); cont = cmd; return }
	check_docker(cmd, cont_line)
	cont = ""
}
function indent_of(s) { match(s, /^[ \t]*/); return RLENGTH }
BEGIN { top_permissions = 0; cont = ""; cont_line = 0; in_run = 0; run_indent = -1 }
{
	raw = $0
	line = strip_comment(raw)

	# Inside a block scalar of `run:` every more-indented line is shell.
	if (in_run) {
		if (raw ~ /^[ \t]*$/) next
		if (indent_of(raw) > run_indent) { shell_line(line, NR); next }
		in_run = 0
		if (cont != "") { check_docker(cont, cont_line); cont = "" }
	}
	if (match(line, /^[ \t]*(-[ \t]+)?run[ \t]*:/)) {
		v = substr(line, RSTART + RLENGTH)
		gsub(/^[ \t]+|[ \t]+$/, "", v)
		if (v ~ /^[|>]/) { in_run = 1; run_indent = indent_of(line) }
		else shell_line(unquote(v), NR)
	}

	if (line ~ /^permissions[ \t]*:/) top_permissions = 1

	if (match(line, /^[ \t]*(-[ \t]+)?uses[ \t]*:/)) {
		v = unquote(substr(line, RSTART + RLENGTH))
		if (v ~ /^\.\//) {
			# local action in this repository
		} else if (v ~ /^docker:\/\//) {
			if (!has_digest(v)) printf "%d\t%s\n", NR, "docker action without digest: " v
		} else if (v !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.\/-]+@[0-9a-f]+$/ || !is_sha1(substr(v, index(v, "@") + 1))) {
			printf "%d\t%s\n", NR, "action not pinned to a full commit SHA: " v
		}
	}
	if (match(line, /^[ \t]*(-[ \t]+)?image[ \t]*:/)) {
		v = unquote(substr(line, RSTART + RLENGTH))
		if (v != "" && !has_digest(v)) printf "%d\t%s\n", NR, "container image without digest: " v
	}
	if (match(line, /^[ \t]*container[ \t]*:/)) {
		v = unquote(substr(line, RSTART + RLENGTH))
		if (v != "" && !has_digest(v)) printf "%d\t%s\n", NR, "job container without digest: " v
	}
	if (line ~ /(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)/)
		printf "%d\t%s\n", NR, "pull_request_target is forbidden"
	if (line ~ /^[ \t]*secrets[ \t]*:[ \t]*inherit[ \t]*$/)
		printf "%d\t%s\n", NR, "secrets: inherit is forbidden"
	rest = line
	while (match(rest, /secrets\.[A-Za-z_][A-Za-z0-9_]*/)) {
		name = substr(rest, RSTART + 8, RLENGTH - 8)
		if (name != "GITHUB_TOKEN") printf "%d\t%s\n", NR, "repository secret referenced: secrets." name
		rest = substr(rest, RSTART + RLENGTH)
	}
}
END {
	if (cont != "") check_docker(cont, cont_line)
	if (is_workflow && !top_permissions) printf "%d\t%s\n", 1, "workflow has no top-level permissions: block"
}
AWK

for f in "${workflow_files[@]+"${workflow_files[@]}"}"; do
	is_workflow=1
	case "$f" in */action.yml | */action.yaml) is_workflow=0 ;; esac
	while IFS=$'\t' read -r ln msg; do
		report "$f" "$ln" "$msg"
	done < <(awk -v is_workflow="$is_workflow" "$workflow_awk" "$f")
done

# --- pre-commit ---------------------------------------------------------------------
precommit="$root/.pre-commit-config.yaml"
if [[ -f "$precommit" ]]; then
	while IFS=$'\t' read -r ln msg; do
		report "$precommit" "$ln" "$msg"
	done < <(awk '
		{ line = $0; sub(/[ \t]+#.*$/, "", line) }
		match(line, /^[ \t]*rev[ \t]*:/) {
			v = substr(line, RSTART + RLENGTH)
			gsub(/^[ \t"'"'"']+|[ \t"'"'"']+$/, "", v)
			if (v !~ /^[0-9a-f]+$/ || length(v) != 40) printf "%d\t%s\n", NR, "pre-commit hook rev is not a full commit SHA: " v
		}' "$precommit")
fi

# --- Dockerfiles ------------------------------------------------------------------------
for f in "${dockerfiles[@]+"${dockerfiles[@]}"}"; do
	while IFS=$'\t' read -r ln msg; do
		report "$f" "$ln" "$msg"
	done < <(awk '
		BEGIN { n = 0 }
		{
			line = $0
			if (line !~ /^[ \t]*[Ff][Rr][Oo][Mm][ \t]/) next
			sub(/^[ \t]*[Ff][Rr][Oo][Mm][ \t]+/, "", line)
			while (line ~ /^--[A-Za-z-]+=[^ \t]*[ \t]+/) sub(/^--[A-Za-z-]+=[^ \t]*[ \t]+/, "", line)
			split(line, w, /[ \t]+/)
			image = w[1]
			alias = (tolower(w[2]) == "as") ? tolower(w[3]) : ""
			if (image == "scratch" || (tolower(image) in stages)) {
				# base without registry or an earlier build stage
			} else if (!(match(image, /@sha256:[0-9a-f]+$/) && RLENGTH == 72)) {
				printf "%d\t%s\n", NR, "FROM without digest: " image
			}
			if (alias != "") stages[alias] = 1
		}' "$f")
done

checked=$((${#workflow_files[@]} + ${#dockerfiles[@]}))
[[ -f "$precommit" ]] && checked=$((checked + 1))
if ((violations)); then
	echo "check-actions-pinned: $violations violation(s) in $root" >&2
	exit 1
fi
((quiet)) || echo "check-actions-pinned: OK ($checked file(s) in $root)"
