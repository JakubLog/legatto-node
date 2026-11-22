#!/usr/bin/env bash
# Static checks of the public server code (local and CI):
#   yamllint --strict, shellcheck on our shell scripts (the pinned upstream
#   Supabase copy is skipped), Python syntax of every Python file and of the
#   extensionless tools with a python shebang, JSON syntax of the schemas.
# Needs: git, yamllint, shellcheck, python3 >= 3.12.
# Exit: 0 clean, 1 a check failed.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
failed=0

echo "== yamllint"
yamllint --strict . || failed=1

sh_files=()
py_files=()
while IFS= read -r f; do
	[[ -f "$f" && ! -L "$f" ]] || continue
	case "$f" in bundle/compose/supabase/*) continue ;; esac
	case "$f" in *.py) py_files+=("$f"); continue ;; esac
	IFS= read -r first <"$f" || continue
	if [[ "$first" =~ ^#!.*/(env\ )?(ba|da)?sh ]]; then sh_files+=("$f")
	elif [[ "$first" =~ ^#!.*python3 ]]; then py_files+=("$f"); fi
done < <(git ls-files -co --exclude-standard)

echo "== shellcheck (${#sh_files[@]} files)"
if ((${#sh_files[@]})); then shellcheck --severity=style -x "${sh_files[@]}" || failed=1; fi

echo "== python syntax (${#py_files[@]} files)"
python3 - "${py_files[@]}" <<'PY' || failed=1
import ast, sys
bad = 0
for path in sys.argv[1:]:
    try:
        ast.parse(open(path, encoding="utf-8").read(), filename=path)
    except SyntaxError as e:
        print(f"{path}:{e.lineno}: {e.msg}", file=sys.stderr)
        bad += 1
sys.exit(1 if bad else 0)
PY

echo "== JSON schemas"
for f in release/schema/*.json; do python3 -m json.tool "$f" >/dev/null || { echo "invalid JSON: $f" >&2; failed=1; }; done

if ((failed)); then echo "lint: FAIL" >&2; exit 1; fi
echo "lint: OK"
