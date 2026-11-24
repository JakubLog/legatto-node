#!/usr/bin/env bash
# (sourced, not executed)
# Sourced by release/*.sh here and by the vendor's release tools (through
# the node checkout): picks the Python interpreter and puts this directory
# (relcore.py, schema.py) on PYTHONPATH, so every release tool uses the one
# copy of the shared code. The tools use only the standard library
# (Python >= 3.9, so the macOS system python3 works as well as Ubuntu
# 24.04's 3.12). LEGATTO_PYTHON overrides the choice.

legatto_python() {
	local candidate
	for candidate in "${LEGATTO_PYTHON:-}" python3 /usr/bin/python3; do
		[[ -n "$candidate" ]] || continue
		if command -v "$candidate" >/dev/null 2>&1 &&
			"$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
			command -v "$candidate"
			return 0
		fi
	done
	echo "release: Python >= 3.9 not found (set LEGATTO_PYTHON)" >&2
	return 4
}

LEGATTO_PYTHON="$(legatto_python)" || exit 4
LEGATTO_RELEASE_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$LEGATTO_RELEASE_LIB${PYTHONPATH:+:$PYTHONPATH}"
export LEGATTO_PYTHON LEGATTO_RELEASE_LIB PYTHONPATH
