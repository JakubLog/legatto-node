#!/usr/bin/env bash
# Runs inside the console test container as root: creates the system users
# the office server has (legatto-console, caddy and their groups) and runs the
# Python suite of this directory, read-only. Arguments replace this directory
# with other test directories (absolute paths); their tests put this
# directory on sys.path to import `harness`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for group in legatto-console legatto-status legatto-audit caddy; do
  getent group "$group" > /dev/null || groupadd --system "$group"
done
getent passwd legatto-console > /dev/null \
  || useradd --system --gid legatto-console --groups legatto-status,legatto-audit \
       --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin legatto-console
getent passwd caddy > /dev/null \
  || useradd --system --gid caddy --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin caddy

export LEGATTO_CONSOLE_TEST_CONTAINER=1  # suites may install the code under /opt/legatto here
(($#)) || set -- "$here"
cd "$here"
for dir in "$@"; do
  python3 -B -m unittest discover -s "$dir" -t "$dir" -p 'test_*.py' -v
done
