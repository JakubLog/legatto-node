#!/usr/bin/env bash
# tests/ops: legatto-pgdump and legatto-restore-test against the pinned
# supabase/postgres image (versions.yml legatto_images.db, multi-arch index
# digest): consistent dump + rotation + status, restore into a throw-away
# container with row counts and checksums, detection of a damaged dump and
# of wrong counts, `record` of a Hetzner clone report, no table content in
# any output. Runs on the control machine with Docker (first run pulls the image).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
FILES=$REPO/sbin
WORK=$(mktemp -d "${TMPDIR:-/tmp}/legatto-ops-backup.XXXXXX")
DB=legatto-ops-test-db-$$
PY=${LEGATTO_TEST_PYTHON:-python3}

versions=$REPO/contract/versions.yml
ref=$(sed -n '/^  db:/,/^  [a-z]/s/^    ref: *\([^ ]*\).*/\1/p' "$versions" | head -1)
index=$(sed -n '/^  db:/,/^  [a-z]/s/^    index_digest: *\([^ ]*\).*/\1/p' "$versions" | head -1)
IMAGE=$ref@$index

cleanup() {
	docker rm -f -v "$DB" >/dev/null 2>&1 || true
	docker ps -aq --filter label=com.legatto.restore-test=1 | while read -r id; do docker rm -f -v "$id" >/dev/null 2>&1; done
	rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0 FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	local want=$1 name=$2 rc=0
	shift 2
	"$@" >"$WORK/out" 2>"$WORK/err" || rc=$?
	if [[ $rc == "$want" ]]; then ok "$name"; else bad "$name (exit $rc, want $want)"; sed 's/^/     | /' "$WORK/err"; fi
}
check() {
	local name=$1
	shift
	if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
jq_py() { "$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if ($2) else 1)" "$1"; }

# --- source database with application-like data --------------------------------------------
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null
docker run -d --name "$DB" --network none -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" "$IMAGE" >/dev/null
for _ in $(seq 1 100); do
	docker exec "$DB" psql -h 127.0.0.1 -U supabase_admin -d postgres -XAtc 'select 1' >/dev/null 2>&1 && break
	sleep 3
done
docker exec -i "$DB" psql -h 127.0.0.1 -U supabase_admin -d postgres -X -q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
create extension if not exists pg_cron;
create extension if not exists pg_net;
select cron.schedule('nightly', '0 3 * * *', 'select 1');
create table public.cases (id bigserial primary key, title text, payload jsonb, amount numeric,
                           at timestamptz default now(), f float8, b bytea);
insert into public.cases (title, payload, amount, f, b)
  select 'Sprawa ' || g || ' Jan Kowalski', jsonb_build_object('n', g, 'email', 'jan' || g || '@example.pl'),
         g * 1.5, g / 3.0, decode(md5(g::text), 'hex') from generate_series(1, 5000) g;
insert into auth.users (id, email, aud, role)
  select gen_random_uuid(), 'u' || g || '@example.pl', 'authenticated', 'authenticated' from generate_series(1, 25) g;
select vault.create_secret('tajne-haslo-kowalskiego', 'test_secret');
create schema app_private;
create table app_private."we|ird name" (k text primary key, v text);
insert into app_private."we|ird name" values ('a', 'Nowak');
create table public.empty_table (x int);
SQL
ok "source database seeded"

# --- sandbox: ops.json, fake legatto-audit, docker mapping supabase-db -> test container ----
ROOT=$WORK/root
mkdir -p "$ROOT/var/lib/legatto/status" "$ROOT/etc/legatto" "$ROOT/usr/local/sbin" "$WORK/bin"
printf '{"v":1,"kuma_host":"status.example.test","hetzner_backup_window":"22-02","pgdump_keep":2,"db_image":"%s"}\n' \
	"$IMAGE" >"$ROOT/etc/legatto/ops.json"
cat >"$ROOT/usr/local/sbin/legatto-audit" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$WORK/audit.calls"
echo '{"seq":42,"hash":"00"}'
EOF
cat >"$WORK/bin/docker" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do if [[ \$a == supabase-db ]]; then args+=("\${LGT_DB:-$DB}"); else args+=("\$a"); fi; done
exec "$(command -v docker)" "\${args[@]}"
EOF
chmod +x "$ROOT/usr/local/sbin/legatto-audit" "$WORK/bin/docker"
run() { env PATH="$WORK/bin:$PATH" LEGATTO_ROOT="$ROOT" "$PY" "$@"; }
PG=$ROOT/var/backups/legatto/pg
ST=$ROOT/var/lib/legatto/status

# --- legatto-pgdump -------------------------------------------------------------------------
expect 0 "pgdump run" run "$FILES/legatto-pgdump" run --json
sleep 1
expect 0 "pgdump run (2)" run "$FILES/legatto-pgdump" run --json
sleep 1
expect 0 "pgdump run (3)" run "$FILES/legatto-pgdump" run --json
check "rotation keeps pgdump_keep=2 dumps" test "$(find "$PG" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" = 2
NEWEST=$(find "$PG" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
# python stat: `stat -f %Lp` (BSD) means a filesystem query under GNU stat and does not fail there
check "dump files are 0600" test "$("$PY" -c 'import os, sys; print("%o" % (os.stat(sys.argv[1]).st_mode & 0o777))' \
	"$NEWEST/db.dump")" = 600
check "backup.json ok with Hetzner window" jq_py "$ST/backup.json" \
	'd["ok"] and d["pgdump"]["state"] == "ok" and d["hetzner_window"] == "22-02" and len(d["pgdump"]["sha256"]) == 64'
check "meta.json counts rows from the dump snapshot" jq_py "$NEWEST/meta.json" \
	'{t["name"]: t["rows"] for t in d["tables"]}["public.cases"] == 5000 and \
	 {t["name"]: t["rows"] for t in d["tables"]}["cron.job"] == 1 and \
	 {t["name"]: t["rows"] for t in d["tables"]}["app_private.\"we|ird name\""] == 1'
check "audit backup.pgdump written" grep -q -- '--event backup.pgdump' "$WORK/audit.calls"

# --- legatto-restore-test run -----------------------------------------------------------------
expect 0 "restore-test run passes" run "$FILES/legatto-restore-test" run --json --report "$WORK/report.json"
cp "$WORK/out" "$WORK/run.json"
check "all checks true" jq_py "$WORK/run.json" 'd["state"] == "ok" and all(d["checks"].values()) and d["restore_errors"] == 0'
check "restore-test.json ok (mode local)" jq_py "$ST/restore-test.json" 'd["ok"] and d["mode"] == "local" and d["state"] == "ok"'
check "throw-away container removed" test -z "$(docker ps -aq --filter label=com.legatto.restore-test=1)"
check "audit backup.restore_test written" grep -q -- '--event backup.restore_test' "$WORK/audit.calls"

# wrong expectation (count) and damaged dump are detected
cp "$NEWEST/meta.json" "$WORK/meta.keep"
"$PY" - "$NEWEST/meta.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for t in d["tables"]:
    if t["name"] == "public.cases":
        t["rows"] += 1
json.dump(d, open(sys.argv[1], "w"))
PY
expect 10 "restore-test fails on a row count mismatch" run "$FILES/legatto-restore-test" run --json
check "  row_counts false, mismatched table named" jq_py "$WORK/out" \
	'not d["checks"]["row_counts"] and d["tables"]["mismatched"] == ["public.cases"]'
check "  restore-test.json state fail" jq_py "$ST/restore-test.json" 'd["state"] == "fail" and not d["ok"]'
cp "$WORK/meta.keep" "$NEWEST/meta.json"
cp "$NEWEST/db.dump" "$WORK/dump.keep"
printf 'X' | dd of="$NEWEST/db.dump" bs=1 seek=4096 conv=notrunc 2>/dev/null
expect 10 "restore-test fails on a damaged dump" run "$FILES/legatto-restore-test" run --json
check "  dump_integrity false" jq_py "$WORK/out" 'not d["checks"]["dump_integrity"]'
cp "$WORK/dump.keep" "$NEWEST/db.dump"

# --- record of a Hetzner clone report -------------------------------------------------------------
"$PY" - "$WORK/run.json" "$WORK/hz.json" <<'PY'
import json, sys
run = json.load(open(sys.argv[1]))
json.dump({"v": 1, "mode": "hetzner", "run": run,
           "hetzner": {"backup_image_id": 123456, "backup_created_at": "2026-11-21T22:10:00Z", "backup_age_h": 3,
                       "server_type": "cx32", "location": "fsn1", "clone_boot_s": 75}}, open(sys.argv[2], "w"))
PY
expect 0 "record --mode hetzner" run "$FILES/legatto-restore-test" record --report "$WORK/hz.json" --mode hetzner \
	--actor '{"kind":"vendor","id":"v-tester"}' --json
check "restore-test.json mode hetzner with hetzner_last_ok_at" jq_py "$ST/restore-test.json" \
	'd["mode"] == "hetzner" and d["ok"] and d["hetzner_last_ok_at"]'
"$PY" - "$WORK/hz.json" "$WORK/hz-bad.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["run"]["checks"]["Jan Kowalski <jan@example.pl>"] = True
json.dump(d, open(sys.argv[2], "w"))
PY
expect 12 "record rejects a report with free text" run "$FILES/legatto-restore-test" record --report "$WORK/hz-bad.json" \
	--mode hetzner --actor '{"kind":"vendor","id":"v-tester"}'
expect 2 "record requires --actor" run "$FILES/legatto-restore-test" record --report "$WORK/hz.json" --mode hetzner

# --- failure path of pgdump -----------------------------------------------------------------------
LAST_OK=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["pgdump"]["last_ok_at"])' "$ST/backup.json")
expect 10 "pgdump fails without the database container" env LGT_DB=legatto-ops-test-missing-db \
	PATH="$WORK/bin:$PATH" LEGATTO_ROOT="$ROOT" "$PY" "$FILES/legatto-pgdump" run
check "  backup.json state fail, last_ok_at kept" jq_py "$ST/backup.json" \
	"d['pgdump']['state'] == 'fail' and d['pgdump']['last_ok_at'] == '$LAST_OK' and not d['ok']"
check "  no partial dump left" test -z "$(find "$PG" -name '.*.partial')"

# --- no table content anywhere outside the dump files ---------------------------------------------
leak=$(grep -l -E 'Kowalski|Nowak|@example\.pl|tajne-haslo' "$ST"/*.json "$PG"/*/meta.json "$WORK/run.json" \
	"$WORK/report.json" "$WORK/audit.calls" 2>/dev/null || true)
check "no table content in status, meta, reports or audit" test -z "$leak"

printf '\nbackup: %d passed, %d failed\n' "$PASS" "$FAIL"
((FAIL == 0))
