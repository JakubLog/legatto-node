#!/bin/sh
# Packs worker/dist into the release artifact `worker.tar.gz` (kind worker-bundle)
# reproducibly: sorted entries, mtime 0, uid/gid 0, gzip without name/time.
# Usage: sh scripts/pack.sh OUT.tar.gz   (after `npm run build`; needs GNU tar)
# Last stdout line: {"script_name":"…","entry_sha256":"…"} for manifest.worker.
set -eu

out=${1:?usage: pack.sh OUT.tar.gz}
here=$(cd "$(dirname "$0")/.." && pwd)
dist="$here/dist"

for f in worker.js tools.mjs bundle.json; do
  if [ ! -f "$dist/$f" ]; then
    echo "pack.sh: $dist/$f missing; run npm run build first" >&2
    exit 1
  fi
done

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  echo "pack.sh: GNU tar is required for a reproducible archive" >&2
  exit 1
fi

field() {
  sed -n "s/^ *\"$1\": \"\\([^\"]*\\)\".*/\\1/p" "$dist/bundle.json"
}
script_name=$(field script_name)
entry_sha256=$(field entry_sha256)
actual=$(sha256sum "$dist/worker.js" | cut -d' ' -f1)
if [ -z "$script_name" ] || [ "$actual" != "$entry_sha256" ]; then
  echo "pack.sh: dist/bundle.json does not describe dist/worker.js; rebuild" >&2
  exit 1
fi

tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --mode='u=rw,go=r' \
  --format=gnu -C "$dist" -cf - worker.js tools.mjs bundle.json | gzip -n -9 >"$out"

printf '{"script_name":"%s","entry_sha256":"%s"}\n' "$script_name" "$entry_sha256"
