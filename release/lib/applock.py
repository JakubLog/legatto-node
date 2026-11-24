"""Pin a legatto-app release in release/app.lock (R6).

The lock is committed (signed commit) in legatto-node; release/build.sh
rebuilds the app images from the pinned commit and refuses to continue unless
release.json and the image digests are reproduced exactly.

Usage: python3 release/lib/applock.py --release-json DIR/release.json [--ci-run URL]
  release.json comes from legatto-app CI (workflow release.yml, artifact of
  scripts/release/build-images.sh). --ci-run records the GitHub Actions run URL.
"""

from __future__ import annotations

import argparse
import os
import re
from typing import List

import relcore as rc

LOCK = os.path.join(rc.NODE, "release", "app.lock")
IMAGES = ("app", "functions", "migrator")


def pin(release_json: str, ci_run: str = "") -> dict:
    rel = rc.read_json(release_json)
    if rel.get("schema") != "legatto-app-release/1":
        raise rc.ReleaseError("%s: schema musi być legatto-app-release/1" % release_json)
    if rel.get("dirty"):
        raise rc.ReleaseError("%s: wydanie zbudowane z brudnego drzewa (--allow-dirty) — nie do przypięcia" % release_json)
    if not re.match(r"^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", rel.get("repo", "")):
        raise rc.ReleaseError("release.json: niepoprawne repo")
    if not re.match(r"^[0-9a-f]{40}$", rel.get("commit", "")):
        raise rc.ReleaseError("release.json: niepoprawny commit")
    rc.check_semver(rel.get("version", ""))
    images = {}
    for name in IMAGES:
        digest = ((rel.get("images") or {}).get(name) or {}).get("digest", "")
        if not re.match(r"^sha256:[0-9a-f]{64}$", digest):
            raise rc.ReleaseError("release.json: brak digestu obrazu %s" % name)
        images[name] = digest
    app = {
        "repo": rel["repo"],
        "commit": rel["commit"],
        "version": rel["version"],
        "release_sha256": rc.sha256_file(release_json),
        "images": images,
    }
    if ci_run:
        if not re.match(r"^https://github\.com/[^\s]+$", ci_run):
            raise rc.ReleaseError("--ci-run musi być adresem https://github.com/…")
        app["ci_run"] = ci_run
    return {"schema": "legatto-app-lock/1", "app": app}


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(prog="release/lib/applock.py", description=__doc__.splitlines()[0])
    p.add_argument("--release-json", required=True)
    p.add_argument("--ci-run", default="")
    a = p.parse_args(argv)
    lock = pin(a.release_json, a.ci_run)
    rc.write_document(LOCK, lock)
    rc.info("przypięto legatto-app %s (%s) w release/app.lock — zatwierdź podpisanym commitem" % (
        lock["app"]["version"], lock["app"]["commit"]))
    return 0


if __name__ == "__main__":
    rc.run_main(main)
