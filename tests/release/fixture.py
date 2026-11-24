"""Synthetic legatto-node and legatto-app checkouts for builder tests.

Used by tests/release/test_build.py here and by the vendor's release chain
test (it drives the vendor tools against a fixture of this repository):
  * upstream image: tiny image pushed to a throw-away local registry (by digest);
  * legatto-app: a git repository whose scripts/release/build-images.sh builds
    three tiny reproducible OCI images, pinned in release/app.lock;
  * binaries / .deb: local files referenced by file:// URLs with sha256;
  * egress-proxy: tiny Dockerfile; egress data and validator: the real ones;
  * Worker (optional): the real sources (npm ci + build + pack.sh).
The fixture node checkout carries this repository's release/ tools, so the
bundle lands in <fixture node>/release/out/.
Requires docker (buildx, containerd image store), syft, yq, git, ssh-keygen.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(NODE, "release", "lib"))
import relcore as rc  # noqa: E402

REGISTRY_IMAGE = "docker.io/library/registry:3@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"
NODE_REPO = "github.com/JakubLog/legatto-node"


def sh(cmd, cwd=None, env=None, stdin=None, ok=True):
    full = dict(os.environ)
    if env:
        full.update(env)
    res = subprocess.run(cmd, cwd=cwd, env=full, input=stdin.encode() if isinstance(stdin, str) else stdin,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ok and res.returncode != 0:
        raise RuntimeError("%s failed (%d):\n%s\n%s" % (" ".join(cmd), res.returncode,
                                                       res.stdout.decode(errors="replace")[-3000:],
                                                       res.stderr.decode(errors="replace")[-5000:]))
    return res


def write(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content.encode() if isinstance(content, str) else content)
    os.chmod(path, mode)


def keygen():
    path = os.environ.get("LEGATTO_SSH_KEYGEN") or "/opt/homebrew/bin/ssh-keygen"
    return path if os.path.isfile(path) else shutil.which("ssh-keygen")


def git_commit(repo, epoch, message):
    env = {"GIT_AUTHOR_DATE": "@%d +0000" % epoch, "GIT_COMMITTER_DATE": "@%d +0000" % epoch,
           "GIT_AUTHOR_NAME": "ci-test", "GIT_AUTHOR_EMAIL": "ci@legatto.invalid",
           "GIT_COMMITTER_NAME": "ci-test", "GIT_COMMITTER_EMAIL": "ci@legatto.invalid"}
    sh(["git", "add", "-A"], cwd=repo)
    sh(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", message], cwd=repo, env=env)


def make_deb(path, package, version):
    """Minimal valid Debian binary package (ar: debian-binary, control.tar.gz, data.tar.gz)."""
    def targz(files):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as t:
            for name, data in files.items():
                ti = tarfile.TarInfo(name)
                ti.size, ti.mtime, ti.mode = len(data), 0, 0o644
                t.addfile(ti, io.BytesIO(data))
        return raw.getvalue()

    control = ("Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: ci <ci@legatto.invalid>\n"
               "Description: test package\n" % (package, version)).encode()
    members = [("debian-binary", b"2.0\n"), ("control.tar.gz", targz({"./control": control})),
               ("data.tar.gz", targz({"./usr/share/doc/%s/README" % package: b"test\n"}))]
    out = b"!<arch>\n"
    for name, data in members:
        out += ("%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, 0, 0, 0, "100644", len(data))).encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    write(path, out)


def tar_members(path):
    with tarfile.open(path) as t:
        return {m.name: (m, t.extractfile(m).read() if m.isfile() else None) for m in t.getmembers()}


APP_BUILD_SCRIPT = r'''#!/usr/bin/env bash
# Fixture of legatto-app scripts/release/build-images.sh: reproducible tiny images.
set -euo pipefail
while (($#)); do
  case "$1" in
  --version) version="$2"; shift 2 ;;
  --out) out="$2"; shift 2 ;;
  --platform) platform="$2"; shift 2 ;;
  *) echo "unknown $1" >&2; exit 2 ;;
  esac
done
epoch="$(git log -1 --format=%ct)"
mkdir -p "$out"
ctx="$(mktemp -d)"
for n in app functions migrator; do
  mkdir -p "$ctx/$n"
  cp "images/$n.txt" "$ctx/$n/content.txt"
  printf 'FROM scratch\nCOPY content.txt /%s.txt\n' "$n" > "$ctx/$n/Dockerfile"
  SOURCE_DATE_EPOCH="$epoch" docker buildx build -q --platform "$platform" --provenance=false --sbom=false \
    --build-arg SOURCE_DATE_EPOCH="$epoch" \
    --output "type=oci,dest=$out/$n.oci.tar,name=ghcr.io/jakublog/legatto/$n:$version,rewrite-timestamp=true" \
    "$ctx/$n" >/dev/null
done
rm -rf "$ctx"
python3 - "$out" "$version" <<'PY'
import hashlib, json, os, sys, tarfile
out, version = sys.argv[1], sys.argv[2]
commit = os.popen("git rev-parse HEAD").read().strip()
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
images, artifacts = {}, []
for n in ("app", "functions", "migrator"):
    p = os.path.join(out, n + ".oci.tar")
    with tarfile.open(p) as t:
        digest = json.load(t.extractfile("index.json"))["manifests"][0]["digest"]
    images[n] = {"ref": "ghcr.io/jakublog/legatto/%s:%s" % (n, version), "digest": digest,
                 "platform": "linux/amd64", "artifact": n + ".oci.tar"}
    artifacts.append({"name": n + ".oci.tar", "kind": "oci-archive", "size": os.path.getsize(p), "sha256": sha(p)})
mig = sorted(os.listdir("supabase/migrations"))
rel = {"schema": "legatto-app-release/1", "version": version, "commit": commit, "repo": "github.com/JakubLog/legatto",
       "images": images, "artifacts": artifacts,
       "migrations": {"from": None, "to": mig[-1][:14], "count": len(mig),
                      "files": [{"name": m, "sha256": sha(os.path.join("supabase/migrations", m))} for m in mig]},
       "crons": [{"name": "sync-ics", "path": "/api/cron/sync-ics", "schedule": "0 4 * * *"}],
       "functions": ["device-login"]}
open(os.path.join(out, "release.json"), "w").write(json.dumps(rel, sort_keys=True, indent=2) + "\n")
json.dump({n: images[n]["digest"] for n in images}, open(os.path.join(out, "digests.json"), "w"), sort_keys=True)
PY
'''

COMPOSE = '''name: legatto
services:
  db:
    image: "@@LEGATTO_IMAGE:db@@"
  app:
    image: "@@LEGATTO_IMAGE:app@@"
  functions:
    image: "@@LEGATTO_IMAGE:functions@@"
  migrator:
    image: "@@LEGATTO_IMAGE:migrator@@"
  egress-app:
    image: "@@LEGATTO_IMAGE:egress-proxy@@"
'''


class Env:
    """Paths and values of one fixture (see setup)."""


def setup(t, with_worker):
    """Registry, legatto-app and legatto-node fixtures under t; nothing released yet."""
    e = Env()
    e.t = t
    e.keygen = keygen()
    e.epoch = int(time.time()) - 7200

    # local registry with the "upstream" db image
    e.registry_cid = sh(["docker", "run", "-d", "--rm", "-p", "127.0.0.1::5000", REGISTRY_IMAGE]).stdout.decode().strip()
    port = sh(["docker", "port", e.registry_cid, "5000"]).stdout.decode().split("\n")[0].rsplit(":", 1)[1]
    e.db_ref = "localhost:%s/legatto-test/db:17.6" % port
    ctx = os.path.join(t, "db-image")
    write(os.path.join(ctx, "hello"), "db fixture\n")
    write(os.path.join(ctx, "Dockerfile"), "FROM scratch\nCOPY hello /hello\n")
    meta = os.path.join(t, "db-meta.json")
    for _ in range(20):
        res = sh(["docker", "buildx", "build", "-q", "--platform", "linux/amd64", "--provenance=false", "--sbom=false",
                  "--metadata-file", meta, "--output", "type=image,name=%s,push=true" % e.db_ref, ctx], ok=False)
        if res.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("push to the local registry failed: %s" % res.stderr.decode(errors="replace"))
    e.db_digest = json.load(open(meta))["containerimage.digest"]
    raw = json.loads(sh(["docker", "buildx", "imagetools", "inspect", "--raw",
                         "%s@%s" % (e.db_ref.rsplit(":", 1)[0], e.db_digest)]).stdout)
    if "manifests" in raw:  # an index: take the linux/amd64 manifest
        e.db_digest = next(m["digest"] for m in raw["manifests"]
                           if m.get("platform", {}).get("architecture") == "amd64")

    # legatto-app fixture and its CI output (release.json)
    e.app = os.path.join(t, "legatto-app")
    os.makedirs(e.app)
    sh(["git", "init", "-q", "-b", "main"], cwd=e.app)
    write(os.path.join(e.app, "scripts", "release", "build-images.sh"), APP_BUILD_SCRIPT, 0o755)
    for n in ("app", "functions", "migrator"):
        write(os.path.join(e.app, "images", n + ".txt"), "%s fixture\n" % n)
    write(os.path.join(e.app, "supabase", "migrations", "20261121000000_init.sql"), "create table t (id int);\n")
    git_commit(e.app, e.epoch, "app fixture")
    app_out = os.path.join(t, "app-ci-out")
    sh(["bash", "scripts/release/build-images.sh", "--version", "2.0.0", "--out", app_out,
        "--platform", "linux/amd64"], cwd=e.app)

    # legatto-node fixture: this repository's release tools, contract and egress validator
    e.node = os.path.join(t, "legatto-node")
    for rel in ("release/build.sh", "release/lib", "release/schema", "contract/contract.yml",
                "egress/legatto-egress", "bundle/egress", ".gitignore"):
        src, dst = os.path.join(NODE, rel), os.path.join(e.node, rel)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    e.has_worker = with_worker and os.path.isfile(os.path.join(NODE, "worker", "package.json"))
    if e.has_worker:  # the real Worker sources: exercises npm ci + build + pack.sh in the pinned Node image
        shutil.copytree(os.path.join(NODE, "worker"), os.path.join(e.node, "worker"),
                        ignore=shutil.ignore_patterns("node_modules", "dist", ".wrangler"))
    write(os.path.join(e.node, "egress", "image", "Dockerfile"), "FROM scratch\nCOPY proxy.txt /proxy.txt\n")
    write(os.path.join(e.node, "egress", "image", "proxy.txt"), "egress proxy fixture\n")
    b = os.path.join(e.node, "bundle")
    write(os.path.join(b, "compose", "docker-compose.legatto.yml"), COMPOSE)
    write(os.path.join(b, "compose", "volumes", "api", "entrypoint.sh"), "#!/bin/sh\nexec \"$@\"\n", 0o755)
    write(os.path.join(b, "compose", ".env.example"), "NOT_SHIPPED=1\n")
    write(os.path.join(b, "caddy", "sites.d", "crm.caddy.tmpl"), "${LEGATTO_HOST_CRM} {\n\trespond 200\n}\n")
    write(os.path.join(b, "systemd", "legatto-stack.service"), "[Service]\nExecStart=/opt/legatto/bin/stack\n")
    write(os.path.join(b, "env", "app.env.tmpl"), "LEGATTO_TZ=${LEGATTO_TZ}\n")
    dl = os.path.join(t, "downloads")
    os.makedirs(dl)
    caddy_tgz = os.path.join(dl, "caddy.tar.gz")
    with tarfile.open(caddy_tgz, "w:gz") as tz:
        data = b"#!/bin/sh\necho caddy fixture\n"
        ti = tarfile.TarInfo("caddy")
        ti.size, ti.mode = len(data), 0o755
        tz.addfile(ti, io.BytesIO(data))
    deb = os.path.join(dl, "headscale_0.29.7_linux_amd64.deb")
    make_deb(deb, "headscale", "0.29.7")
    versions = {
        "legatto_supabase_selfhosted_version": "0.8.4",
        "legatto_images": {"db": {"ref": e.db_ref, "digest": e.db_digest}},
        "legatto_binaries": {"caddy": {"version": "2.11.9", "url": "file://" + caddy_tgz, "member": "caddy",
                                       "sha256": rc.sha256_file(caddy_tgz), "size": os.path.getsize(caddy_tgz)}},
        "legatto_debs": {"headscale": {"version": "0.29.7", "url": "file://" + deb,
                                       "sha256": rc.sha256_file(deb), "size": os.path.getsize(deb)}},
    }
    write(os.path.join(e.node, "contract", "versions.yml"), "---\n" + json.dumps(versions, indent=2) + "\n")
    sh(["git", "init", "-q", "-b", "main"], cwd=e.node)
    sh(["git", "remote", "add", "origin", "https://%s.git" % NODE_REPO], cwd=e.node)
    sh([sys.executable, os.path.join(e.node, "release", "lib", "applock.py"),
        "--release-json", os.path.join(app_out, "release.json")])
    git_commit(e.node, e.epoch, "node fixture")
    e.lock = json.load(open(os.path.join(e.node, "release", "app.lock")))
    e.out_root = os.path.join(e.node, "release", "out")
    e.env = {"LEGATTO_PYTHON": sys.executable, "LEGATTO_SSH_KEYGEN": e.keygen or ""}
    return e


def add_release(e, version, sequence, extra_commit=None, minutes=1):
    """Commit release/notes/<version>.{json,md} (and optional changes) into the node fixture."""
    write(os.path.join(e.node, "release", "notes", version + ".json"),
          json.dumps({"type": "feature", "sequence": sequence, "min_installed": "0.0.0", "min_contract_version": 1,
                      "advisories": []}, indent=2) + "\n")
    write(os.path.join(e.node, "release", "notes", version + ".md"), "# %s\n\nWydanie testowe %s.\n" % (version, version))
    if extra_commit:
        extra_commit(e)
    e.epoch += 60 * minutes
    git_commit(e.node, e.epoch, "release %s" % version)


def build(e, version, out=None, env=None, ok=True, extra=()):
    cmd = [os.path.join(e.node, "release", "build.sh"), "--version", version, "--app-src", e.app] + list(extra)
    if out:
        cmd += ["--out", out]
    return sh(cmd, cwd=e.node, env=dict(e.env, **(env or {})), ok=ok)


def teardown(e):
    if e is not None and getattr(e, "registry_cid", None):
        subprocess.run(["docker", "stop", e.registry_cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
