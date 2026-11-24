"""Assemble an unsigned release bundle: release/out/<version>/ (CONTRACT §4.7-4.8, R6).

Inputs (all from a clean, committed legatto-node tree — this repository):
  release/notes/<V>.json   type, sequence, min_installed, min_contract_version, advisories,
                           optional channels, healthchecks, expires_days
  release/notes/<V>.md     changelog (Polish) -> artifact notes.md
  release/app.lock         pinned legatto-app release; the app images are rebuilt
                           from that commit and must reproduce the pinned digests
  contract/versions.yml    upstream images (by digest), binaries, .deb
  bundle/{compose,caddy/sites.d,systemd,env}/**   -> config.tar.gz
  bundle/egress/{base,features}.yml     -> manifest.egress
  egress/image/                          -> egress-proxy image
  worker/                                -> worker.tar.gz
manifest.source pins exactly two sources: this legatto-node commit and the
legatto-app release. The same command runs on the vendor's control machine
and in this repository's CI (.github/workflows/release-build.yml, reference
build with build provenance); the vendor signs only when both agree.

Determinism: every time field derives from the commit time of HEAD
(SOURCE_DATE_EPOCH), tarballs are canonical (sorted, fixed owner and mtime,
gzip without name/time), SBOMs are normalised. Two builds of the same commit
give the same manifest except the sha256/size of image archives (docker save
is not byte-reproducible); the vendor's signing tool relies on that.

Image archives (V2): an image whose digest did not change keeps the archive
bytes of an earlier build (local cache release/out/.cache/images/, else the
archive of a published release, sha256 checked against its signed
manifest). Its artifact sha256 is then the same in every release, so
publishing copies it on the server and offices reuse the file they have.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

import relcore as rc
import schema

APP_IMAGES = ("app", "functions", "migrator")
EGRESS_IMAGE = "egress-proxy"
PLACEHOLDER_RE = re.compile(r"@@LEGATTO_IMAGE:([a-z][a-z0-9-]{0,40})@@")
LEFTOVER_RE = re.compile(r"@@[A-Z_]+[^@\n]*@@")
# Node toolchain for the Worker build (same digest as .github/workflows/worker.yml):
# node 22.23.5, bookworm (has openssl for the Worker tool tests), image index digest.
NODE_IMAGE = "docker.io/library/node:22-bookworm@sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb"
DEFAULT_HEALTHCHECKS = ["compose:all-healthy", "http:crm:/healthz", "sql:migration-level", "egress:selftest"]
SPEC_KEYS = {"type", "sequence", "min_installed", "min_contract_version", "advisories", "channels",
             "healthchecks", "expires_days"}
CONFIG_TREES = (  # (bundle subdirectory, path prefix in config.tar.gz, applier)
    ("compose", "compose", "compose"),
    ("caddy/sites.d", "caddy/sites.d", "caddy-site"),
    ("systemd", "systemd", "systemd-unit"),
    ("env", "env", "env-template"),
)
CONFIG_PATH_RULES = {  # updater constraints per applier (CONTRACT §4.8)
    "caddy-site": re.compile(r"^caddy/sites\.d/[a-z0-9][a-z0-9._-]*\.caddy(\.tmpl)?$"),
    "systemd-unit": re.compile(
        r"^systemd/(legatto-stack\.service|legatto-cron@\.service|legatto-cron-[a-z0-9-]+\.(service|timer)"
        r"|legatto-secrets-render\.service)(\.tmpl)?$"),
    "env-template": re.compile(r"^env/[a-z0-9][a-z0-9._-]*\.env\.tmpl$"),
}


# --- small helpers -------------------------------------------------------------------------

def git(*args: str, cwd: str = rc.NODE) -> str:
    return rc.run(["git"] + list(args), cwd=cwd, capture=True, quiet=True).stdout.decode().strip()


def repo_slug_from_remote(url: str) -> Optional[str]:
    m = re.match(r"^(?:https://|ssh://git@|git@)github\.com[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", url)
    return "github.com/%s/%s" % (m.group(1), m.group(2)) if m else None


def node_source() -> Tuple[str, str, int]:
    """(repo, commit, commit epoch) of the clean legatto-node checkout this builder belongs to.

    The bundle, egress and Worker sources, the contract, the release notes
    and app.lock are read from this commit only, never from uncommitted files.
    """
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise rc.ReleaseError("drzewo legatto-node ma niezatwierdzone zmiany — paczka powstaje tylko z commita")
    commit = git("rev-parse", "HEAD")
    epoch = int(git("show", "-s", "--format=%ct", "HEAD"))
    repo = os.environ.get("LEGATTO_NODE_REPO")
    if not repo:
        try:
            repo = repo_slug_from_remote(git("remote", "get-url", "origin")) or ""
        except rc.ReleaseError:
            repo = ""
    if not re.match(r"^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo or ""):
        raise rc.ReleaseError("nie ustalono repo node (origin na github.com albo LEGATTO_NODE_REPO=github.com/<owner>/<repo>)")
    return repo, commit, epoch


def link_or_copy(src: str, dst: str) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


def repository_of(ref: str) -> str:
    """docker.io/supabase/postgres:17.6 -> docker.io/supabase/postgres"""
    head, sep, tail = ref.rpartition(":")
    return head if sep and "/" not in tail else ref


def download(url: str, sha256: str, size: Optional[int], cache_dir: str) -> str:
    """Download url into the content-addressed cache; verify sha256 (and size)."""
    os.makedirs(cache_dir, exist_ok=True)
    target = os.path.join(cache_dir, sha256)
    if os.path.isfile(target) and rc.sha256_file(target) == sha256:
        return target
    rc.info("pobieranie %s" % url)
    tmp = target + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": "legatto-release"})
    with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    got = rc.sha256_file(tmp)
    if got != sha256 or (size is not None and os.path.getsize(tmp) != size):
        os.unlink(tmp)
        raise rc.ReleaseError("%s: sha256/rozmiar niezgodny z oczekiwanym %s (sha256 %s)" % (url, sha256, got))
    os.replace(tmp, target)
    return target


class CanonicalTar:
    """Deterministic .tar.gz: sorted entries, uid/gid 0, fixed mtime, gzip without name and time."""

    def __init__(self, mtime: int):
        self.mtime = mtime
        self.entries: Dict[str, Tuple[Optional[bytes], int]] = {}

    def add_dir(self, path: str) -> None:
        self.entries.setdefault(path.rstrip("/") + "/", (None, 0o755))

    def add_file(self, path: str, data: bytes, executable: bool) -> None:
        if path in self.entries:
            raise rc.ReleaseError("zdublowana ścieżka w archiwum: %s" % path)
        parts = path.split("/")
        for i in range(1, len(parts)):
            self.add_dir("/".join(parts[:i]))
        self.entries[path] = (data, 0o755 if executable else 0o644)

    def write(self, dest: str) -> None:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for path in sorted(self.entries):
                data, mode = self.entries[path]
                info = tarfile.TarInfo(path.rstrip("/"))
                info.mtime, info.mode, info.uid, info.gid, info.uname, info.gname = self.mtime, mode, 0, 0, "", ""
                if data is None:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                else:
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        out = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
            gz.write(raw.getvalue())
        rc.write_bytes(dest, out.getvalue())


def oci_descriptor(tar_path: str) -> Dict[str, Any]:
    """The single image descriptor of an OCI archive (docker save / buildx type=oci)."""
    try:
        with tarfile.open(tar_path) as tar:
            member = tar.extractfile("index.json")
            if member is None:
                raise KeyError
            index = json.loads(member.read().decode("utf-8"))
    except (KeyError, tarfile.TarError, ValueError):
        raise rc.ReleaseError("%s: brak index.json (wymagany format OCI z Docker >= 25)" % tar_path)
    manifests = index.get("manifests") or []
    if len(manifests) != 1 or manifests[0].get("mediaType") not in (
            "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"):
        raise rc.ReleaseError("%s: index.json musi wskazywać dokładnie jeden manifest obrazu" % tar_path)
    return manifests[0]


def check_oci(tar_path: str, digest: str, ref: str) -> None:
    desc = oci_descriptor(tar_path)
    if desc.get("digest") != digest:
        raise rc.ReleaseError("%s: digest %s, oczekiwano %s" % (tar_path, desc.get("digest"), digest))
    name = (desc.get("annotations") or {}).get("io.containerd.image.name")
    if name != ref:
        raise rc.ReleaseError("%s: nazwa obrazu %r, oczekiwano %r (docker load musi nadać nazwę)" % (tar_path, name, ref))


def published_archives(workdir: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """(ref, digest) -> archive of a published release, from signed manifests on LEGATTO_UPDATES_URL.

    Reads the public URL only (no storage credentials); index and manifests
    must carry valid release signatures (allowed_signers of this checkout).
    """
    layout = rc.contract()["legatto_release_layout"]
    got = rc.fetch_verified(layout["index"], "index", "release", workdir, public_only=True)
    if got is None:
        return {}
    index = rc.load_json_bytes(got[1], layout["index"])
    base = (os.environ.get("LEGATTO_UPDATES_URL") or rc.DEFAULT_UPDATES_URL).rstrip("/")
    found: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for rel in sorted(index.get("releases") or [], key=lambda r: r["sequence"], reverse=True):
        key = layout["manifest"].replace("<version>", rel["version"])
        m = rc.fetch_verified(key, "release", "release", workdir, public_only=True)
        if m is None or rc.sha256_bytes(m[1]) != rel["manifest_sha256"]:
            continue
        manifest = rc.load_json_bytes(m[1], key)
        arts = {a["name"]: a for a in manifest["artifacts"]}
        for img in manifest["images"]:
            art = arts.get(img["artifact"] or "")
            if art is not None and (img["ref"], img["digest"]) not in found:
                found[(img["ref"], img["digest"])] = {
                    "version": rel["version"], "sha256": art["sha256"], "size": art["size"],
                    "url": "%s/%s" % (base, layout["artifacts"].replace("<version>", rel["version"])
                                      .replace("<artifact name>", art["name"]))}
    return found


class ImageArchives:
    """Image archives by digest: the local cache first, then published releases, else a fresh archive."""

    def __init__(self, cache_root: str, workdir: str, use_published: bool):
        self.cache_root = cache_root
        self.dir = os.path.join(cache_root, "images")
        self.workdir = workdir
        self.use_published = use_published
        self._published: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None

    def _path(self, digest: str) -> str:
        return os.path.join(self.dir, digest.split(":", 1)[1] + ".tar")

    @staticmethod
    def _valid(path: str, digest: str, ref: str) -> bool:
        try:
            check_oci(path, digest, ref)
        except rc.ReleaseError:
            return False
        return True

    def published(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        if self._published is None:
            self._published = {}
            if self.use_published:
                try:
                    self._published = published_archives(os.path.join(self.workdir, "published"))
                except (rc.ReleaseError, OSError) as e:
                    rc.info("UWAGA: opublikowane wydania niedostępne (%s) — archiwa obrazów tylko z lokalnej pamięci" % e)
        return self._published

    def find(self, ref: str, digest: str) -> Optional[str]:
        """An archive of exactly this image (name and digest) built before, or None."""
        path = self._path(digest)
        if os.path.isfile(path) and self._valid(path, digest, ref):
            return path
        hit = self.published().get((ref, digest))
        if hit is None:
            return None
        try:
            blob = download(hit["url"], hit["sha256"], hit["size"], self.cache_root)
        except (rc.ReleaseError, OSError) as e:
            rc.info("UWAGA: archiwum %s z wydania %s niedostępne (%s)" % (digest, hit["version"], e))
            return None
        if not self._valid(blob, digest, ref):
            return None
        return self.keep(blob, digest)

    def keep(self, path: str, digest: str) -> str:
        """Move a verified archive into the cache; returns its cached path."""
        os.makedirs(self.dir, exist_ok=True)
        target = self._path(digest)
        shutil.move(path, target)
        os.chmod(target, 0o644)
        return target


# --- the build ----------------------------------------------------------------------------------

class Build:
    def __init__(self, version: str, out: str, app_src: Optional[str], reuse_published: bool = True):
        self.version = rc.check_semver(version)
        self.out = out
        self.app_src_arg = app_src
        self.reuse_published = reuse_published
        self.artifacts: List[Dict[str, Any]] = []
        self.images: List[Dict[str, Any]] = []
        self.sboms: List[Dict[str, Any]] = []
        self.components: List[str] = []

    # -- inputs
    def load_inputs(self) -> None:
        notes_dir = os.path.join(rc.NODE, "release", "notes")
        self.spec = rc.read_json(os.path.join(notes_dir, self.version + ".json"))
        unknown = set(self.spec) - SPEC_KEYS
        missing = {"type", "sequence", "min_installed", "min_contract_version", "advisories"} - set(self.spec)
        if unknown or missing:
            raise rc.ReleaseError("release/notes/%s.json: nieznane klucze %s, brakujące %s" % (
                self.version, sorted(unknown), sorted(missing)))
        notes_md = os.path.join(notes_dir, self.version + ".md")
        if not os.path.isfile(notes_md) or not open(notes_md, encoding="utf-8").read().strip():
            raise rc.ReleaseError("brak changelogu release/notes/%s.md" % self.version)
        self.notes_md = notes_md
        contract_version = int(rc.contract()["legatto_contract_version"])
        if int(self.spec["min_contract_version"]) > contract_version:
            raise rc.ReleaseError("min_contract_version %s > legatto_contract_version %d" % (
                self.spec["min_contract_version"], contract_version))
        self.versions = rc.yaml_to_json(rc.VERSIONS_YML)
        self.lock = rc.read_json(os.path.join(rc.NODE, "release", "app.lock"))
        if self.lock.get("schema") != "legatto-app-lock/1":
            raise rc.ReleaseError("release/app.lock: schema musi być legatto-app-lock/1")
        if not self.lock.get("app"):
            raise rc.ReleaseError("release/app.lock nie przypina wydania legatto-app — "
                                  "przypnij je: python3 release/lib/applock.py --release-json <release.json>")
        self.repo, self.commit, self.epoch = node_source()
        self.released_at = rc.fmt_ts(self.epoch)
        expires_days = int(self.spec.get("expires_days", 60))
        if not 7 <= expires_days <= 365:
            raise rc.ReleaseError("expires_days poza zakresem 7-365")
        self.expires = rc.fmt_ts(self.epoch + expires_days * 86400)
        if rc.parse_ts(self.expires) <= rc.now_epoch():
            raise rc.ReleaseError("manifest wygasłby przed publikacją (commit z %s + %d dni)" % (self.released_at, expires_days))

    def add_artifact(self, name: str, kind: str, **extra: Any) -> Dict[str, Any]:
        path = os.path.join(self.out, name)
        art = {"name": name, "kind": kind, "size": os.path.getsize(path), "sha256": rc.sha256_file(path)}
        art.update(extra)
        self.artifacts.append(art)
        return art

    # -- images
    def required_images(self) -> List[str]:
        compose_dir = os.path.join(self.src, "bundle", "compose")
        if not os.path.isdir(compose_dir):
            raise rc.ReleaseError("brak bundle/compose")
        names = set()
        for path, _ in self.walk(compose_dir):
            with open(path, "rb") as f:
                names.update(PLACEHOLDER_RE.findall(f.read().decode("utf-8", errors="replace")))
        if not names:
            raise rc.ReleaseError("bundle/compose nie zawiera żadnego @@LEGATTO_IMAGE:<name>@@")
        return sorted(names)

    def add_image(self, name: str, ref: str, digest: str, produce: Callable[[], str]) -> None:
        """Ship image name: the archive built before for this ref and digest, else produce() (checked)."""
        path = self.archives.find(ref, digest)
        if path is None:
            fresh = produce()
            check_oci(fresh, digest, ref)
            path = self.archives.keep(fresh, digest)
        else:
            rc.info("obraz %s %s bez zmian — archiwum użyte ponownie (ten sam sha256)" % (name, digest))
        art_name = "image-%s.tar" % name
        link_or_copy(path, os.path.join(self.out, art_name))
        self.add_artifact(art_name, "oci-archive")
        self.images.append({"name": name, "ref": ref, "digest": digest, "platform": "linux/amd64", "artifact": art_name})
        self.sbom("image-" + name, "oci-archive:" + art_name, "image %s (%s@%s)" % (name, repository_of(ref), digest), ref)

    def upstream_image(self, name: str) -> None:
        key = name.replace("-", "_")
        entry = (self.versions.get("legatto_images") or {}).get(key)
        if not entry:
            raise rc.ReleaseError("obraz %s nie ma wpisu legatto_images.%s w versions.yml" % (name, key))
        ref, digest = entry["ref"], entry["digest"]

        def save() -> str:
            pinned = "%s@%s" % (repository_of(ref), digest)
            rc.run(["docker", "pull", "--quiet", "--platform", "linux/amd64", pinned])
            rc.run(["docker", "tag", pinned, ref])
            tar_path = os.path.join(self.work, "image-%s.tar" % name)
            rc.run(["docker", "save", "--platform", "linux/amd64", "-o", tar_path, ref])
            return tar_path

        self.add_image(name, ref, digest, save)

    def egress_image(self) -> None:
        """Build egress/image. Tag and SOURCE_DATE_EPOCH come from the egress/image tree and its last
        commit, so an unchanged source gives the same image (and the cached archive) in every release."""
        context = os.path.join(self.src, "egress", "image")
        if not os.path.isfile(os.path.join(context, "Dockerfile")):
            raise rc.ReleaseError("brak egress/image/Dockerfile")
        tree = git("rev-parse", "%s:egress/image" % self.commit)
        epoch = int(git("log", "-1", "--format=%ct", self.commit, "--", "egress/image"))
        owner_repo = self.repo.split("/", 1)[1].lower()
        ref = "ghcr.io/%s/egress-proxy:src-%s" % (owner_repo, tree[:12])
        tar_path = os.path.join(self.work, "egress-proxy.oci.tar")
        rc.run(["docker", "buildx", "build", "--platform", "linux/amd64", "--provenance=false", "--sbom=false",
                "--build-arg", "SOURCE_DATE_EPOCH=%d" % epoch,
                "--output", "type=oci,dest=%s,name=%s,rewrite-timestamp=true" % (tar_path, ref), context],
               env={"SOURCE_DATE_EPOCH": str(epoch)})
        self.add_image(EGRESS_IMAGE, ref, oci_descriptor(tar_path)["digest"], lambda: tar_path)

    def export_head(self) -> str:
        """Committed content only (git archive of the legatto-node commit): ignored files never reach
        the bundle or build contexts."""
        src = os.path.join(self.work, "src")
        os.makedirs(src)
        top = set(git("ls-tree", "--name-only", self.commit).split("\n"))
        paths = [p for p in ("bundle", "egress", "worker") if p in top]
        if not paths:
            return src
        archive = rc.run(["git", "archive", "--format=tar", self.commit, "--"] + paths,
                         cwd=rc.NODE, capture=True, quiet=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    raise rc.ReleaseError("niebezpieczna ścieżka w git archive: %s" % member.name)
            if hasattr(tarfile, "data_filter"):
                tar.extractall(src, filter="data")
            else:
                tar.extractall(src)
        return src

    # -- legatto-app
    def app_source(self) -> str:
        app = self.lock["app"]
        src = self.app_src_arg or os.environ.get("LEGATTO_APP_SRC")
        if src:
            src = os.path.abspath(src)
            head = git("rev-parse", "HEAD", cwd=src)
            if head != app["commit"]:
                raise rc.ReleaseError("%s: HEAD %s ≠ commit z app.lock %s" % (src, head, app["commit"]))
            if git("status", "--porcelain", "--untracked-files=normal", cwd=src):
                raise rc.ReleaseError("%s: drzewo legatto-app ma niezatwierdzone zmiany" % src)
            return src
        src = os.path.join(self.work, "legatto-app")
        url = "https://%s.git" % app["repo"]
        rc.run(["git", "clone", "--quiet", "--no-checkout", url, src])
        rc.run(["git", "-c", "advice.detachedHead=false", "checkout", "--quiet", app["commit"]], cwd=src)
        return src

    def app_release(self) -> Dict[str, Any]:
        app = self.lock["app"]
        src = self.app_source()
        app_out = os.path.join(self.work, "app-release")
        script = os.path.join(src, "scripts", "release", "build-images.sh")
        if not os.path.isfile(script):
            raise rc.ReleaseError("legatto-app %s nie ma scripts/release/build-images.sh" % app["commit"])
        rc.run(["bash", script, "--version", app["version"], "--out", app_out, "--platform", "linux/amd64"], cwd=src)
        release_json = os.path.join(app_out, "release.json")
        got = rc.sha256_file(release_json)
        if got != app["release_sha256"]:
            raise rc.ReleaseError("przebudowa legatto-app %s daje release.json %s, app.lock przypina %s" % (
                app["version"], got, app["release_sha256"]))
        rel = rc.read_json(release_json)
        for key in ("repo", "commit", "version"):
            if rel.get(key) != app[key]:
                raise rc.ReleaseError("release.json: %s=%r ≠ app.lock %r" % (key, rel.get(key), app[key]))
        for name in APP_IMAGES:
            img = rel["images"][name]
            if img["digest"] != app["images"][name]:
                raise rc.ReleaseError("obraz %s: przebudowa %s ≠ app.lock %s" % (name, img["digest"], app["images"][name]))
            listed = {a["name"]: a for a in rel.get("artifacts", [])}
            art = listed.get(img["artifact"])
            path = os.path.join(app_out, img["artifact"])
            if not art or rc.sha256_file(path) != art["sha256"]:
                raise rc.ReleaseError("legatto-app: artefakt %s niezgodny z release.json" % img["artifact"])
            img["path"] = path
        rel["_src"] = src
        return rel

    def app_migrations(self, rel: Dict[str, Any]) -> Dict[str, Any]:
        mig = rel["migrations"]
        files = mig.get("files") or []
        if files:
            tar = CanonicalTar(self.epoch)
            for f in files:
                path = os.path.join(rel["_src"], "supabase", "migrations", f["name"])
                if not os.path.isfile(path):
                    raise rc.ReleaseError("brak migracji %s w legatto-app %s" % (f["name"], rel["commit"]))
                with open(path, "rb") as fh:
                    data = fh.read()
                if rc.sha256_bytes(data) != f["sha256"]:
                    raise rc.ReleaseError("migracja %s: sha256 ≠ release.json" % f["name"])
                tar.add_file(f["name"], data, executable=False)
            tar.write(os.path.join(self.out, "migrations.tar.gz"))
            self.add_artifact("migrations.tar.gz", "sql-migrations")
        return {"from": mig.get("from"), "to": mig["to"], "count": int(mig.get("count", len(files))),
                "files": [{"name": f["name"], "sha256": f["sha256"]} for f in files], "n_minus_1_compatible": True}

    # -- config.tar.gz
    @staticmethod
    def walk(top: str):
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for fn in sorted(filenames):
                if fn.startswith(".") or fn.upper().startswith("README"):
                    continue
                path = os.path.join(dirpath, fn)
                if os.path.islink(path) or not os.path.isfile(path):
                    raise rc.ReleaseError("w paczce dozwolone są tylko zwykłe pliki: %s" % path)
                yield path, os.path.relpath(path, top).replace(os.sep, "/")

    def config(self) -> None:
        tar = CanonicalTar(self.epoch)
        files = []
        subst = {i["name"]: "%s@%s" % (repository_of(i["ref"]), i["digest"]) for i in self.images}
        for sub, prefix, applier in CONFIG_TREES:
            top = os.path.join(self.src, "bundle", sub)
            if not os.path.isdir(top):
                if applier == "compose":
                    raise rc.ReleaseError("brak bundle/compose")
                continue
            for dirpath, dirnames, _ in os.walk(top):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                rel_dir = os.path.relpath(dirpath, top).replace(os.sep, "/")
                tar.add_dir(prefix if rel_dir == "." else "%s/%s" % (prefix, rel_dir))
            for path, rel in self.walk(top):
                arc = "%s/%s" % (prefix, rel)
                rule = CONFIG_PATH_RULES.get(applier)
                if rule and not rule.match(arc):
                    raise rc.ReleaseError("%s: nazwa niedozwolona dla applier %s" % (arc, applier))
                with open(path, "rb") as f:
                    data = f.read()
                if applier == "compose":
                    text = data.decode("utf-8", errors="surrogateescape")

                    def repl(m: "re.Match[str]") -> str:
                        if m.group(1) not in subst:
                            raise rc.ReleaseError("%s: obraz %s nie istnieje w paczce" % (arc, m.group(1)))
                        return subst[m.group(1)]

                    text = PLACEHOLDER_RE.sub(repl, text)
                    data = text.encode("utf-8", errors="surrogateescape")
                if LEFTOVER_RE.search(data.decode("utf-8", errors="replace")):
                    raise rc.ReleaseError("%s: pozostał nierozwiązany znacznik @@…@@" % arc)
                executable = bool(os.stat(path).st_mode & stat.S_IXUSR)
                tar.add_file(arc, data, executable)
                files.append({"path": arc, "sha256": rc.sha256_bytes(data), "applier": applier})
        tar.write(os.path.join(self.out, "config.tar.gz"))
        self.add_artifact("config.tar.gz", "config", files=sorted(files, key=lambda f: f["path"]))

    # -- binaries and packages
    def binaries(self) -> None:
        cache = os.path.join(rc.OUT_ROOT, ".cache")
        allow = rc.contract()["legatto_binary_allowlist"]
        for name, b in sorted((self.versions.get("legatto_binaries") or {}).items()):
            if name not in allow:
                raise rc.ReleaseError("binarka %s spoza legatto_binary_allowlist" % name)
            archive = download(b["url"], b["sha256"], b.get("size"), cache)
            with tarfile.open(archive) as tar:
                member = tar.getmember(b["member"])
                if not member.isfile():
                    raise rc.ReleaseError("%s: %s nie jest plikiem" % (b["url"], b["member"]))
                extracted = tar.extractfile(member)
                assert extracted is not None
                data = extracted.read()
            art_name = "%s-%s" % (name, b["version"])
            rc.write_bytes(os.path.join(self.out, art_name), data, mode=0o755)
            sha = rc.sha256_bytes(data)
            self.add_artifact(art_name, "binary", binaries=[{"name": name, "version": b["version"], "sha256": sha}])
            self.sbom("binary-" + name, "file:" + art_name, "binary %s %s" % (name, b["version"]), b["version"])
            self.components.append("- %s %s (sha256 %s)" % (name, b["version"], sha))

    def debs(self) -> None:
        cache = os.path.join(rc.OUT_ROOT, ".cache")
        allow = rc.contract()["legatto_deb_allowlist"]
        for name, d in sorted((self.versions.get("legatto_debs") or {}).items()):
            if name not in allow:
                raise rc.ReleaseError("pakiet %s spoza legatto_deb_allowlist" % name)
            path = download(d["url"], d["sha256"], d.get("size"), cache)
            art_name = d["url"].rsplit("/", 1)[1].lower()
            shutil.copyfile(path, os.path.join(self.out, art_name))
            self.add_artifact(art_name, "deb", packages=[{"name": name, "version": d["version"], "sha256": d["sha256"]}])
            self.sbom("deb-" + name, "file:" + art_name, "deb %s %s" % (name, d["version"]), d["version"])
            self.components.append("- %s %s (.deb, sha256 %s)" % (name, d["version"], d["sha256"]))

    # -- worker
    def worker(self) -> bool:
        wdir = os.path.join(self.src, "worker")
        if not os.path.isfile(os.path.join(wdir, "package.json")):
            return False
        pack = os.path.join(wdir, "scripts", "pack.sh")
        if not os.path.isfile(pack):
            raise rc.ReleaseError("brak worker/scripts/pack.sh")
        uid_gid = "%d:%d" % (os.getuid(), os.getgid())
        res = rc.run(["docker", "run", "--rm", "--platform", "linux/amd64", "--user", uid_gid,
                      "-e", "HOME=/tmp", "-e", "CI=true", "-e", "SOURCE_DATE_EPOCH=%d" % self.epoch,
                      "-v", "%s:/worker" % wdir, "-v", "%s:/out" % self.work, "-w", "/worker", NODE_IMAGE,
                      "sh", "-euc", "npm ci --ignore-scripts --no-audit --no-fund >&2 && npm run build >&2 "
                      "&& sh scripts/pack.sh /out/worker.tar.gz"], capture=True)
        meta = rc.load_json_bytes(res.stdout.strip().splitlines()[-1], "worker/scripts/pack.sh")
        shutil.move(os.path.join(self.work, "worker.tar.gz"), os.path.join(self.out, "worker.tar.gz"))
        with tarfile.open(os.path.join(self.out, "worker.tar.gz")) as tar:
            hashes = {rc.sha256_bytes(tar.extractfile(m).read()) for m in tar.getmembers() if m.isfile()}  # type: ignore[union-attr]
        if meta.get("entry_sha256") not in hashes:
            raise rc.ReleaseError("worker.tar.gz nie zawiera pliku o entry_sha256 z pack.sh")
        self.add_artifact("worker.tar.gz", "worker-bundle",
                          worker={"script_name": meta["script_name"], "entry_sha256": meta["entry_sha256"]})
        self.sbom("worker", "dir:worker", "cloudflare worker %s" % meta["script_name"], self.version,
                  cwd=self.src)
        self.components.append("- Worker %s (entry sha256 %s)" % (meta["script_name"], meta["entry_sha256"]))
        return True

    # -- SBOM
    def sbom(self, slug: str, source: str, subject: str, source_version: str, cwd: Optional[str] = None) -> None:
        name = "sbom-%s.cdx.json" % slug
        res = rc.run([rc.need_tool("syft", "https://github.com/anchore/syft"), "scan", source, "-q",
                      "--source-name", slug, "--source-version", source_version, "-o", "cyclonedx-json"],
                     cwd=cwd or self.out, capture=True)
        doc = json.loads(res.stdout.decode("utf-8"))
        meta = doc.setdefault("metadata", {})
        meta["timestamp"] = self.released_at
        doc.pop("serialNumber", None)
        doc["serialNumber"] = "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "legatto-sbom:" + rc.sha256_bytes(rc.canonical(doc)))
        rc.write_bytes(os.path.join(self.out, name), rc.document_bytes(doc))
        self.add_artifact(name, "sbom")
        self.sboms.append({"artifact": name, "format": "cyclonedx-json", "subject": subject[:200]})

    # -- egress
    def egress(self) -> Dict[str, Any]:
        base = rc.yaml_to_json(os.path.join(self.src, "bundle", "egress", "base.yml"))
        feats = rc.yaml_to_json(os.path.join(self.src, "bundle", "egress", "features.yml"))
        if base.get("version") != 1 or feats.get("version") != 1:
            raise rc.ReleaseError("bundle/egress: version musi być 1")
        egress = {"version": 1, "roles": base.get("roles") or {}, "features": feats.get("features") or {}}
        tool = os.path.join(self.src, "egress", "legatto-egress")
        if not os.path.isfile(tool):
            raise rc.ReleaseError("brak egress/legatto-egress (walidator allowlisty)")
        path = os.path.join(self.work, "egress.json")
        rc.write_bytes(path, rc.document_bytes(egress))
        rc.run([sys.executable, tool, "validate-data", "--egress-json", path])
        return egress

    # -- notes
    def notes(self, app: Dict[str, Any], migrations: Dict[str, Any]) -> None:
        with open(self.notes_md, encoding="utf-8") as f:
            text = f.read().rstrip() + "\n"
        lines = [
            "", "## Składniki wydania %s" % self.version, "",
            "- legatto-node %s@%s" % (self.repo, self.commit),
            "- legatto-app %s (%s@%s)" % (app["version"], app["repo"], app["commit"]),
            "- migracje bazy: %d nowych, poziom %s" % (len(migrations["files"]), migrations["to"]),
        ]
        lines += ["- obraz %s: %s@%s" % (i["name"], repository_of(i["ref"]), i["digest"]) for i in self.images]
        lines += self.components
        rc.write_bytes(os.path.join(self.out, "notes.md"), (text + "\n".join(lines) + "\n").encode("utf-8"))
        self.add_artifact("notes.md", "notes")

    def run(self) -> str:
        self.load_inputs()
        if os.path.exists(self.out) and os.listdir(self.out):
            raise rc.ReleaseError("%s już istnieje — usuń katalog, aby zbudować ponownie" % self.out)
        os.makedirs(self.out, exist_ok=True)
        work_root = os.path.join(rc.OUT_ROOT, ".work")
        os.makedirs(work_root, exist_ok=True)
        self.work = tempfile.mkdtemp(prefix=self.version + "-", dir=work_root)
        self.archives = ImageArchives(os.path.join(rc.OUT_ROOT, ".cache"), self.work, self.reuse_published)
        try:
            self.src = self.export_head()
            rc.need_tool("docker")
            needed = self.required_images()
            rel = self.app_release()
            for name in needed:
                if name in APP_IMAGES:
                    img = rel["images"][name]
                    self.add_image(name, img["ref"], img["digest"], lambda path=img["path"]: path)
                elif name == EGRESS_IMAGE:
                    self.egress_image()
                else:
                    self.upstream_image(name)
            unused = [n for n in APP_IMAGES if n not in needed]
            if unused:
                raise rc.ReleaseError("compose nie używa obrazów aplikacji: %s" % ", ".join(unused))
            self.config()
            migrations = self.app_migrations(rel)
            self.binaries()
            self.debs()
            has_worker = self.worker()
            egress = self.egress()
            app = self.lock["app"]
            self.notes(app, migrations)
            healthchecks = self.spec.get("healthchecks") or (
                DEFAULT_HEALTHCHECKS + (["worker:selftest"] if has_worker else []))
            app_source = {"repo": app["repo"], "commit": app["commit"], "version": app["version"],
                          "release_sha256": app["release_sha256"]}
            if app.get("ci_run"):
                app_source["ci_run"] = app["ci_run"]
            manifest = {
                "schema": "legatto-release/1",
                "product": "legatto",
                "version": self.version,
                "sequence": int(self.spec["sequence"]),
                "type": self.spec["type"],
                "channels": self.spec.get("channels") or list(rc.contract()["legatto_channels"]),
                "released_at": self.released_at,
                "expires": self.expires,
                "min_installed": self.spec["min_installed"],
                "min_contract_version": int(self.spec["min_contract_version"]),
                "changelog_url": "%s/releases/%s/notes.md" % (rc.DEFAULT_UPDATES_URL, self.version),
                "advisories": self.spec["advisories"],
                "source": {
                    "node": {"repo": self.repo, "commit": self.commit},
                    "app": app_source,
                    "supabase_selfhosted": str(self.versions["legatto_supabase_selfhosted_version"]),
                },
                "artifacts": sorted(self.artifacts, key=lambda a: a["name"]),
                "images": sorted(self.images, key=lambda i: i["name"]),
                "migrations": migrations,
                "rollback": "images-only",
                "egress": egress,
                "sbom": sorted(self.sboms, key=lambda s: s["artifact"]),
                "healthchecks": healthchecks,
                "crons": rel.get("crons") or [],
                "functions": rel.get("functions") or [],
            }
            errors = schema.validate("manifest", manifest)
            if errors:
                raise rc.ReleaseError("manifest niezgodny ze schematem:\n  " + "\n  ".join(errors))
            rc.write_document(os.path.join(self.out, "manifest.json"), manifest)
            rc.verify_bundle_files(self.out, manifest)
        finally:
            shutil.rmtree(self.work, ignore_errors=True)
        rc.info("paczka %s: %s (%d artefaktów, %d obrazów) — NIEPODPISANA" % (
            self.version, self.out, len(self.artifacts), len(self.images)))
        return self.out


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(prog="release/build.sh", description="Assemble the unsigned release bundle.")
    p.add_argument("--version", required=True)
    p.add_argument("--out", help="output directory (default release/out/<version>)")
    p.add_argument("--app-src", help="local legatto-app checkout at the app.lock commit (default: fresh clone)")
    p.add_argument("--no-reuse-published", action="store_true",
                   help="reuse image archives only from the local cache, never download them from published releases")
    a = p.parse_args(argv)
    Build(a.version, os.path.abspath(a.out) if a.out else rc.out_dir(a.version), a.app_src,
          reuse_published=not a.no_reuse_published).run()
    return 0


if __name__ == "__main__":
    rc.run_main(main)
