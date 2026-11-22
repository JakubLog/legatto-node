"""Content checks of release artifacts and staging of a release directory.

Everything here is pure Python and changes nothing outside the staging
directory. Rule 3 of section 4.7: size and sha256 of every file, image
digests, binary/deb allowlists, config files only for known appliers and
their fixed targets.
"""

import hashlib
import json
import os
import re
import tarfile

from . import const
from .host import sha256_file
from .source import copy_file

CONFIG_PATH_RULES = {
    "compose": re.compile(r"^compose/[A-Za-z0-9._@-]+(/[A-Za-z0-9._@-]+)*$"),
    "caddy-site": re.compile(r"^caddy/sites\.d/[a-z0-9][a-z0-9-]{0,40}\.caddy(\.tmpl)?$"),
    "systemd-unit": re.compile(r"^systemd/(%s)(\.tmpl)?$" % "|".join(const.UNIT_NAME_PATTERNS)),
    "env-template": re.compile(r"^env/[a-z0-9][a-z0-9-]{0,40}\.env\.tmpl$"),
    "egress": re.compile(r"^egress/[a-z0-9][a-z0-9-]{0,40}\.yml$"),
}
# Appliers whose .tmpl files the updater renders from office.env.
RENDERED_APPLIERS = ("compose", "caddy-site", "systemd-unit")
PLACEHOLDER_RE = re.compile(r"\$\{([^}]*)\}")
MIGRATION_NAME_RE = re.compile(r"^[0-9]{14}_[a-z0-9_]{1,100}\.sql$")
OCI_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
                   "application/vnd.docker.distribution.manifest.list.v2+json")


class BundleError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# --- tar handling --------------------------------------------------------------------------
def _norm_member(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    parts = name.split("/")
    if not name or name.startswith("/") or "\\" in name or any(p in ("", ".", "..") for p in parts):
        raise BundleError("artifact-content", "unsafe path in archive: %r" % name)
    return name


def tar_entries(path: str, limit: int):
    """Yield (name, file object) for regular files; refuse links, devices, traversal, oversize."""
    total = 0
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise BundleError("artifact-content", "%s: not a tar archive (%s)" % (os.path.basename(path), exc)) from exc
    with tf:
        seen = set()
        for member in tf:
            name = _norm_member(member.name)
            if member.isdir():
                continue
            if not member.isreg():
                raise BundleError("artifact-content", "%s: %s is not a regular file" % (os.path.basename(path), name))
            if name in seen:
                raise BundleError("artifact-content", "%s: duplicate member %s" % (os.path.basename(path), name))
            seen.add(name)
            total += member.size
            if total > limit:
                raise BundleError("artifact-content", "%s: unpacked size above limit" % os.path.basename(path))
            yield name, tf.extractfile(member)


def _hash_fileobj(fh) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def tar_hashes(path: str, limit: int) -> dict:
    return {name: _hash_fileobj(fh) for name, fh in tar_entries(path, limit)}


def tar_contents(path: str, limit: int) -> dict:
    return {name: fh.read() for name, fh in tar_entries(path, limit)}


# --- placeholder rules --------------------------------------------------------------------
def office_placeholders_ok(text: str) -> list:
    """Names of ${...} placeholders outside section 4.1 (empty list = OK)."""
    bad = []
    for name in PLACEHOLDER_RE.findall(text):
        if name not in const.OFFICE_ENV_KEYS and name not in bad:
            bad.append(name)
    return bad


def render_office(text: str, office_env: dict) -> str:
    def repl(match):
        name = match.group(1)
        if name not in const.OFFICE_ENV_KEYS or name not in office_env:
            raise BundleError("artifact-content", "placeholder ${%s} not available" % name)
        return office_env[name]
    return PLACEHOLDER_RE.sub(repl, text)


# --- manifest-level checks ------------------------------------------------------------------
def manifest_rules(manifest: dict) -> list:
    """Static rules that the schema cannot express."""
    errors = []
    arts = manifest["artifacts"]
    names = [a["name"] for a in arts]
    if len(set(names)) != len(names):
        errors.append("duplicate artifact names")
    by_name = {a["name"]: a for a in arts}
    kinds = [a["kind"] for a in arts]
    for kind in ("config", "sql-migrations", "edge-functions", "worker-bundle"):
        if kinds.count(kind) > 1:
            errors.append("more than one %s artifact" % kind)
    bins, debs = [], []
    for a in arts:
        if a["kind"] not in const.ARTIFACT_KINDS:
            errors.append("%s: unknown kind" % a["name"])
        if a["kind"] == "binary":
            if len(a["binaries"]) != 1 or a["binaries"][0]["sha256"] != a["sha256"]:
                errors.append("%s: binary artifact must describe exactly its own file" % a["name"])
            for b in a["binaries"]:
                if b["name"] not in const.BINARY_ALLOWLIST:
                    errors.append("%s: binary %s not allowed" % (a["name"], b["name"]))
                bins.append(b["name"])
        if a["kind"] == "deb":
            if len(a["packages"]) != 1 or a["packages"][0]["sha256"] != a["sha256"]:
                errors.append("%s: deb artifact must describe exactly its own file" % a["name"])
            for p in a["packages"]:
                if p["name"] not in const.DEB_ALLOWLIST:
                    errors.append("%s: package %s not allowed" % (a["name"], p["name"]))
                debs.append(p["name"])
        if a["kind"] == "config":
            paths = [f["path"] for f in a["files"]]
            if len(set(paths)) != len(paths):
                errors.append("%s: duplicate file paths" % a["name"])
            for f in a["files"]:
                rule = CONFIG_PATH_RULES.get(f["applier"])
                if rule is None or not rule.match(f["path"]):
                    errors.append("%s: %s not allowed for applier %s" % (a["name"], f["path"], f["applier"]))
    if len(set(bins)) != len(bins):
        errors.append("binary shipped twice")
    if len(set(debs)) != len(debs):
        errors.append("package shipped twice")
    referenced = set()
    for img in manifest["images"]:
        if img["artifact"] is not None:
            target = by_name.get(img["artifact"])
            if target is None or target["kind"] != "oci-archive":
                errors.append("image %s: artifact %s is not an oci-archive" % (img["name"], img["artifact"]))
            referenced.add(img["artifact"])
    for a in arts:
        if a["kind"] == "oci-archive" and a["name"] not in referenced:
            errors.append("%s: oci-archive not referenced by images[]" % a["name"])
    for s in manifest["sbom"]:
        target = by_name.get(s["artifact"])
        if target is None or target["kind"] != "sbom":
            errors.append("sbom %s: not an sbom artifact" % s["artifact"])
    migration_files = manifest["migrations"]["files"]
    if migration_files and "sql-migrations" not in kinds:
        errors.append("migrations listed but no sql-migrations artifact")
    mig_names = [f["name"] for f in migration_files]
    if mig_names != sorted(mig_names) or len(set(mig_names)) != len(mig_names):
        errors.append("migration names not strictly increasing")
    if migration_files and manifest["migrations"]["to"] != mig_names[-1][:14]:
        errors.append("migrations.to does not match the last migration")
    if not manifest["migrations"]["n_minus_1_compatible"]:
        errors.append("n_minus_1_compatible is false")
    if manifest["rollback"] != "images-only":
        errors.append("rollback must be images-only")
    if "canary" not in manifest["channels"]:
        errors.append("channels must contain canary")
    return errors


# --- artifact content checks ------------------------------------------------------------------
def check_artifact_files(manifest: dict, art_dir: str) -> dict:
    """Size, sha256 and content of every artifact. Raises BundleError; returns extra info."""
    info = {"notes_md": None}
    for a in manifest["artifacts"]:
        path = os.path.join(art_dir, a["name"])
        if not os.path.isfile(path):
            raise BundleError("artifact-missing", a["name"])
        if os.path.getsize(path) != a["size"]:
            raise BundleError("artifact-hash", "%s: size differs from manifest" % a["name"])
        if sha256_file(path) != a["sha256"]:
            raise BundleError("artifact-hash", "%s: sha256 differs from manifest" % a["name"])
        kind = a["kind"]
        if kind == "config":
            _check_config(a, path)
        elif kind == "sql-migrations":
            _check_migrations(manifest, a, path)
        elif kind == "edge-functions":
            _check_functions(manifest, a, path)
        elif kind == "worker-bundle":
            hashes = tar_hashes(path, const.MAX_FUNCTIONS_BYTES)
            if a["worker"]["entry_sha256"] not in hashes.values():
                raise BundleError("artifact-content", "%s: no file with worker.entry_sha256" % a["name"])
        elif kind == "oci-archive":
            wanted = [i["digest"] for i in manifest["images"] if i["artifact"] == a["name"]]
            check_oci_archive(path, wanted)
        elif kind == "sbom":
            try:
                with open(path, "rb") as fh:
                    json.loads(fh.read().decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise BundleError("artifact-content", "%s: SBOM is not JSON" % a["name"]) from exc
        elif kind == "notes":
            with open(path, "rb") as fh:
                data = fh.read(const.MAX_NOTES_BYTES)
            info["notes_md"] = data.decode("utf-8", "replace")
    return info


def _check_config(a: dict, path: str) -> None:
    contents = tar_contents(path, const.MAX_CONFIG_BYTES)
    listed = {f["path"]: f for f in a["files"]}
    extra = sorted(set(contents) - set(listed))
    missing = sorted(set(listed) - set(contents))
    if extra or missing:
        raise BundleError("artifact-content", "%s: files differ from manifest (extra %s, missing %s)"
                          % (a["name"], extra[:5], missing[:5]))
    for rel, entry in listed.items():
        data = contents[rel]
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise BundleError("artifact-hash", "%s: %s sha256 differs" % (a["name"], rel))
        if rel.endswith(".tmpl") and entry["applier"] in RENDERED_APPLIERS:
            bad = office_placeholders_ok(data.decode("utf-8", "replace"))
            if bad:
                raise BundleError("artifact-content", "%s: unknown placeholders %s" % (rel, bad[:5]))


def _check_migrations(manifest: dict, a: dict, path: str) -> None:
    hashes = tar_hashes(path, const.MAX_CONFIG_BYTES)
    listed = {f["name"]: f["sha256"] for f in manifest["migrations"]["files"]}
    for name in hashes:
        if "/" in name or not MIGRATION_NAME_RE.match(name):
            raise BundleError("artifact-content", "%s: bad migration file %s" % (a["name"], name))
    if set(hashes) != set(listed):
        raise BundleError("artifact-content", "%s: files differ from migrations.files" % a["name"])
    for name, digest in hashes.items():
        if listed[name] != digest:
            raise BundleError("artifact-hash", "%s: %s sha256 differs" % (a["name"], name))


def _check_functions(manifest: dict, a: dict, path: str) -> None:
    names = set(tar_hashes(path, const.MAX_FUNCTIONS_BYTES))
    for fn in manifest.get("functions", []):
        if "%s/index.ts" % fn not in names:
            raise BundleError("artifact-content", "%s: function %s has no index.ts" % (a["name"], fn))


def check_oci_archive(path: str, digests: list) -> None:
    """Every wanted manifest digest is reachable from index.json and its blob hashes to it."""
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise BundleError("artifact-content", "%s: not a tar archive" % os.path.basename(path)) from exc
    with tf:
        members = {}
        for m in tf.getmembers():
            name = _norm_member(m.name)
            if m.isreg():
                members[name] = m
            elif not m.isdir():
                raise BundleError("artifact-content", "%s: %s is not a regular file" % (os.path.basename(path), name))

        def blob(digest: str) -> bytes:
            algo, _, hexd = digest.partition(":")
            member = members.get("blobs/%s/%s" % (algo, hexd))
            if algo != "sha256" or member is None:
                raise BundleError("image-digest", "%s: blob %s missing" % (os.path.basename(path), digest))
            data = tf.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != hexd:
                raise BundleError("image-digest", "%s: blob %s content mismatch" % (os.path.basename(path), digest))
            return data

        if "index.json" not in members:
            raise BundleError("image-digest", "%s: no OCI index.json" % os.path.basename(path))
        try:
            index = json.loads(tf.extractfile(members["index.json"]).read().decode("utf-8"))
        except ValueError as exc:
            raise BundleError("image-digest", "%s: bad index.json" % os.path.basename(path)) from exc
        found = set()
        queue = list(index.get("manifests", []))
        depth = 0
        while queue and depth < 64:
            depth += 1
            desc = queue.pop(0)
            digest = desc.get("digest", "")
            if desc.get("mediaType") in OCI_INDEX_TYPES:
                try:
                    queue.extend(json.loads(blob(digest).decode("utf-8")).get("manifests", []))
                except ValueError as exc:
                    raise BundleError("image-digest", "bad nested index %s" % digest) from exc
            else:
                found.add(digest)
        for digest in digests:
            if digest not in found:
                raise BundleError("image-digest", "%s: image %s not in archive" % (os.path.basename(path), digest))
            blob(digest)


# --- staging -----------------------------------------------------------------------------------
def stage_release(host, manifest: dict, manifest_bytes: bytes, sigs: dict, art_dir: str, stage: str,
                  office_env: dict) -> None:
    """Build releases/.staging-<v>: manifest, signatures, artifacts (not images), config, migrations."""
    os.makedirs(stage, mode=0o755)
    host.write_bytes(os.path.join(stage, "manifest.json"), manifest_bytes, mode=0o644)
    for signer_id, data in sigs.items():
        host.write_bytes(os.path.join(stage, "manifest.json.%s.sig" % signer_id), data, mode=0o644)
    for a in manifest["artifacts"]:
        src = os.path.join(art_dir, a["name"])
        if a["kind"] != "oci-archive":
            copy_file(src, os.path.join(stage, "artifacts", a["name"]))
        if a["kind"] == "config":
            appliers = {f["path"]: f["applier"] for f in a["files"]}
            for rel, data in tar_contents(src, const.MAX_CONFIG_BYTES).items():
                applier = appliers[rel]
                out_rel, mode = rel, 0o644
                if rel.endswith(".tmpl") and applier in RENDERED_APPLIERS:
                    data = render_office(data.decode("utf-8"), office_env).encode("utf-8")
                    out_rel = rel[:-len(".tmpl")]
                if applier == "compose" and rel.endswith(".sh"):
                    mode = 0o755
                if applier == "env-template":
                    mode = 0o600
                host.write_bytes(os.path.join(stage, *out_rel.split("/")), data, mode=mode)
        elif a["kind"] == "sql-migrations":
            for rel, data in tar_contents(src, const.MAX_CONFIG_BYTES).items():
                host.write_bytes(os.path.join(stage, "migrations", rel), data, mode=0o644)
