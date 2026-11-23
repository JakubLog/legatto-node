"""Local release mirror for the updater tests: programmatic ed25519 keys,
bundles, manifests, promotions, canary attestations, index and KRL, laid out
exactly like legatto_release_layout. Runs on Python >= 3.9."""

import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time

SSH_KEYGEN = os.environ.get("LEGATTO_SSH_KEYGEN_TEST", "ssh-keygen")
EPOCH = 1700000000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))


def tar_bytes(files: dict, gz=True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = EPOCH
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if not gz:
        return raw
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=EPOCH) as gzf:
        gzf.write(raw)
    return out.getvalue()


def oci_image(ref: str, salt: str):
    """Minimal OCI layout tar (docker save of one image). Returns (bytes, manifest digest)."""
    layer = tar_bytes({"hello.txt": ("layer %s\n" % salt).encode()}, gz=False)
    config = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers",
                         "diff_ids": ["sha256:" + sha(layer)]}, "config": {}}).encode()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                      "digest": "sha256:" + sha(config), "size": len(config)},
                           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                                       "digest": "sha256:" + sha(layer), "size": len(layer)}]}).encode()
    digest = "sha256:" + sha(manifest)
    index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                       "digest": digest, "size": len(manifest),
                                       "annotations": {"io.containerd.image.name": ref},
                                       "platform": {"architecture": "amd64", "os": "linux"}}]}).encode()
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": index,
             "blobs/sha256/" + sha(layer): layer, "blobs/sha256/" + sha(config): config,
             "blobs/sha256/" + sha(manifest): manifest}
    return tar_bytes(files, gz=False), digest


def build_deb(workdir: str, package: str, version: str) -> bytes:
    """A real .deb built with dpkg-deb (Linux test stage only)."""
    root = os.path.join(workdir, ".deb-%s-%s" % (package, version))
    os.makedirs(os.path.join(root, "DEBIAN"), exist_ok=True)
    with open(os.path.join(root, "DEBIAN", "control"), "w") as fh:
        fh.write("Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: test <t@example.test>\n"
                 "Description: legatto updater test package\n" % (package, version))
    out = root + ".deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", root, out], check=True, capture_output=True)
    with open(out, "rb") as fh:
        data = fh.read()
    shutil.rmtree(root)
    os.unlink(out)
    return data


class Keys:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self.paths = {}

    def get(self, name: str) -> str:
        if name not in self.paths:
            path = os.path.join(self.dir, name)
            subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path], check=True)
            self.paths[name] = path
        return self.paths[name]

    def pub(self, name: str) -> str:
        with open(self.get(name) + ".pub") as fh:
            return " ".join(fh.read().split()[:2])

    def sign(self, key: str, namespace: str, data: bytes) -> bytes:
        tmp = os.path.join(self.dir, "tosign-%d" % os.getpid())
        with open(tmp, "wb") as fh:
            fh.write(data)
        if os.path.exists(tmp + ".sig"):
            os.unlink(tmp + ".sig")
        subprocess.run([SSH_KEYGEN, "-Y", "sign", "-q", "-f", self.get(key), "-n", namespace, tmp], check=True)
        with open(tmp + ".sig", "rb") as fh:
            sig = fh.read()
        os.unlink(tmp)
        os.unlink(tmp + ".sig")
        return sig

    def krl(self, path: str, revoke=()):
        args = [SSH_KEYGEN, "-k", "-f", path] + [self.get(k) + ".pub" for k in revoke]
        subprocess.run(args, check=True, capture_output=True)


RELEASE_NS = '"legatto-release,legatto-promote,legatto-index,legatto-revoke"'


def allowed_signers(keys: Keys, release_a="release-a", release_b="release-b", canary="canary") -> str:
    lines = ["release-a@legatto.pl namespaces=%s %s" % (RELEASE_NS, keys.pub(release_a)),
             "release-b@legatto.pl namespaces=%s %s" % (RELEASE_NS, keys.pub(release_b)),
             'canary@legatto.pl namespaces="legatto-canary" %s' % keys.pub(canary)]
    return "\n".join(lines) + "\n"


DEFAULT_EGRESS = {"version": 1,
                  "roles": {"host": [{"host": "updates.legatto.pl", "port": 443, "purpose": "updates"}],
                            "app": [{"host": "api.resend.com", "port": 443, "purpose": "mail"}]},
                  "features": {"ai": {"app": [{"host": "api.anthropic.com", "port": 443, "purpose": "ai"}]}}}

UNIT_STACK = """[Unit]
Description=Legatto stack
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/legatto/sbin/legatto-stack up
ExecReload=/opt/legatto/sbin/legatto-stack up
[Install]
WantedBy=multi-user.target
"""
UNIT_CRON = """[Unit]
Description=Legatto cron %i
[Service]
Type=oneshot
DynamicUser=yes
ExecStart=/opt/legatto/sbin/legatto-stack cron %i
"""
UNIT_TIMER = """[Unit]
Description=sync-ics
[Timer]
OnCalendar=*-*-* 04:00:00
Unit=legatto-cron@sync-ics.service
[Install]
WantedBy=timers.target
"""
CADDY_SITE = """reverse_proxy 172.30.0.10:3000
header {
    Strict-Transport-Security "max-age=31536000"
}
"""


class Release:
    """One release bundle. Fields may be changed before build() to build bad releases."""

    def __init__(self, version: str, sequence: int, typ="security", migrations=("20261101000000_init.sql",),
                 prev_migration=None, with_caddy=True, with_worker=False):
        self.version = version
        self.sequence = sequence
        self.type = typ
        self.migrations = list(migrations)
        self.prev_migration = prev_migration
        self.with_caddy = with_caddy
        self.with_worker = with_worker
        self.debs = []                    # (manifest package name, control Package, version)
        self.egress = copy.deepcopy(DEFAULT_EGRESS)
        self.extra_config = {}            # path -> (bytes, applier) added to config.tar.gz
        self.unlisted_config = {}         # path -> bytes in the tar but not in files[]
        self.manifest_patch = {}          # top-level overrides
        self.image_digest_override = None
        self.tamper_after_sign = None     # name of an artifact whose bytes change after signing
        self.manifest_bytes = None
        self.manifest_sha = None
        self.app_digest = None

    def compose_config(self, db_digest: str) -> dict:
        return {
            "name": "legatto",
            "services": {
                "db": {"image": "docker.io/supabase/postgres@" + db_digest,
                       "networks": {"int": None},
                       "extra_hosts": ["${LEGATTO_HOST_CRM}=${LEGATTO_TS_IP4}"],
                       "volumes": [{"type": "bind", "source": "@COMPOSE@/supabase/volumes/db/roles.sql",
                                    "target": "/docker-entrypoint-initdb.d/roles.sql", "read_only": True},
                                   {"type": "volume", "source": "db-data", "target": "/var/lib/postgresql/data"}]},
                "app": {"image": "docker.io/legatto/app@" + self.app_digest,
                        "networks": {"int": None, "host": None},
                        "ports": [{"mode": "ingress", "host_ip": "127.0.0.1", "target": 3000,
                                   "published": "3000", "protocol": "tcp"}],
                        "secrets": [{"source": "pii", "target": "pii_field_key"}]},
            },
            "networks": {"int": {"name": "legatto-int", "internal": True}, "host": {"name": "legatto-host"}},
            "volumes": {"db-data": {"name": "legatto_db-data"}},
            "secrets": {"pii": {"name": "legatto_pii", "file": "@ROOT@/run/legatto/keys/pii_field_key"}},
        }

    def build(self, mirror, signers=("release-a",), namespace="legatto-release") -> str:
        out = os.path.join(mirror.root, "releases", self.version)
        os.makedirs(out, exist_ok=True)
        image_bytes, digest = oci_image("docker.io/legatto/app:%s" % self.version, self.version)
        self.app_digest = digest
        arts = []

        def add(name, data, kind, **extra):
            with open(os.path.join(out, name), "wb") as fh:
                fh.write(data)
            entry = {"name": name, "kind": kind, "size": len(data), "sha256": sha(data)}
            entry.update(extra)
            arts.append(entry)

        add("image-app.tar", image_bytes, "oci-archive")
        config = {
            "compose/supabase/docker-compose.yml": (b"services: {}\n", "compose"),
            "compose/docker-compose.legatto.yml": (b"services: {}\n", "compose"),
            "compose/supabase/volumes/db/roles.sql": (b"-- roles\n", "compose"),
            "compose/fake-config.json": (json.dumps(self.compose_config(mirror.db_digest)).encode(), "compose"),
            "systemd/legatto-stack.service": (UNIT_STACK.encode(), "systemd-unit"),
            "systemd/legatto-cron@.service": (UNIT_CRON.encode(), "systemd-unit"),
            "systemd/legatto-cron-sync-ics.timer": (UNIT_TIMER.encode(), "systemd-unit"),
            "env/app.env.tmpl": (b"APP_URL=https://${LEGATTO_HOST_CRM}\nKEY=${secret:jwt_secret}\n", "env-template"),
        }
        if self.with_caddy:
            config["caddy/sites.d/crm.caddy"] = (CADDY_SITE.encode(), "caddy-site")
        config.update(self.extra_config)
        files = [{"path": p, "sha256": sha(d), "applier": a} for p, (d, a) in sorted(config.items())]
        tar_files = {p: d for p, (d, _a) in config.items()}
        tar_files.update(self.unlisted_config)
        add("config.tar.gz", tar_bytes(tar_files), "config", files=files)
        mig_files = {name: ("-- %s\n" % name).encode() for name in self.migrations}
        if mig_files:
            add("migrations.tar.gz", tar_bytes(mig_files), "sql-migrations")
        caddy = ("#!/bin/sh\ncase \"$1\" in version) echo 'v2.11.9 h1:test';; validate) "
                 "test -d \"$LEGATTO_CADDY_SITES\" || exit 1; echo valid;; *) exit 2;; esac\n").encode()
        add("caddy-2.11.9", caddy, "binary", binaries=[{"name": "caddy", "version": "2.11.9", "sha256": sha(caddy)}])
        add("sbom-app.cdx.json", b'{"bomFormat":"CycloneDX","specVersion":"1.6"}', "sbom")
        add("notes.md", ("# %s\n\nZmiany testowe.\n" % self.version).encode(), "notes")
        for name, control_name, version in self.debs:
            data = build_deb(mirror.root, control_name, version)
            add("%s_%s_amd64.deb" % (name, version), data, "deb",
                packages=[{"name": name, "version": version, "sha256": sha(data)}])
        if self.with_worker:
            entry = b"export default {}\n"
            add("worker.tar.gz", tar_bytes({"worker.js": entry}), "worker-bundle",
                worker={"script_name": "legatto-intake", "entry_sha256": sha(entry)})
        manifest = {
            "schema": "legatto-release/1", "product": "legatto", "version": self.version,
            "sequence": self.sequence, "type": self.type, "channels": ["canary", "early", "stable"],
            "released_at": ts(mirror.now), "expires": ts(mirror.now + 90 * 86400),
            "min_installed": "0.0.0", "min_contract_version": 1,
            "changelog_url": "https://github.com/JakubLog/legatto-infra/releases/tag/v%s" % self.version,
            "advisories": ([{"id": "LEGATTO-2026-001", "severity": "high", "summary": "Test advisory"}]
                           if self.type == "security" else []),
            "source": {"infra": {"repo": "github.com/JakubLog/legatto-infra", "commit": "a" * 40},
                       "node": {"repo": "github.com/JakubLog/legatto-node", "commit": "d" * 40},
                       "app": {"repo": "github.com/JakubLog/legatto", "commit": "b" * 40,
                               "version": self.version, "release_sha256": "c" * 64}},
            "artifacts": arts,
            "images": [{"name": "app", "ref": "docker.io/legatto/app:%s" % self.version,
                        "digest": self.image_digest_override or digest, "platform": "linux/amd64",
                        "artifact": "image-app.tar"},
                       {"name": "db", "ref": "docker.io/supabase/postgres:17.6.1.136", "digest": mirror.db_digest,
                        "platform": "linux/amd64", "artifact": None}],
            "migrations": {"from": self.prev_migration, "to": self.migrations[-1][:14] if self.migrations
                           else (self.prev_migration or "20261101000000"),
                           "count": len(self.migrations), "n_minus_1_compatible": True,
                           "files": [{"name": n, "sha256": sha(d)} for n, d in sorted(mig_files.items())]},
            "rollback": "images-only",
            "egress": self.egress,
            "sbom": [{"artifact": "sbom-app.cdx.json", "format": "cyclonedx-json", "subject": "app"}],
            "healthchecks": ["compose:all-healthy", "http:crm:/healthz", "sql:migration-level", "egress:selftest"],
            "functions": [],
        }
        manifest.update(self.manifest_patch)
        data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        self.manifest_bytes = data
        self.manifest_sha = sha(data)
        mirror.write_doc("releases/%s/manifest.json" % self.version, data, signers, namespace)
        if self.tamper_after_sign:
            path = os.path.join(out, self.tamper_after_sign)
            with open(path, "rb") as fh:
                body = bytearray(fh.read())
            body[-2] ^= 0x01
            with open(path, "wb") as fh:
                fh.write(bytes(body))
        mirror.releases[self.version] = self
        return self.manifest_sha


class Mirror:
    def __init__(self, root: str, keys: Keys, now: float):
        self.root = root
        self.keys = keys
        self.now = now
        self.releases = {}
        self.attest = {}
        self.promos = {}
        self.yanked = set()
        self.db_digest = "sha256:" + sha(b"supabase-postgres-test")
        os.makedirs(root, exist_ok=True)

    def write_doc(self, rel: str, data: bytes, signers, namespace: str) -> None:
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        base = os.path.dirname(path)
        name = os.path.basename(path)
        for existing in os.listdir(base):
            if existing.startswith(name + ".") and existing.endswith(".sig"):
                os.unlink(os.path.join(base, existing))
        for signer in signers:
            key, _, signer_id = signer.partition(":")
            sig = self.keys.sign(key, namespace, data)
            with open("%s.%s.sig" % (path, signer_id or key), "wb") as fh:
                fh.write(sig)

    def attestation(self, version: str, result="PASS", signer="canary", namespace="legatto-canary") -> str:
        rel = self.releases[version]
        doc = {"schema": "legatto-canary/1", "product": "legatto", "version": version, "sequence": rel.sequence,
               "manifest_sha256": rel.manifest_sha, "result": result, "verify_report_sha256": "d" * 64,
               "installed_at": ts(self.now), "finished_at": ts(self.now), "canary": "canary-office"}
        if result == "FAIL":
            doc["failed_checks"] = ["health"]
        data = (json.dumps(doc, sort_keys=True) + "\n").encode()
        self.write_doc("releases/%s/attest/canary.json" % version, data, [signer], namespace)
        self.attest[version] = sha(data)
        return self.attest[version]

    def promote(self, version: str, channel: str, signers=("release-a",), promoted_at=None, **patch) -> str:
        rel = self.releases[version]
        doc = {"schema": "legatto-promote/1", "product": "legatto", "version": version, "sequence": rel.sequence,
               "type": rel.type, "channel": channel, "manifest_sha256": rel.manifest_sha,
               "canary_attestation_sha256": self.attest[version],
               "promoted_at": promoted_at or ts(self.now)}
        if channel == "stable":
            doc["early_promotion_sha256"] = self.promos[(version, "early")]
        doc.update(patch)
        data = (json.dumps(doc, sort_keys=True) + "\n").encode()
        self.write_doc("releases/%s/promote/%s.json" % (version, channel), data, signers, "legatto-promote")
        self.promos[(version, channel)] = sha(data)
        return self.promos[(version, channel)]

    def index(self, sequence: int, issued=None, expires=None, signers=("release-a",), krl_revoke=None,
              namespace="legatto-index", versions=None) -> bytes:
        issued = self.now if issued is None else issued
        expires = issued + 30 * 86400 if expires is None else expires
        krl_sha = None
        if krl_revoke is not None:
            path = os.path.join(self.root, "revoked.krl")
            self.keys.krl(path, krl_revoke)
            with open(path, "rb") as fh:
                data = fh.read()
            self.write_doc("revoked.krl", data, signers, "legatto-revoke")
            krl_sha = sha(data)
        entries = []
        for version in (versions or sorted(self.releases)):
            rel = self.releases[version]
            entry = {"version": version, "sequence": rel.sequence, "type": rel.type,
                     "manifest_sha256": rel.manifest_sha, "attestation_sha256": self.attest.get(version),
                     "promotions": {"early": self.promos.get((version, "early")),
                                    "stable": self.promos.get((version, "stable"))},
                     "yanked": version in self.yanked}
            if version in self.yanked:
                entry["yanked_reason"] = "test"
            entries.append(entry)
        doc = {"schema": "legatto-index/1", "product": "legatto", "sequence": sequence, "issued_at": ts(issued),
               "expires": ts(expires), "releases": entries, "krl_sha256": krl_sha}
        data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
        self.write_doc("index.json", data, signers, namespace)
        return data
