"""Typed appliers (section 4.8): validators, switch, restore, health checks.

Order of the switch: const.APPLIERS. Every validator runs before the first
change; restore() brings back images, config and binaries of a kept
release (the database is never touched).
"""

import json
import os
import re
import shutil
import tempfile

from . import check, const
from .host import CommandError, read_bytes, rmtree, sha256_file, symlink_atomic

VERSION_ARGS = {"caddy": ["version"], "lego": ["--version"], "smokescreen": ["--version"]}
HEALTH_RE = re.compile(r"^(compose:all-healthy|http:(crm|admin|internal):(/.*)|sql:migration-level|"
                       r"egress:selftest|worker:selftest)$")


class ApplyError(Exception):
    def __init__(self, applier: str, detail: str):
        super().__init__("%s: %s" % (applier, detail))
        self.applier = applier
        self.detail = detail


def _repo(ref: str) -> str:
    return ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref


class Appliers:
    def __init__(self, host, store, policy, office_env, actor):
        self.host = host
        self.store = store
        self.policy = policy
        self.office_env = office_env
        self.actor = actor

    def actor_json(self) -> str:
        return json.dumps(self.actor, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def run(self, applier: str, argv, **kw):
        try:
            return self.host.run(argv, **kw)
        except CommandError as exc:
            raise ApplyError(applier, str(exc)) from exc

    # --- paths -------------------------------------------------------------------------
    def releases(self) -> str:
        return self.host.p(const.RELEASES)

    def release_dir(self, version: str) -> str:
        return os.path.join(self.releases(), version)

    def bin_dir(self, version: str) -> str:
        return os.path.join(self.host.p(const.BIN), version)

    def compose_argv(self, release: str) -> list:
        compose = os.path.join(release, "compose")
        argv = ["docker", "compose", "-p", const.COMPOSE_PROJECT, "--project-directory",
                os.path.join(compose, const.COMPOSE_PROJECT_SUBDIR)]
        for f in const.COMPOSE_FILES:
            argv += ["-f", os.path.join(compose, f)]
        return argv

    # --- validators (no change to the system) ---------------------------------------
    def validate(self, manifest: dict, stage: str, bin_stage: str, bootstrap: bool) -> None:
        kinds = {a["kind"] for a in manifest["artifacts"]}
        self._validate_migrations(manifest, stage)
        self._validate_debs(manifest, stage)
        self._prepare_binaries(manifest, stage, bin_stage)
        if os.path.isdir(os.path.join(stage, "env")):
            rc, _out, err = self.run("env-template", [const.CLI_SECRETS, "render", "--check", "--templates",
                                                      os.path.join(stage, "env")], check=False)
            if rc != 0:
                raise ApplyError("env-template", "legatto-secrets render --check exit %s: %s" % (rc, err.strip()[-300:]))
        self._validate_egress(stage, bootstrap)
        self._validate_units(stage)
        self._validate_caddy(stage, bin_stage)
        if manifest.get("functions") and not any(i["name"] == "functions" for i in manifest["images"]):
            raise ApplyError("functions", "functions listed but no functions image")
        if "edge-functions" in kinds and not manifest.get("functions"):
            raise ApplyError("functions", "edge-functions artifact without functions[]")
        self._validate_compose(manifest, stage)

    def _validate_migrations(self, manifest: dict, stage: str) -> None:
        applied = self.store.migrations["applied"]
        files = manifest["migrations"]["files"]
        latest = max(applied) if applied else None
        for f in files:
            if f["name"] in applied:
                if applied[f["name"]] != f["sha256"]:
                    raise ApplyError("sql-migrations", "%s was applied with a different sha256" % f["name"])
            elif latest is not None and f["name"] < latest:
                raise ApplyError("sql-migrations", "%s sorts before applied %s" % (f["name"], latest))
        if files:
            rc, _out, err = self.run("sql-migrations", [
                const.CLI_STACK, "migrate", "--compose-dir", os.path.join(stage, "compose"),
                "--templates", os.path.join(stage, "env"), "--check"], check=False, timeout=900)
            if rc != 0:
                raise ApplyError("sql-migrations", "migrator check exit %s: %s" % (rc, err.strip()[-300:]))

    def _validate_debs(self, manifest: dict, stage: str) -> None:
        for a in manifest["artifacts"]:
            if a["kind"] != "deb":
                continue
            pkg = a["packages"][0]
            path = os.path.join(stage, "artifacts", a["name"])
            _rc, out, _err = self.run("deb", ["dpkg-deb", "-f", path, "Package", "Version"], timeout=60)
            fields = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
            if fields.get("Package") != pkg["name"] or pkg["name"] not in const.DEB_ALLOWLIST:
                raise ApplyError("deb", "%s: Package %r not allowed" % (a["name"], fields.get("Package")))
            if fields.get("Version") != pkg["version"]:
                raise ApplyError("deb", "%s: Version %r != manifest %s" % (a["name"], fields.get("Version"), pkg["version"]))

    def _prepare_binaries(self, manifest: dict, stage: str, bin_stage: str) -> None:
        """bin/.staging-<v>: complete set (previous binaries + new ones), each version-checked."""
        rmtree(bin_stage)
        os.makedirs(bin_stage, mode=0o755)
        current = self.host.p(const.BIN_CURRENT)
        if os.path.isdir(current):
            for name in os.listdir(current):
                if name in const.BINARY_ALLOWLIST:
                    shutil.copy2(os.path.join(current, name), os.path.join(bin_stage, name))
        for a in manifest["artifacts"]:
            if a["kind"] != "binary":
                continue
            b = a["binaries"][0]
            dest = os.path.join(bin_stage, b["name"])
            shutil.copyfile(os.path.join(stage, "artifacts", a["name"]), dest)
            os.chmod(dest, 0o755)
            if sha256_file(dest) != b["sha256"]:
                raise ApplyError("binary", "%s: sha256 differs" % b["name"])
            rc, out, err = self.run("binary", [dest] + VERSION_ARGS[b["name"]], check=False, timeout=30)
            if rc != 0 or b["version"] not in (out + err):
                raise ApplyError("binary", "%s: version check failed (want %s)" % (b["name"], b["version"]))

    def _validate_egress(self, stage: str, bootstrap: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="legatto-egress-") as out:
            self.run("egress", [const.CLI_EGRESS, "render", "--release-dir", stage, "--out", out],
                     timeout=120)
            self.run("egress", [const.CLI_EGRESS, "check", "--dir", out], timeout=120)
        if bootstrap:
            return
        current = self.host.p(const.CURRENT)
        src = (current) if os.path.isfile(os.path.join(current, "manifest.json")) else "none"
        rc, _out, _err = self.run("egress", [const.CLI_EGRESS, "diff", "--from", src, "--to", stage,
                                             "--json"], check=False, timeout=120)
        if rc in (const.EGRESS_PINNED_REMOVED, const.EGRESS_INVALID) or rc not in (0, const.EGRESS_WIDENING):
            raise ApplyError("egress", "legatto-egress diff exit %s" % rc)

    def _validate_units(self, stage: str) -> None:
        units = os.path.join(stage, "systemd")
        if not os.path.isdir(units):
            return
        errors = []
        with tempfile.TemporaryDirectory(prefix="legatto-units-") as tmp:
            paths = []
            for name in sorted(os.listdir(units)):
                with open(os.path.join(units, name), encoding="utf-8") as fh:
                    text = fh.read()
                errors += check.check_unit(name, text)
                target = os.path.join(tmp, name.replace("@.", "@verify."))
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(text)
                if name.endswith(".timer"):
                    instance = re.sub(r"^legatto-cron-(.+)\.timer$", r"legatto-cron@\1.service", name)
                    tpl = os.path.join(units, "legatto-cron@.service")
                    if os.path.isfile(tpl) and not os.path.exists(os.path.join(tmp, instance)):
                        shutil.copyfile(tpl, os.path.join(tmp, instance))
                paths.append(target)
            if errors:
                raise ApplyError("systemd-unit", "; ".join(errors[:5]))
            rc, out, err = self.run("systemd-unit", ["systemd-analyze", "verify", "--man=no"] + paths,
                                    check=False, timeout=120, env={"SYSTEMD_UNIT_PATH": tmp + ":"})
            if rc != 0:
                raise ApplyError("systemd-unit", "systemd-analyze verify: %s" % (err or out).strip()[-300:])

    def _validate_caddy(self, stage: str, bin_stage: str) -> None:
        sites = os.path.join(stage, "caddy", "sites.d")
        if not os.path.isdir(sites):
            return
        errors = []
        for name in sorted(os.listdir(sites)):
            if not name.endswith(".caddy"):
                errors.append("%s: not a .caddy file" % name)
                continue
            with open(os.path.join(sites, name), encoding="utf-8") as fh:
                errors += check.check_caddy_site(name, fh.read())
        if errors:
            raise ApplyError("caddy-site", "; ".join(errors[:5]))
        caddy = os.path.join(bin_stage, "caddy")
        if not os.path.isfile(caddy):
            caddy = os.path.join(self.host.p(const.BIN_CURRENT), "caddy")
        rc, out, err = self.run("caddy-site", [caddy, "validate", "--config", self.host.p(const.CADDYFILE),
                                               "--adapter", "caddyfile"],
                                check=False, timeout=120, env={"LEGATTO_CADDY_SITES": sites})
        if rc != 0:
            raise ApplyError("caddy-site", "caddy validate: %s" % (err or out).strip()[-300:])

    def _validate_compose(self, manifest: dict, stage: str) -> None:
        compose = os.path.join(stage, "compose")
        if not os.path.isdir(compose):
            raise ApplyError("compose", "release has no compose tree")
        rc, out, err = self.run("compose", [const.CLI_STACK, "check", "--compose-dir", compose,
                                            "--templates", os.path.join(stage, "env")],
                                check=False, timeout=300)
        if rc != 0:
            raise ApplyError("compose", "legatto-stack check exit %s: %s" % (rc, (err or out).strip()[-300:]))
        _rc, out, _err = self.run("compose", check.compose_config_argv(compose), timeout=120)
        try:
            cfg = json.loads(out)
        except ValueError as exc:
            raise ApplyError("compose", "docker compose config: output is not JSON") from exc
        errors = check.check_compose_config(cfg, manifest, self.office_env, compose, self.host.p)
        if errors:
            raise ApplyError("compose", "; ".join(errors[:5]))

    # --- images -------------------------------------------------------------------------
    def image_present(self, img: dict) -> bool:
        """repo@digest is in the local store. The digest is content-addressed and pinned by
        the signed manifest, so a present image is exactly the one the release names."""
        ref = "%s@%s" % (_repo(img["ref"]), img["digest"])
        try:
            rc, _out, _err = self.host.run(["docker", "image", "inspect", "--format", "{{.Id}}", ref],
                                           check=False, timeout=60)
        except CommandError:
            return False
        return rc == 0

    def archives_to_load(self, manifest: dict) -> list:
        """oci-archive artifacts with at least one image not yet in the local store."""
        return [a["name"] for a in manifest["artifacts"] if a["kind"] == "oci-archive"
                and not all(self.image_present(i) for i in manifest["images"] if i["artifact"] == a["name"])]

    def load_images(self, manifest: dict, art_dir: str, names: list) -> None:
        for name in names:
            self.run("compose", ["docker", "load", "-q", "-i", os.path.join(art_dir, name)], timeout=1800)
        self.assert_images(manifest)

    def assert_images(self, manifest: dict) -> None:
        for img in manifest["images"]:
            if not self.image_present(img):
                raise ApplyError("compose", "image %s@%s not present after load" % (_repo(img["ref"]), img["digest"]))

    # --- switch ----------------------------------------------------------------------------
    def maintenance(self) -> None:
        if os.path.isfile(os.path.join(self.host.p(const.CURRENT), "manifest.json")):
            self.run("compose", [const.CLI_STACK, "stop", "app", "functions"], timeout=300)

    def migrate(self, manifest: dict, release: str) -> None:
        files = manifest["migrations"]["files"]
        if not files:
            return
        self.run("sql-migrations", [const.CLI_STACK, "migrate", "--compose-dir",
                                    os.path.join(release, "compose"),
                                    "--templates", os.path.join(release, "env")], timeout=1800)
        for f in files:
            self.store.migrations["applied"][f["name"]] = f["sha256"]
        self.store.save()

    def install_debs(self, manifest: dict, release: str) -> None:
        for a in manifest["artifacts"]:
            if a["kind"] != "deb":
                continue
            pkg = a["packages"][0]
            rc, out, _err = self.run("deb", ["dpkg-query", "-W", "-f=${Version}", pkg["name"]], check=False)
            if rc == 0 and out.strip() == pkg["version"]:
                continue
            self.run("deb", ["apt-get", "install", "-y", "--no-install-recommends",
                             "./" + a["name"]], cwd=os.path.join(release, "artifacts"), timeout=1800,
                     env={"DEBIAN_FRONTEND": "noninteractive"})

    def switch_binaries(self, bin_stage: str, version: str) -> str:
        target = self.bin_dir(version)
        rmtree(target)
        os.replace(bin_stage, target)
        symlink_atomic(version, self.host.p(const.BIN_CURRENT))
        return version

    def render_env(self, release: str) -> None:
        env = os.path.join(release, "env")
        if os.path.isdir(env):
            self.run("env-template", [const.CLI_SECRETS, "render", "--templates", env], timeout=300)

    def apply_egress(self, release: str) -> None:
        self.run("egress", [const.CLI_EGRESS, "apply", "--release-dir", release,
                            "--actor", self.actor_json()], timeout=600)

    def sync_units(self, release: str) -> None:
        src = os.path.join(release, "systemd")
        dest = self.host.p(const.SYSTEMD_DIR)
        new = sorted(os.listdir(src)) if os.path.isdir(src) else []
        managed = [n for n in (os.listdir(dest) if os.path.isdir(dest) else [])
                   if any(re.fullmatch(p, n) for p in const.UNIT_NAME_PATTERNS)]
        for name in managed:
            if name not in new:
                if name.endswith((".timer", ".path")):
                    self.run("systemd-unit", ["systemctl", "disable", "--now", name], check=False)
                os.unlink(os.path.join(dest, name))
        for name in new:
            data = read_bytes(os.path.join(src, name))
            if read_bytes(os.path.join(dest, name)) != data:
                self.host.write_bytes(os.path.join(dest, name), data, mode=0o644)
        self.run("systemd-unit", ["systemctl", "daemon-reload"], timeout=120)
        for name in new:
            if name.endswith((".timer", ".path")):
                self.run("systemd-unit", ["systemctl", "enable", "--now", name], timeout=120)
            elif name == const.UNIT_STACK:
                self.run("systemd-unit", ["systemctl", "enable", name], timeout=120)

    def sync_caddy(self, release: str) -> None:
        src = os.path.join(release, "caddy", "sites.d")
        if not os.path.isdir(src):
            return
        dest = self.host.p(const.CADDY_SITES)
        os.makedirs(dest, exist_ok=True)
        new = sorted(n for n in os.listdir(src) if n.endswith(".caddy"))
        for name in new:
            data = read_bytes(os.path.join(src, name))
            if read_bytes(os.path.join(dest, name)) != data:
                self.host.write_bytes(os.path.join(dest, name), data, mode=0o644)
        for name in os.listdir(dest):
            if name.endswith(".caddy") and name not in new:
                os.unlink(os.path.join(dest, name))
        self.run("caddy-site", ["systemctl", "reload-or-restart", const.UNIT_CADDY], timeout=120)

    def switch_compose(self, version: str) -> None:
        symlink_atomic(self.release_dir(version), self.host.p(const.CURRENT))
        self.run("compose", ["systemctl", "reload-or-restart", const.UNIT_STACK], timeout=900)

    def worker(self, release: str):
        return self.host.run([const.CLI_WORKER_DEPLOY, "--release-dir", release,
                              "--actor", self.actor_json()], check=False, timeout=900)

    def switch(self, manifest: dict, version: str, bin_stage: str, steps: list) -> None:
        """Apply in const.APPLIERS order. `steps` records what changed (for logs)."""
        release = self.release_dir(version)
        for applier in const.APPLIERS:
            if applier == "sql-migrations":
                self.migrate(manifest, release)
            elif applier == "deb":
                self.install_debs(manifest, release)
            elif applier == "binary":
                self.switch_binaries(bin_stage, version)
            elif applier == "env-template":
                self.render_env(release)
            elif applier == "egress":
                self.apply_egress(release)
            elif applier == "systemd-unit":
                self.sync_units(release)
            elif applier == "caddy-site":
                self.sync_caddy(release)
            elif applier == "functions":
                pass  # the functions image is switched with compose (no mounts, no files)
            elif applier == "compose":
                self.switch_compose(version)
            elif applier == "worker":
                continue  # runs after a green health check
            steps.append(applier)

    def restore(self, version: str, bin_version: str) -> None:
        """Back to a kept release: binaries, env, egress, units, sites, compose. DB untouched."""
        release = self.release_dir(version)
        if not os.path.isfile(os.path.join(release, "manifest.json")):
            raise ApplyError("compose", "release %s is not kept on disk" % version)
        if bin_version and os.path.isdir(self.bin_dir(bin_version)):
            symlink_atomic(bin_version, self.host.p(const.BIN_CURRENT))
        self.render_env(release)
        self.apply_egress(release)
        self.sync_units(release)
        self.sync_caddy(release)
        self.switch_compose(version)

    # --- health -----------------------------------------------------------------------------
    def health(self, manifest: dict) -> list:
        """Poll the manifest's health checks until all pass or the policy timeout ends.
        Returns the list of failing checks (empty = healthy)."""
        checks = [c for c in manifest["healthchecks"] if c != "worker:selftest"]
        attempts = max(1, self.policy["health_timeout_seconds"] // const.HEALTH_POLL_SECONDS)
        failing = list(checks)
        for attempt in range(attempts):
            failing = [c for c in failing if not self._probe(c, manifest)]
            if not failing:
                return []
            if attempt + 1 < attempts:
                self.host.sleep(const.HEALTH_POLL_SECONDS)
        return failing

    def _probe(self, name: str, manifest: dict) -> bool:
        m = HEALTH_RE.match(name)
        if not m:
            return False
        try:
            if name == "compose:all-healthy":
                rc, out, _err = self.host.run([const.CLI_STACK, "status", "--json"], check=False, timeout=60)
                return rc == 0 and bool(json.loads(out).get("ok"))
            if name.startswith("http:"):
                surface, path = m.group(2), m.group(3)
                argv = [const.CLI_STACK, "probe"] + (["--internal"] if surface == "internal"
                                                      else ["--surface", surface]) + [path]
                rc, _out, _err = self.host.run(argv, check=False, timeout=60)
                return rc == 0
            if name == "sql:migration-level":
                rc, out, _err = self.host.run(
                    ["docker", "exec", const.DB_CONTAINER, "psql", "-U", "postgres", "-Atc",
                     "select coalesce(max(version),'') from supabase_migrations.schema_migrations"],
                    check=False, timeout=60)
                return rc == 0 and out.strip() >= manifest["migrations"]["to"]
            if name == "egress:selftest":
                rc, _out, _err = self.host.run([const.CLI_EGRESS, "selftest", "--json"], check=False, timeout=300)
                return rc == 0
        except (CommandError, ValueError):
            return False
        return False
