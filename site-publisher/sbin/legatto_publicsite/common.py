"""Shared helpers of the publicsite host tools (legatto-intake,
legatto-site-publish, legatto-worker-deploy, legatto-cf-bootstrap).

Python 3.12 standard library only. Names and paths come from
contract/contract.yml; every constant below carries a
`# contract: <key>` comment and the publicsite tests check them against it.
Each path can be redirected with LEGATTO_ROOT (tests run the tools inside a
temporary directory tree); production never sets it.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

CONTRACT_VERSION = 1  # contract: legatto_contract_version

# --- paths ----------------------------------------------------------------------
P_OFFICE_ENV = "/etc/legatto/office.env"  # contract: legatto_paths.office_env
P_STATUS = "/var/lib/legatto/status"  # contract: legatto_paths.status
P_INTAKE = "/var/lib/legatto/intake"  # contract: legatto_paths.intake
P_CURRENT = "/opt/legatto/current"  # contract: legatto_paths.current
P_CREDSTORE = "/etc/credstore.encrypted"  # contract: legatto_paths.credstore
P_PUBLICSITE_ETC = "/etc/legatto/publicsite"  # contract: legatto_paths.publicsite_etc
P_INTAKE_ETC = "/etc/legatto/intake"  # contract: legatto_paths.intake_etc
P_CF_CA_BUNDLE = "/etc/legatto/ca/cloudflare-api.pem"  # contract: legatto_paths.cf_ca_bundle
P_PUBLISH_STATE = "/var/lib/legatto/publish"  # contract: legatto_paths.publish_state
P_WORKER_STATE = "/var/lib/legatto/worker"  # contract: legatto_paths.worker_state
P_RUN = "/run/legatto"  # contract: legatto_paths.run

# --- containers and networks ----------------------------------------------------------
NET_INT = "legatto-int"  # contract: legatto_docker_networks.int.name
NET_EGRESS_INTAKE = "legatto-egress-intake"  # contract: legatto_docker_networks.egress_intake.name
NET_EGRESS_PUBLISH = "legatto-egress-publish"  # contract: legatto_docker_networks.egress_publish.name
PROXY_INTAKE = "egress-intake"  # contract: legatto_egress_container_proxies.intake.service
PROXY_PUBLISH = "egress-publish"  # contract: legatto_egress_container_proxies.publish.service
PROXY_PORT = 4750  # contract: legatto_ports.local.egress_proxy
CONTAINER_UID = 65532  # contract: legatto_container_uid
API_GW_PORT = 8000  # contract: legatto_ports.local.api_gw

# --- credentials (systemd-creds names) ------------------------------------------------
CRED_CF_DNS = "legatto-cf-dns-token"  # contract: legatto_credentials.cf_dns_token
CRED_CF_QUEUES = "legatto-cf-queues-token"  # contract: legatto_credentials.cf_queues_token
CRED_CF_PAGES = "legatto-cf-pages-token"  # contract: legatto_credentials.cf_pages_token
CRED_FORM_X25519 = "legatto-form-x25519"  # contract: legatto_credentials.form_x25519
CRED_SELFTEST = "legatto-selftest-ed25519"  # contract: legatto_credentials.selftest_ed25519
CRED_DB_INTAKE = "legatto-db-intake"  # contract: legatto_credentials.db_intake_password
CRED_DB_PUBLISHER = "legatto-db-publisher"  # contract: legatto_credentials.db_publisher_password

# --- units and CLIs ----------------------------------------------------------------
UNIT_INTAKE_PROCESS = "legatto-intake-process.service"  # contract: legatto_units.intake_process
CLI_AUDIT = "legatto-audit"  # contract: legatto_cli.audit
CONTAINER_DB = "supabase-db"  # contract: legatto_container_db

# Container images: the app image of the installed release, by digest (R6).
APP_IMAGE_NAME = "app"
ENV_KEYS_REQUIRED = ("LEGATTO_SLUG", "LEGATTO_OFFICE_DOMAIN", "LEGATTO_HOST_SITE", "LEGATTO_HOST_VPN",
                     "LEGATTO_HOST_CRM", "LEGATTO_HOST_ADMIN", "LEGATTO_HOST_STUDIO", "LEGATTO_TS_IP4",
                     "LEGATTO_TS_IP6", "LEGATTO_PUBLIC_IPV4")

# Common exit codes (CONTRACT §4.6).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LOCKED = 3
EXIT_PRECONDITION = 4


class ToolError(Exception):
    """Expected failure with an exit code and a message for humans (no secrets)."""

    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


def path(contract_path: str) -> Path:
    """Contract path, optionally re-rooted under $LEGATTO_ROOT (tests)."""
    root = os.environ.get("LEGATTO_ROOT")
    return Path(root + contract_path) if root else Path(contract_path)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def fail(message: str, code: int = EXIT_ERROR) -> NoReturn:
    raise ToolError(message, code)


def write_atomic(target: Path, data: bytes, mode: int = 0o640, uid: int | None = None, gid: int | None = None) -> None:
    """Temp file in the same directory, fsync, chmod/chown, rename."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0 and (uid is not None or gid is not None):
            os.chown(tmp, -1 if uid is None else uid, -1 if gid is None else gid)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_json_atomic(target: Path, obj: Any, mode: int = 0o640, uid: int | None = None, gid: int | None = None) -> None:
    write_atomic(target, (json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode(), mode, uid, gid)


def read_json(target: Path, default: Any = None) -> Any:
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_status(component: str, ok: bool, fields: dict[str, Any]) -> None:
    """/var/lib/legatto/status/<component>.json (CONTRACT §4.4), 0640 root:legatto-status."""
    target = path(P_STATUS) / f"{component}.json"
    envelope = {"v": 1, "component": component, "ts": utc_now(), "ok": ok}
    envelope.update(fields)
    gid = None
    if os.geteuid() == 0:
        gid = _group_id("legatto-status")  # contract: legatto_groups.status
    write_json_atomic(target, envelope, 0o640, None, gid)


def _group_id(name: str) -> int | None:
    import grp

    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def audit(cat: str, event: str, actor: dict[str, Any], params: dict[str, Any]) -> None:
    """Appends to the audit chain through the single writer (legatto-audit append)."""
    binary = os.environ.get("LEGATTO_AUDIT_BIN", CLI_AUDIT)
    cmd = [binary, "append", "--cat", cat, "--event", event, "--actor", json.dumps(actor, sort_keys=True),
           "--params", json.dumps(params, sort_keys=True)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode != 0:
        log(f"audit append {event} failed with exit {result.returncode}")


ACTOR_RE = re.compile(r"^[a-z][a-z0-9.@_-]{0,63}$")


def parse_actor(raw: str | None, tool: str) -> dict[str, Any]:
    if raw is None:
        return {"kind": "system", "id": tool}
    try:
        actor = json.loads(raw)
    except json.JSONDecodeError:
        fail("--actor must be a JSON object", EXIT_USAGE)
    if not isinstance(actor, dict) or actor.get("kind") not in ("office-admin", "vendor", "system", "bootstrap"):
        fail("--actor needs kind office-admin|vendor|system|bootstrap", EXIT_USAGE)
    if not isinstance(actor.get("id"), str) or not ACTOR_RE.match(actor["id"]):
        fail("--actor.id is invalid", EXIT_USAGE)
    return {"kind": actor["kind"], "id": actor["id"]}


class Lock:
    """Non-blocking flock on /run/legatto/<name>.lock; exit 3 when held."""

    def __init__(self, name: str) -> None:
        self.target = path(P_RUN) / f"{name}.lock"
        self.handle: Any = None

    def __enter__(self) -> "Lock":
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.target, "a+")  # noqa: SIM115 - held for the lifetime of the lock
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.close()
            fail(f"another instance holds {self.target}", EXIT_LOCKED)
        return self

    def __exit__(self, *exc: object) -> None:
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()


def require_root() -> None:
    if os.geteuid() != 0 and not os.environ.get("LEGATTO_ROOT"):
        fail("must run as root", EXIT_PRECONDITION)


def office_env() -> dict[str, str]:
    """Parses /etc/legatto/office.env (KEY=value, no quoting, no expansion)."""
    target = path(P_OFFICE_ENV)
    try:
        text = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"{target} is missing", EXIT_PRECONDITION)
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.match(r"^LEGATTO_[A-Z0-9_]+$", key):
            fail(f"{target}: malformed line", EXIT_PRECONDITION)
        values[key] = value
    missing = [k for k in ENV_KEYS_REQUIRED if not values.get(k)]
    if missing:
        fail(f"{target} lacks {', '.join(missing)}", EXIT_PRECONDITION)
    return values


def cloudflare_config() -> dict[str, Any]:
    """Non-secret ids written by legatto-cf-bootstrap; exit 4 before bootstrap."""
    target = path(P_PUBLICSITE_ETC) / "cloudflare.json"
    config = read_json(target)
    if not isinstance(config, dict) or config.get("v") != 1:
        fail(f"{target} is missing; run the cf_bootstrap role first", EXIT_PRECONDITION)
    return config


class Credentials:
    """Decrypted systemd credentials for one tool run, staged for a container.

    Source: $CREDENTIALS_DIRECTORY (unit with LoadCredentialEncrypted=) or,
    when an operator runs the tool by hand, `systemd-creds decrypt` of
    /etc/credstore.encrypted/<name>. Either way the value is written to a
    private directory under /run/legatto/credentials (tmpfs, 0700 root) as a
    0400 file owned by the container uid, bind-mounted read-only into exactly
    one container, and removed when the run ends.
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.unit_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        self.private_dir: Path | None = None

    def __enter__(self) -> "Credentials":
        return self

    def get(self, name: str) -> Path:
        if self.private_dir is None:
            base = ensure_dir(path(P_RUN) / "credentials", 0o700)
            self.private_dir = Path(tempfile.mkdtemp(prefix=f"{self.tool}-", dir=base))
        target = self.private_dir / name
        if target.is_file():
            return target
        loaded = Path(self.unit_dir) / name if self.unit_dir else None
        if loaded is not None and loaded.is_file():
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, "wb") as handle:
                handle.write(loaded.read_bytes())
        else:
            source = path(P_CREDSTORE) / name
            if not source.is_file():
                fail(f"credential {name} does not exist in {path(P_CREDSTORE)}", EXIT_PRECONDITION)
            creds = os.environ.get("LEGATTO_SYSTEMD_CREDS", "systemd-creds")
            result = subprocess.run([creds, "decrypt", f"--name={name}", str(source), str(target)],
                                    capture_output=True, text=True, check=False, timeout=60)
            if result.returncode != 0:
                fail(f"cannot decrypt credential {name} (systemd-creds exit {result.returncode})", EXIT_PRECONDITION)
        os.chmod(target, 0o400)
        if os.geteuid() == 0:
            os.chown(target, CONTAINER_UID, CONTAINER_UID)
        return target

    def read(self, name: str) -> bytes:
        return self.get(name).read_bytes()

    def __exit__(self, *exc: object) -> None:
        if self.private_dir is not None:
            for entry in self.private_dir.iterdir():
                entry.unlink(missing_ok=True)
            self.private_dir.rmdir()


def encrypt_credential(name: str, secret: bytes) -> None:
    """Writes /etc/credstore.encrypted/<name> with systemd-creds (0400 root); secret via stdin."""
    target = path(P_CREDSTORE) / name
    target.parent.mkdir(parents=True, exist_ok=True)
    creds = os.environ.get("LEGATTO_SYSTEMD_CREDS", "systemd-creds")
    tmp = target.with_name(f".{name}.tmp")
    result = subprocess.run([creds, "encrypt", f"--name={name}", "-", str(tmp)], input=secret,
                            capture_output=True, check=False, timeout=60)
    if result.returncode != 0:
        tmp.unlink(missing_ok=True)
        fail(f"systemd-creds encrypt {name} failed (exit {result.returncode})")
    os.chmod(tmp, 0o400)
    os.replace(tmp, target)


@dataclass(frozen=True)
class Image:
    ref: str  # <repository>@sha256:<digest>
    digest: str


def release_image(release_dir: Path, name: str = APP_IMAGE_NAME) -> tuple[Image, dict[str, Any]]:
    """Image of the release by digest: `<repo without tag>@<digest>` (updater loads it)."""
    manifest = read_json(release_dir / "manifest.json")
    if not isinstance(manifest, dict):
        fail(f"{release_dir}/manifest.json is missing", EXIT_PRECONDITION)
    for image in manifest.get("images", []):
        if image.get("name") == name:
            digest = image.get("digest", "")
            ref = image.get("ref", "")
            if not re.match(r"^sha256:[0-9a-f]{64}$", digest) or ":" not in ref:
                fail(f"manifest image {name} is malformed", EXIT_PRECONDITION)
            repository = ref.rsplit(":", 1)[0]
            return Image(f"{repository}@{digest}", digest), manifest
    fail(f"manifest has no image {name}", EXIT_PRECONDITION)


@dataclass
class Mount:
    source: Path
    target: str
    readonly: bool = True


@dataclass
class ContainerSpec:
    """One `docker run` of the app image with the publicsite hardening baseline."""

    image: Image
    command: list[str]
    network: str  # a contract network name or "none"
    mounts: list[Mount]
    env: dict[str, str]
    name_prefix: str
    memory: str = "512m"
    tmpfs_size: str = "64m"

    def argv(self, docker: str) -> list[str]:
        args = [docker, "run", "--rm", "--pull=never",
                "--name", f"{self.name_prefix}-{os.getpid()}",
                "--network", self.network,
                "--user", f"{CONTAINER_UID}:{CONTAINER_UID}",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "256", "--memory", self.memory,
                "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_size}",
                "--entrypoint", "/nodejs/bin/node",
                "--log-driver", "none",
                "-e", "HOME=/tmp"]
        for key in sorted(self.env):
            args += ["-e", f"{key}={self.env[key]}"]
        for mount in self.mounts:
            spec = f"type=bind,src={mount.source},dst={mount.target}"
            if mount.readonly:
                spec += ",readonly"
            args += ["--mount", spec]
        args.append(self.image.ref)
        args += self.command
        return args


def proxy_env(service: str) -> dict[str, str]:
    url = f"http://{service}:{PROXY_PORT}"
    return {"HTTPS_PROXY": url, "https_proxy": url}


def run_container(spec: ContainerSpec, timeout: int) -> tuple[int, dict[str, Any] | None]:
    """Runs the container; returns (exit code, parsed JSON stdout or None)."""
    docker = os.environ.get("LEGATTO_DOCKER", "docker")
    try:
        result = subprocess.run(spec.argv(docker), capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run([docker, "rm", "-f", f"{spec.name_prefix}-{os.getpid()}"], capture_output=True, check=False)
        return 124, None
    for line in result.stderr.splitlines()[-20:]:
        log(f"[{spec.name_prefix}] {line}")
    parsed: dict[str, Any] | None = None
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if lines:
        try:
            candidate = json.loads(lines[-1])
            parsed = candidate if isinstance(candidate, dict) else None
        except json.JSONDecodeError:
            parsed = None
    return result.returncode, parsed


def ensure_dir(target: Path, mode: int, uid: int | None = None, gid: int | None = None) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    os.chmod(target, mode)
    if os.geteuid() == 0 and (uid is not None or gid is not None):
        os.chown(target, -1 if uid is None else uid, -1 if gid is None else gid)
    return target


def main_wrapper(tool: str, run: Any) -> int:
    """Uniform error handling: ToolError -> its code; unexpected -> 1."""
    try:
        return int(run())
    except ToolError as err:
        log(f"{tool}: {err}")
        emit({"ok": False, "error": str(err)})
        return err.code
    except KeyboardInterrupt:
        return EXIT_ERROR
