"""Shared helpers of the net-lane host tools (legatto-breakglass, legatto-policy,
legatto-tailnet, legatto-fw-*).

Installed by the base role to /opt/legatto/lib/net/legatto_net.py; the tools
import it from <their dir>/../lib/net. Python 3.12 standard library only.

Paths below are the contract values (contract/contract.yml); the net tests
check every `# contract:` comment against that file. Tests run the
tools with LEGATTO_TEST_ROOT=<scratch dir> (every path is prefixed) and fake
binaries first on PATH; production never sets the variable and gets a fixed
PATH.
"""

from __future__ import annotations

import errno
import fcntl
import grp
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

ROOT = os.environ.get("LEGATTO_TEST_ROOT", "")
if not ROOT:
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SBIN = ROOT + "/opt/legatto/sbin"  # contract: legatto_paths.sbin
OFFICE_ENV = ROOT + "/etc/legatto/office.env"  # contract: legatto_paths.office_env
POLICY_DIR = ROOT + "/etc/legatto/policy"  # contract: legatto_paths.acl_policy_dir
HEADSCALE_POLICY = ROOT + "/etc/headscale/policy.hujson"  # contract: legatto_paths.headscale_policy
STATUS_DIR = ROOT + "/var/lib/legatto/status"  # contract: legatto_paths.status
BREAKGLASS_DIR = ROOT + "/var/lib/legatto/breakglass"  # contract: legatto_paths.breakglass
TAILNET_DIR = ROOT + "/var/lib/legatto/tailnet"  # contract: legatto_paths.tailnet
AUDIT_LOG = ROOT + "/var/log/legatto/audit.log"  # contract: legatto_paths.audit_log
AUDIT_STATE = ROOT + "/var/lib/legatto/audit"  # contract: legatto_paths.audit_state
RUN_DIR = ROOT + "/run/legatto"  # contract: legatto_paths.run
FW_RUN = ROOT + "/run/legatto/fw"  # contract: legatto_paths.fw_run
NFT_MAIN = ROOT + "/etc/nftables.conf"  # contract: legatto_paths.nft_main

STATUS_GROUP = "legatto-status"  # contract: legatto_groups.status
CONSOLE_GROUP = "legatto-console"  # contract: legatto_groups.console
OPS_GROUP = "legatto-ops"  # contract: legatto_groups.ops
HEADSCALE_UNIT = "headscale.service"  # contract: legatto_units.headscale
NFT_TABLE = "legatto"
NFT_FAMILY = "inet"
NFT_SETS = {"vendor4": "vendor4", "vendor6": "vendor6", "window4": "bg4", "window6": "bg6"}  # contract: legatto_breakglass.nft_sets
TAG_SERVER = "tag:server"  # contract: legatto_tailnet_tags.server
TAG_OFFICE = "tag:office-device"  # contract: legatto_tailnet_tags.office_device
PREFIX_V4 = ipaddress.ip_network("100.64.0.0/10")  # contract: legatto_tailnet_prefix_v4
PREFIX_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")  # contract: legatto_tailnet_prefix_v6
VENDOR_RE = re.compile(r"^v-[a-z][a-z0-9-]{1,20}$")  # contract: legatto_vendor_login_regex
STAFF_RE = re.compile(r"^[a-z][a-z0-9.-]{1,40}$")
ACTOR_KINDS = ("office-admin", "vendor", "system", "bootstrap")
ACTOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:-]{0,62}$")

EXIT_OK, EXIT_ERR, EXIT_ARGS, EXIT_LOCK, EXIT_PRECOND = 0, 1, 2, 3, 4


class ToolError(Exception):
    def __init__(self, message: str, code: int = EXIT_ERR):
        super().__init__(message)
        self.code = code


# --- time ------------------------------------------------------------------------------

def now() -> datetime:
    """Current UTC time. Tests may pin it with LEGATTO_TEST_NOW (only with LEGATTO_TEST_ROOT)."""
    fixed = os.environ.get("LEGATTO_TEST_NOW") if ROOT else None
    if fixed:
        return parse_ts(fixed)
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def hours(n: int) -> timedelta:
    return timedelta(hours=n)


# --- files -----------------------------------------------------------------------------

def require_root() -> None:
    if os.geteuid() != 0 and not ROOT:
        raise ToolError("must run as root", EXIT_PRECOND)


def atomic_write(path: str, data: bytes, mode: int = 0o640, group: str | None = None,
                 owner_uid: int = 0) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            gid = 0
            if group:
                try:
                    gid = grp.getgrnam(group).gr_gid
                except KeyError:
                    gid = 0
            os.fchown(fd, owner_uid, gid)
        os.close(fd)
        fd = -1
        os.rename(tmp, path)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path: str, doc: object, mode: int = 0o640, group: str | None = None) -> None:
    atomic_write(path, (json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8"),
                 mode, group)


def read_json(path: str, default: object = None) -> object:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_status(component: str, ok: bool, fields: dict) -> None:
    """CONTRACT §4.4 envelope; atomic, 0640 root:legatto-status."""
    if not os.path.isdir(STATUS_DIR):
        return
    doc = {"v": 1, "component": component, "ts": fmt_ts(now()), "ok": bool(ok)}
    doc.update(fields)
    atomic_write(os.path.join(STATUS_DIR, f"{component}.json"),
                 (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8"), 0o640, STATUS_GROUP)


def read_office_env() -> dict:
    values: dict = {}
    try:
        with open(OFFICE_ENV, encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key] = value
    except FileNotFoundError:
        pass
    return values


class FileLock:
    """flock with a bounded wait; exit code 3 when another instance holds it."""

    def __init__(self, path: str, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self.fd = -1

    def __enter__(self) -> "FileLock":
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
            if time.monotonic() >= deadline:
                os.close(self.fd)
                self.fd = -1
                raise ToolError(f"another instance holds {self.path}", EXIT_LOCK)
            time.sleep(0.1)

    def __exit__(self, *_exc: object) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)


# --- processes -----------------------------------------------------------------------------

def run(cmd: list, check: bool = True, timeout: float = 30, input_text: str | None = None,
        ) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text, check=False)
    except FileNotFoundError as exc:
        raise ToolError(f"{cmd[0]}: not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{cmd[0]}: timed out after {timeout:.0f} s") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        raise ToolError(f"{' '.join(cmd[:3])}: exit {proc.returncode}: {detail[-1] if detail else ''}")
    return proc


def tool(name: str) -> str:
    """Path of a sibling host tool (legatto-audit, legatto-policy, ...)."""
    path = os.path.join(SBIN, name)
    if os.path.exists(path):
        return path
    return name


# --- actor / audit -------------------------------------------------------------------------

def parse_actor(raw: str | None, required: bool = True) -> dict | None:
    if raw is None:
        if required:
            raise ToolError("--actor JSON is required for state-changing commands", EXIT_ARGS)
        return None
    try:
        actor = json.loads(raw)
    except ValueError as exc:
        raise ToolError(f"--actor is not JSON: {exc}", EXIT_ARGS) from exc
    if not isinstance(actor, dict) or actor.get("kind") not in ACTOR_KINDS \
            or not isinstance(actor.get("id"), str) or not ACTOR_ID_RE.match(actor["id"]):
        raise ToolError("--actor must be {\"kind\": office-admin|vendor|system|bootstrap, \"id\": ...}", EXIT_ARGS)
    if actor["kind"] == "vendor" and not VENDOR_RE.match(actor["id"]):
        raise ToolError("vendor actor id must be a v-<name> account", EXIT_ARGS)
    return actor


def audit(cat: str, event: str, actor: dict, params: dict, node: str | None = None) -> dict:
    """Append through the single writer; raises ToolError when it fails."""
    cmd = [tool("legatto-audit"), "append", "--cat", cat, "--event", event,
           "--actor", json.dumps(actor, sort_keys=True), "--params", json.dumps(params, sort_keys=True)]
    if node:
        cmd += ["--node", node]
    proc = run(cmd, check=False, timeout=20)
    if proc.returncode != 0:
        raise ToolError(f"audit append {event} failed (exit {proc.returncode}): {proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise ToolError(f"audit append {event}: unexpected output") from exc


def audit_best_effort(cat: str, event: str, actor: dict, params: dict) -> dict | None:
    try:
        return audit(cat, event, actor, params)
    except ToolError as exc:
        warn(str(exc))
        return None


def warn(message: str) -> None:
    print(f"{os.path.basename(sys.argv[0])}: {message}", file=sys.stderr)


# --- headscale -------------------------------------------------------------------------------

def ts_field(value: object) -> str | None:
    """Headscale prints timestamps either as RFC 3339 strings or {seconds, nanos}."""
    if isinstance(value, dict) and "seconds" in value:
        seconds = int(value.get("seconds") or 0)
        if seconds <= 0:
            return None
        return fmt_ts(datetime.fromtimestamp(seconds, timezone.utc))
    if isinstance(value, str) and value and not value.startswith("0001-"):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return fmt_ts(parsed)
    return None


def headscale_json(args: list, timeout: float = 20) -> object:
    proc = run(["headscale", *args, "--output", "json"], timeout=timeout)
    text = proc.stdout.strip()
    if not text or text == "null":
        return []
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ToolError(f"headscale {' '.join(args)}: unparsable JSON") from exc


def normalize_node(raw: dict) -> dict:
    user = raw.get("user") or {}
    tags: list = []
    for key in ("tags", "forced_tags", "valid_tags"):
        for tag in raw.get(key) or []:
            if tag not in tags:
                tags.append(tag)
    ips = [str(ip) for ip in raw.get("ip_addresses") or []]
    ip4 = next((ip for ip in ips if ":" not in ip), None)
    ip6 = next((ip for ip in ips if ":" in ip), None)
    return {
        "id": str(raw.get("id")),
        "name": raw.get("given_name") or raw.get("name") or "",
        "user": user.get("name") if isinstance(user, dict) else None,
        "tags": sorted(tags),
        "ips": ips,
        "ip4": ip4,
        "ip6": ip6,
        "online": bool(raw.get("online")),
        "last_seen": ts_field(raw.get("last_seen")),
        "expiry": ts_field(raw.get("expiry")),
    }


def headscale_nodes() -> list:
    data = headscale_json(["nodes", "list"])
    if not isinstance(data, list):
        raise ToolError("headscale nodes list: expected a list")
    return [normalize_node(n) for n in data if isinstance(n, dict)]


def headscale_users() -> dict:
    data = headscale_json(["users", "list"])
    if not isinstance(data, list):
        raise ToolError("headscale users list: expected a list")
    return {u.get("name"): str(u.get("id")) for u in data if isinstance(u, dict) and u.get("name")}


def node_is_tagged(node: dict) -> bool:
    return bool(node["tags"])


def vendor_ips(nodes: list, vendors: list) -> tuple:
    v4, v6 = [], []
    for node in nodes:
        if node["user"] in vendors and not node_is_tagged(node):
            v4 += [ip for ip in node["ips"] if ":" not in ip]
            v6 += [ip for ip in node["ips"] if ":" in ip]
    return sorted(set(v4)), sorted(set(v6))


# --- nft -----------------------------------------------------------------------------------------

def nft_apply(script: str) -> None:
    """Run one atomic nft transaction from stdin."""
    run(["nft", "-f", "-"], input_text=script, timeout=20)


def nft_set_elements(name: str) -> dict:
    """Return {element: seconds_left_or_None} of a set in table inet legatto."""
    proc = run(["nft", "-j", "list", "set", NFT_FAMILY, NFT_TABLE, name], check=False, timeout=10)
    if proc.returncode != 0:
        raise ToolError(f"nft list set {name}: {proc.stderr.strip()}")
    result: dict = {}
    doc = json.loads(proc.stdout)
    for item in doc.get("nftables", []):
        nft_set = item.get("set")
        if not nft_set:
            continue
        for elem in nft_set.get("elem", []) or []:
            if isinstance(elem, dict) and "elem" in elem:
                inner = elem["elem"]
                result[str(inner.get("val"))] = inner.get("expires")
            else:
                result[str(elem)] = None
    return result


def nft_element_line(addresses: list, timeout_s: int | None = None) -> str:
    if timeout_s is None:
        return ", ".join(addresses)
    return ", ".join(f"{a} timeout {int(timeout_s)}s" for a in addresses)
