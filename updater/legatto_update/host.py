"""Access to the host: paths, clock, commands, files.

Production runs as root with fixed paths and a fixed PATH. The test suite
(tests/updater) sets LEGATTO_TEST_ROOT: every absolute path is then placed
under that directory, the inherited PATH is used (fake docker/systemctl/
legatto-* tools) and the clock can be injected. Nothing else changes.
"""

import datetime as _dt
import grp
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time

from . import const

SAFE_PATH = "/opt/legatto/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


class CommandError(Exception):
    def __init__(self, argv, rc, out, err):
        super().__init__("%s: exit %s: %s" % (argv[0], rc, (err or out or "").strip()[-400:]))
        self.argv = argv
        self.rc = rc
        self.out = out
        self.err = err


class Host:
    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        self.test_root = env.get("LEGATTO_TEST_ROOT") or None
        self._env = env

    # --- paths -----------------------------------------------------------------
    def p(self, path: str) -> str:
        if self.test_root and path.startswith("/"):
            return self.test_root.rstrip("/") + path
        return path

    def state(self, *parts: str) -> str:
        return os.path.join(self.p(const.UPDATE_STATE), *parts)

    # --- clock -----------------------------------------------------------------------
    def now(self) -> float:
        if self.test_root and self._env.get("LEGATTO_TEST_NOW"):
            return parse_ts(self._env["LEGATTO_TEST_NOW"])
        return time.time()

    def mono(self) -> float:
        if self.test_root and self._env.get("LEGATTO_TEST_MONO"):
            return float(self._env["LEGATTO_TEST_MONO"])
        return time.monotonic()

    def boot_id(self) -> str:
        if self.test_root and self._env.get("LEGATTO_TEST_BOOT_ID"):
            return self._env["LEGATTO_TEST_BOOT_ID"]
        try:
            with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
                return fh.read().strip()
        except OSError:
            return "unknown"

    def sleep(self, seconds: float) -> None:
        if self.test_root and self._env.get("LEGATTO_TEST_NO_SLEEP"):
            return
        time.sleep(seconds)

    # --- privileges ---------------------------------------------------------------
    def is_root(self) -> bool:
        return bool(self.test_root) or os.geteuid() == 0

    def proxy(self):
        if self.test_root:
            return self._env.get("LEGATTO_TEST_PROXY") or None
        return const.EGRESS_PROXY

    # --- commands -----------------------------------------------------------------
    def command_env(self, extra=None) -> dict:
        if self.test_root:
            env = dict(self._env)
        else:
            env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"}
        if extra:
            env.update(extra)
        return env

    def run(self, argv, *, input_bytes=None, timeout=600, check=True, env=None, cwd=None):
        try:
            proc = subprocess.run(
                [str(a) for a in argv], input=input_bytes, capture_output=True, timeout=timeout,
                env=self.command_env(env), cwd=cwd, check=False)
        except FileNotFoundError as exc:
            raise CommandError(list(argv), 127, "", str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(list(argv), 124, "", "timeout after %ss" % timeout) from exc
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        if check and proc.returncode != 0:
            raise CommandError(list(argv), proc.returncode, out, err)
        return proc.returncode, out, err

    # --- files ------------------------------------------------------------------------
    def chgrp(self, path: str, group) -> None:
        if group is None:
            return
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            if self.test_root:
                return
            raise
        if self.test_root:
            return
        os.chown(path, 0, gid)

    def write_bytes(self, path: str, data: bytes, mode=0o644, group=None) -> None:
        """Atomic write: temp file in the same directory, fsync, rename, fsync dir."""
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            self.chgrp(tmp, group)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        fsync_dir(directory)

    def write_json(self, path: str, obj, mode=0o644, group=None) -> None:
        data = (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        self.write_bytes(path, data, mode=mode, group=group)


def fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def read_json(path: str, default=None):
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))
    except FileNotFoundError:
        return default


def read_bytes(path: str):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def symlink_atomic(target: str, link: str) -> None:
    tmp = "%s.tmp-%d" % (link, os.getpid())
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(target, tmp)
    os.replace(tmp, link)
    fsync_dir(os.path.dirname(link))


def rmtree(path: str) -> None:
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def fmt_ts(epoch: float) -> str:
    return _dt.datetime.fromtimestamp(int(epoch), tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str) -> float:
    """Parse YYYY-MM-DDTHH:MM:SSZ (the only time format of the contract)."""
    dt = _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    return dt.timestamp()


def parse_semver(value: str):
    """Key for SemVer 2.0 precedence (build metadata is not allowed by the schemas)."""
    core, _, pre = value.partition("-")
    major, minor, patch = (int(x) for x in core.split("."))
    if not pre:
        return (major, minor, patch, 1, ())
    ids = []
    for part in pre.split("."):
        ids.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return (major, minor, patch, 0, tuple(ids))


def semver_gt(a: str, b: str) -> bool:
    return parse_semver(a) > parse_semver(b)


def read_office_env(path: str) -> dict:
    """KEY=value per line, no quoting, no expansion (section 4.1)."""
    values = {}
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                raise ValueError("office.env: line without '='")
            values[key.strip()] = value
    return values
