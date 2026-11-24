"""Shared fixtures of the console tests: a prefixed server tree, fake tools, request builders."""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CONSOLE_SRC = os.path.join(REPO, "office-console")
import sys  # noqa: E402

sys.path.insert(0, CONSOLE_SRC)

from legatto_console import contract, crypto, executor, store, validate  # noqa: E402

IS_ROOT = os.geteuid() == 0
ADMIN_HOST = "admin.app.legatto-example.example"
OFFICE_IP = "fd7a:115c:a1e0::5"
STAFF_IP = "100.64.0.7"
FAKE_TOOLS = (contract.CLI_AUDIT, contract.CLI_BREAKGLASS, contract.CLI_UPDATE, contract.CLI_TAILNET,
              contract.CLI_EGRESS, contract.CLI_RECOVERY_PACK)


def console_ids() -> tuple[int, int]:
    return pwd.getpwnam(contract.CONSOLE_USER).pw_uid, grp.getgrnam(contract.CONSOLE_GROUP).gr_gid


class ServerTree:
    """A temporary root with the contract layout, fake tools and a first console user."""

    def __init__(self) -> None:
        self.root = tempfile.mkdtemp(prefix="legatto-console-test-")
        os.chmod(self.root, 0o755)
        contract.PREFIX = self.root
        self.uid, self.gid = console_ids()
        for spec in executor.SPOOL_LAYOUT:
            location = self.p(spec.path)
            os.makedirs(location, exist_ok=True)
            os.chown(location, 0, 0 if spec.group is None else self.gid)
            os.chmod(location, spec.mode)
        for directory, mode, gid in ((contract.STATUS_DIR, 0o750, grp.getgrnam(contract.STATUS_GROUP).gr_gid),
                                     (os.path.dirname(contract.FEATURES), 0o750, self.gid),
                                     (contract.RECOVERY_DIR, 0o750, self.gid),
                                     (contract.BREAKGLASS_SUMMARIES, 0o750, self.gid),
                                     (contract.UPDATE_PENDING, 0o750, self.gid),
                                     (contract.TAILNET_STATE, 0o700, 0),
                                     (contract.RUN_DIR, 0o755, 0),
                                     (contract.SBIN, 0o755, 0),
                                     ("/usr/bin", 0o755, 0),
                                     ("/fake", 0o755, 0),
                                     ("/var/log/legatto", 0o750, grp.getgrnam(contract.AUDIT_GROUP).gr_gid)):
            location = self.p(directory)
            os.makedirs(location, exist_ok=True)
            os.chown(location, 0, gid)
            os.chmod(location, mode)
        for name in FAKE_TOOLS:
            self.install_fake(contract.tool(name))
        self.install_fake(self.p(contract.TAILSCALE))
        self.write_json("/fake/whois.json", {
            OFFICE_IP: {"ComputedName": "biuro-laptop", "Name": "biuro-laptop.tn.example.", "Tags": ["tag:office-device"]},
            STAFF_IP: {"ComputedName": "anna-telefon", "Name": "anna-telefon.tn.example.", "Tags": []},
        })
        with open(self._mk(contract.OFFICE_ENV), "w", encoding="utf-8") as handle:
            handle.write(f"LEGATTO_SLUG=example\nLEGATTO_OFFICE_TITLE=Biuro testowe\n"
                         f"LEGATTO_HOST_ADMIN={ADMIN_HOST}\nLEGATTO_TZ=Europe/Warsaw\n")
        self.write_json(contract.FEATURES, {"v": 1, "updated_at": "2026-11-21T00:00:00Z",
                                            "features": {n: n == "hibp" for n in contract.FEATURE_NAMES},
                                            "ics_hosts": []}, mode=0o640, gid=self.gid)
        self.clock_offset = 0.0
        self.ex = executor.Executor(clock=self.now)

    def _mk(self, location: str) -> str:
        full = self.p(location)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        return full

    def now(self) -> float:
        return time.time() + self.clock_offset

    def p(self, location: str) -> str:
        return self.root + location

    def install_fake(self, target: str) -> None:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy(os.path.join(HERE, "fake_tool.py"), target)
        os.chmod(target, 0o755)

    def write_json(self, location: str, obj, mode: int = 0o644, gid: int = 0) -> None:
        full = self._mk(location)
        with open(full, "w", encoding="utf-8") as handle:
            json.dump(obj, handle)
        os.chown(full, 0, gid)
        os.chmod(full, mode)

    def fake(self, tool: str, behaviour: dict) -> None:
        self.write_json(f"/fake/{tool}.json", behaviour)

    def calls(self, tool: str | None = None) -> list[dict]:
        try:
            with open(self.p("/fake/calls.jsonl"), encoding="utf-8") as handle:
                items = [json.loads(line) for line in handle]
        except FileNotFoundError:
            return []
        return [c for c in items if tool is None or c["tool"] == tool]

    def audit_entries(self) -> list[dict]:
        try:
            with open(self.p(contract.AUDIT_LOG), encoding="utf-8") as handle:
                return [json.loads(line) for line in handle]
        except FileNotFoundError:
            return []

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
        contract.PREFIX = ""

    # --- users and requests -------------------------------------------------------------------
    def add_user(self, login: str, password: str = "correct horse battery", must_change: bool = False,
                 kind: str = "admin") -> str:
        secret = self.ex._new_account(login, login.title(), crypto.scrypt_hash(password), must_change, kind)
        return secret

    def totp(self, login: str, offset_steps: int = 0) -> str:
        with open(os.path.join(self.p(contract.CONSOLE_TOTP_SEEDS), login), encoding="ascii") as handle:
            key = crypto.decode_totp_secret(handle.read())
        return crypto.totp(key, self.now() + offset_steps * crypto.TOTP_STEP)

    def forget_step(self, login: str) -> None:
        try:
            os.unlink(os.path.join(self.p(contract.CONSOLE_AUTH), login + ".step"))
        except FileNotFoundError:
            pass

    def request(self, rtype: str, params: dict, user: str = "szef", ip: str = OFFICE_IP, totp: str | None = None,
                rid: str | None = None, ts: float | None = None, auth: dict | None = None) -> dict:
        rid = rid or crypto.new_ulid(self.now())
        if auth is None:
            auth = {"method": "local-totp", "totp": totp if totp is not None else self.totp(user)}
        return {"v": 1, "id": rid, "type": rtype, "ts": validate.format_utc(self.now() if ts is None else ts),
                "actor": {"user": user, "ip": ip}, "auth": auth, "params": params}

    def drop(self, request: dict | bytes, name: str | None = None, owner: int | None = None) -> str:
        """Write a request into incoming/ the way the panel does (owned by legatto-console)."""
        raw = request if isinstance(request, bytes) else json.dumps(request).encode()
        name = name or (request["id"] + ".json")
        path = os.path.join(self.p(contract.REQUESTS_INCOMING), name)
        with open(path, "wb") as handle:
            handle.write(raw)
        os.chown(path, self.uid if owner is None else owner, self.gid)
        os.chmod(path, 0o640)
        return path

    def run(self, request: dict) -> dict:
        self.drop(request)
        self.ex.process(once=True)
        return self.result(request["id"])

    def result(self, rid: str) -> dict | None:
        return store.read_json(os.path.join(self.p(contract.REQUESTS_RESULTS), rid + ".json"))


class TreeCase(unittest.TestCase):
    """Base class: fresh ServerTree per test, one console user `szef`."""

    def setUp(self) -> None:
        if not IS_ROOT:
            self.skipTest("needs root (run through tests/console/run.sh)")
        self.tree = ServerTree()
        self.secret = self.tree.add_user("szef")
        self.tree.add_user("anna")

    def tearDown(self) -> None:
        self.tree.cleanup()
