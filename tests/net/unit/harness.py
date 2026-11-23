"""Scratch-root harness for the net-lane host tools.

Each test gets a directory that mirrors the server layout (LEGATTO_TEST_ROOT)
with the real tools symlinked into opt/legatto/sbin and fake system binaries
(tests/net/fakes/fake.py) first on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SBIN = os.path.join(REPO, "sbin")
LIB = SBIN  # legatto_net.py, the module the tools share
FAKE = os.path.join(REPO, "tests", "net", "fakes", "fake.py")
TEMPLATE = os.path.join(REPO, "headscale", "acl.hujson.j2")
TOOLS = {
    "legatto-audit": os.path.join(SBIN, "legatto-audit"),
    "legatto-policy": os.path.join(SBIN, "legatto-policy"),
    "legatto-breakglass": os.path.join(SBIN, "legatto-breakglass"),
    "legatto-tailnet": os.path.join(SBIN, "legatto-tailnet"),
    "legatto-fw-apply": os.path.join(SBIN, "legatto-fw"),
    "legatto-fw-confirm": os.path.join(SBIN, "legatto-fw"),
    "legatto-fw-rollback": os.path.join(SBIN, "legatto-fw"),
}
FAKE_BINS = ("headscale", "nft", "tailscale", "systemctl", "systemd-run", "conntrack", "loginctl", "journalctl")
TS4, TS6 = "100.64.0.1", "fd7a:115c:a1e0::1"
STATIC = {"v": 1, "ts_ip4": TS4, "ts_ip6": TS6, "vendors": ["v-jan"],
          "tags": {"server": "tag:server", "office_device": "tag:office-device"},
          "groups": {"staff": "group:staff", "vendor": "group:vendor"},
          "ports": {"ssh": 22, "https": 443}}


def node(ident, user, ips, tags=()):
    return {"id": ident, "name": f"n{ident}", "given_name": f"n{ident}", "user": {"id": str(ident), "name": user},
            "ip_addresses": list(ips), "tags": list(tags), "online": True,
            "last_seen": "2026-11-21T10:00:00Z", "expiry": "0001-01-01T00:00:00Z"}


DEFAULT_NODES = [
    node(1, "tagged-devices", [TS4, TS6], ["tag:server"]),
    node(2, "anna", ["100.64.0.2", "fd7a:115c:a1e0::2"]),
    node(3, "tagged-devices", ["100.64.0.3", "fd7a:115c:a1e0::3"], ["tag:office-device"]),
    node(4, "v-jan", ["100.64.0.4", "fd7a:115c:a1e0::4"]),
]


class ToolTestCase(unittest.TestCase):
    with_policy_inputs = True

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="legatto-net-test-")
        self.root = os.path.join(self.tmp, "root")
        self.fake_state = os.path.join(self.tmp, "fake")
        self.bin = os.path.join(self.tmp, "bin")
        for path in ("opt/legatto/sbin", "etc/legatto/policy", "etc/headscale", "var/lib/legatto/status",
                     "var/lib/legatto/breakglass", "var/lib/legatto/tailnet", "var/log/legatto", "run/legatto"):
            os.makedirs(os.path.join(self.root, path))
        os.makedirs(self.fake_state)
        os.makedirs(self.bin)
        for name, path in TOOLS.items():
            os.symlink(path, os.path.join(self.root, "opt/legatto/sbin", name))
        for name in FAKE_BINS:
            os.symlink(FAKE, os.path.join(self.bin, name))
        with open(os.path.join(self.root, "etc/legatto/office.env"), "w") as fh:
            fh.write("LEGATTO_SLUG=testoffice\nLEGATTO_HOST_VPN=vpn.example.test\n")
        if self.with_policy_inputs:
            shutil.copy(TEMPLATE, os.path.join(self.root, "etc/legatto/policy/acl.hujson.j2"))
            self.write("etc/legatto/policy/static.json", STATIC)
            self.write("var/lib/legatto/tailnet/staff.json", {"v": 1, "staff": ["anna"]})
        self.set_fake({"users": [{"id": i, "name": n} for i, n in ((1, "anna"), (2, "v-jan"))],
                       "next_user_id": 3, "nodes": DEFAULT_NODES})
        self.now = None

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers --------------------------------------------------------------------------
    def env(self) -> dict:
        env = dict(os.environ)
        env.update({"LEGATTO_TEST_ROOT": self.root, "LEGATTO_NET_LIB": LIB, "FAKE_STATE": self.fake_state,
                    "PATH": self.bin + os.pathsep + env.get("PATH", "/usr/bin:/bin")})
        if self.now:
            env["LEGATTO_TEST_NOW"] = self.now
        return env

    def run_tool(self, name: str, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run([os.path.join(self.root, "opt/legatto/sbin", name), *args], env=self.env(),
                              capture_output=True, text=True, timeout=timeout, check=False)

    def path(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def write(self, rel: str, doc: object) -> None:
        with open(self.path(rel), "w") as fh:
            json.dump(doc, fh)

    def read(self, rel: str) -> object:
        with open(self.path(rel)) as fh:
            return json.load(fh)

    def text(self, rel: str) -> str:
        """File content; `rel` is relative to the scratch root unless absolute."""
        with open(rel if os.path.isabs(rel) else self.path(rel), encoding="utf-8") as fh:
            return fh.read()

    def fake(self) -> dict:
        with open(os.path.join(self.fake_state, "state.json")) as fh:
            return json.load(fh)

    def set_fake(self, updates: dict) -> None:
        state = {}
        path = os.path.join(self.fake_state, "state.json")
        if os.path.exists(path):
            state = self.fake()
        state.update(updates)
        with open(path, "w") as fh:
            json.dump(state, fh)

    def calls(self, name: str | None = None) -> list:
        path = os.path.join(self.fake_state, "calls.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            calls = [json.loads(line) for line in fh]
        return [c for c in calls if name is None or c["cmd"] == name]

    def audit_entries(self) -> list:
        path = self.path("var/log/legatto/audit.log")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [json.loads(line) for line in fh]

    def events(self) -> list:
        return [e["event"] for e in self.audit_entries()]

    def assert_ok(self, proc: subprocess.CompletedProcess, code: int = 0) -> None:
        self.assertEqual(proc.returncode, code, f"stdout={proc.stdout}\nstderr={proc.stderr}")
