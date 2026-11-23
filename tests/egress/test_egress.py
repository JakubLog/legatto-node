"""tests/egress: legatto-egress on reference data (CONTRACT §6, egress).

Runs inside the Ubuntu 24.04 test container (tests/egress/run.sh) as root,
privileged, so that nft can load rules and uid-based rules can be exercised.

Environment:
  REPO            legatto-node checkout (read-only)
  WORK            scratch directory shared with run.sh
  TARGET_IP       address of a helper container listening on tcp 443 and 8080
  UPDATE_GOLDEN   "1" rewrites tests/egress/golden (then fails, to force review)

fixtures/role holds config.json, pinned.json and features.json as the
deployment role renders them for the example office (the private deployment
tooling checks that the role output still equals this fixture).
"""

from __future__ import annotations

import copy
import fcntl
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(os.environ.get("REPO", "/repo"))
WORK = Path(os.environ.get("WORK", "/work"))
TOOL = REPO / "egress" / "legatto-egress"
FIXTURE = REPO / "tests" / "egress" / "fixtures" / "release-a"
ROLE_OUT = REPO / "tests" / "egress" / "fixtures" / "role"
GOLDEN = REPO / "tests" / "egress" / "golden"
TARGET_IP = os.environ.get("TARGET_IP", "")

# Fixed ids so that the rendered nft rules (meta skuid N) are reproducible.
TEST_USERS = {"smokescreen": 990, "legatto-mon": 991, "legatto-acme": 992, "headscale": 993,
              "_chrony": 994, "systemd-resolve": 995}
TEST_GROUPS = {"legatto-status": 980, "legatto-console": 981}

BASE_TABLE = """
table inet legatto
delete table inet legatto
table inet legatto {
	chain output {
		type filter hook output priority filter - 10; policy accept;
		jump egress_out
	}
	chain forward {
		type filter hook forward priority filter - 10; policy drop;
		ct state established,related accept
		iifname "br-*" oifname "eth0" jump egress_fwd
	}
	chain egress_out {
	}
	chain egress_fwd {
	}
}
"""


def sh(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    res = subprocess.run(list(args), capture_output=True, text=True, **kw)
    if check and res.returncode != 0:
        raise AssertionError(f"{args}: rc={res.returncode}\n{res.stdout}\n{res.stderr}")
    return res


def ensure_accounts() -> None:
    for name, gid in TEST_GROUPS.items():
        if sh("getent", "group", name, check=False).returncode != 0:
            sh("groupadd", "-g", str(gid), name)
    for name, uid in TEST_USERS.items():
        if sh("getent", "passwd", name, check=False).returncode != 0:
            sh("useradd", "-r", "-u", str(uid), "-U", "-M", "-s", "/usr/sbin/nologin", name)


class Sandbox:
    """The role-rendered config.json (fixtures/role), with every path moved under a temp dir."""

    def __init__(self, mode: str = "observe"):
        self.root = Path(tempfile.mkdtemp(prefix="egress-"))
        role_out = ROLE_OUT
        cfg = json.loads((role_out / "config.json").read_text())
        cfg["mode"] = mode
        p = cfg["paths"]
        for key in ("etc", "proxy_dir", "rendered_dir", "pinned", "features", "nft_file", "status_dir",
                    "state_dir", "lock", "current", "audit_cli"):
            p[key] = str(self.root / p[key].lstrip("/"))
        self.cfg = cfg
        self.audit_log = self.root / "audit.jsonl"
        audit = Path(p["audit_cli"])
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text("#!/bin/sh\n# test double of legatto-audit append: records the arguments\n"
                         f"python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \"$@\" >> {self.audit_log}\n"
                         "echo '{\"seq\":1,\"hash\":\"0\"}'\n")
        audit.chmod(0o755)
        Path(p["pinned"]).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(role_out / "pinned.json", p["pinned"])
        Path(p["features"]).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(role_out / "features.json", p["features"])
        Path(p["etc"]).mkdir(parents=True, exist_ok=True)
        self.config = self.root / "config.json"
        self.write_config()

    def write_config(self) -> None:
        self.config.write_text(json.dumps(self.cfg, indent=2))

    def set_mode(self, mode: str) -> None:
        self.cfg["mode"] = mode
        self.write_config()

    def set_features(self, flags: dict, ics_hosts: list | None = None) -> None:
        data = {"v": 1, "updated_at": "2026-11-21T10:00:00Z",
                "features": {**self.cfg["feature_defaults"], **flags}, "ics_hosts": ics_hosts or []}
        Path(self.cfg["paths"]["features"]).write_text(json.dumps(data))

    def run(self, *args: str, user: int | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(TOOL), "--config", str(self.config), *args],
                              capture_output=True, text=True, user=user)

    def release(self, egress: dict, version: str = "1.5.0") -> Path:
        d = Path(tempfile.mkdtemp(prefix="release-", dir=self.root))
        (d / "manifest.json").write_text(json.dumps({"version": version, "egress": egress}))
        return d

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def fixture_egress() -> dict:
    return json.loads((FIXTURE / "manifest.json").read_text())["egress"]


def load_base_table() -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as fh:
        fh.write(BASE_TABLE)
    sh("nft", "-f", fh.name)
    os.unlink(fh.name)


def connect(host: str, port: int, uid: int, timeout: float = 2.0) -> bool:
    code = (f"import socket,sys\ns=socket.socket(); s.settimeout({timeout})\n"
            f"sys.exit(0 if s.connect_ex(({host!r},{port}))==0 else 1)\n")
    return subprocess.run([sys.executable, "-c", code], user=uid, group=uid, extra_groups=[],
                          capture_output=True).returncode == 0


def counters() -> dict[str, int]:
    out = json.loads(sh("nft", "-j", "list", "counters", "table", "inet", "legatto").stdout)
    return {i["counter"]["name"]: i["counter"]["packets"] for i in out["nftables"] if "counter" in i}


class Listener:
    def __init__(self, host: str, port: int):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
                conn.close()
            except OSError:
                return

    def close(self) -> None:
        self.sock.close()


# --------------------------------------------------------------------------- data


class DataTests(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()

    def tearDown(self):
        self.sb.cleanup()

    def validate(self, egress: dict) -> subprocess.CompletedProcess:
        f = self.sb.root / "egress.json"
        f.write_text(json.dumps(egress))
        return self.sb.run("validate-data", "--egress-json", str(f))

    def test_bundle_data_is_valid(self):
        res = self.sb.run("validate-data", "--base", str(WORK / "base.json"),
                          "--features", str(WORK / "features.json"), "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout)
        self.assertEqual(sorted(out["features"]), sorted(self.sb.cfg["feature_names"]))

    def test_bundle_matches_fixture_shape(self):
        res = self.sb.run("validate-data", "--egress-json", str(FIXTURE / "manifest.json"))
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_rejected_entries(self):
        bad_hosts = ["1.2.3.4", "10.0.0.1", "2001:db8::1", "[::1]", "*.workers.dev", "*.com", "*.co.uk",
                     "*.s3.amazonaws.com", "API.resend.com", "api.resend.com:443", "a*.example.com",
                     "*.*.example.com", "example", "http://api.resend.com"]
        for host in bad_hosts:
            with self.subTest(host=host):
                eg = fixture_egress()
                eg["roles"]["app"].append({"host": host, "port": 443, "purpose": "x"})
                res = self.validate(eg)
                self.assertEqual(res.returncode, 42, f"{host}: {res.stderr}")
        cases = {
            "port 8443": {"host": "api.example.org", "port": 8443, "purpose": "x"},
            "port 80 outside host": {"host": "api.example.org", "port": 80, "purpose": "x"},
            "empty purpose": {"host": "api.example.org", "port": 443, "purpose": ""},
            "extra key": {"host": "api.example.org", "port": 443, "purpose": "x", "path": "/"},
            "duplicate": {"host": "api.resend.com", "port": 443, "purpose": "again"},
        }
        for name, entry in cases.items():
            with self.subTest(case=name):
                eg = fixture_egress()
                eg["roles"]["app"].append(entry)
                self.assertEqual(self.validate(eg).returncode, 42)
        eg = fixture_egress()
        eg["roles"]["db"] = []
        self.assertEqual(self.validate(eg).returncode, 42, "unknown role")
        eg = fixture_egress()
        eg["features"]["telemetry"] = {}
        self.assertEqual(self.validate(eg).returncode, 42, "unknown feature")

    def test_ip_in_ics_hosts_rejected(self):
        rel = self.sb.release(fixture_egress())
        for host in ("192.0.2.10", "*.calendar.example.org", "Calendar.example.org"):
            with self.subTest(host=host):
                self.sb.set_features({"ics": True}, [host])
                res = self.sb.run("render", "--release-dir", str(rel), "--out", str(self.sb.root / "out"))
                self.assertEqual(res.returncode, 42, res.stderr)


# --------------------------------------------------------------------------- render


def read_tree(d: Path) -> dict[str, str]:
    return {str(p.relative_to(d)): p.read_text() for p in sorted(d.rglob("*")) if p.is_file()}


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.rel = self.sb.release(fixture_egress(), version="1.4.0")

    def tearDown(self):
        self.sb.cleanup()

    def render(self, mode: str) -> Path:
        self.sb.set_mode(mode)
        out = self.sb.root / f"out-{mode}"
        res = self.sb.run("render", "--release-dir", str(self.rel), "--out", str(out), "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        return out

    def test_golden(self):
        """Render ACLs and nft from the reference release; compare with golden files."""
        for mode in ("observe", "enforce"):
            out = self.render(mode)
            tree = read_tree(out)
            golden_dir = GOLDEN / mode
            if os.environ.get("UPDATE_GOLDEN") == "1":
                shutil.rmtree(golden_dir, ignore_errors=True)
                for rel, text in tree.items():
                    (golden_dir / rel).parent.mkdir(parents=True, exist_ok=True)
                    (golden_dir / rel).write_text(text.replace(str(self.sb.root), "@SANDBOX@"))
                continue
            expected = read_tree(golden_dir)
            self.assertEqual(sorted(tree), sorted(expected), f"{mode}: file set differs")
            for rel in tree:
                text = tree[rel].replace(str(self.sb.root), "@SANDBOX@")
                self.assertEqual(text, expected[rel], f"{mode}/{rel} differs from golden")
        if os.environ.get("UPDATE_GOLDEN") == "1":
            self.fail("golden files rewritten; review the diff and rerun without UPDATE_GOLDEN")

    def test_roles_and_features(self):
        out = self.render("enforce")
        app = (out / "proxy/app/acl.yaml").read_text()
        self.assertIn('"api.resend.com"', app)
        self.assertNotIn("anthropic", app)
        self.assertIn("action: enforce", app)
        self.assertIn("allowed_domains: []", (out / "proxy/functions/acl.yaml").read_text())
        self.assertIn('"api.pwnedpasswords.com"', (out / "proxy/auth/acl.yaml").read_text())
        host = (out / "proxy/host/acl.yaml").read_text()
        for name in ("updates.legatto.pl", "status.legatto-example.example", "acme-v02.api.letsencrypt.org"):
            self.assertIn(f'"{name}"', host)
        intake = (out / "proxy/intake/acl.yaml").read_text()
        self.assertIn('"legatto-example.example"', intake, "office entry (site selftest)")
        nft = (out / "egress.nft").read_text()
        self.assertNotIn("172.30.255.4", nft.split("# egress-fn")[0] if "# egress-fn" in nft else nft)
        self.assertIn("egress-fn (functions): empty allowlist, no uplink", nft)
        self.assertIn('ip saddr 172.30.255.2 tcp dport { 443 } accept', nft)
        self.assertIn("meta skuid 990 tcp dport { 80, 443 } accept", nft)
        cfg = (out / "proxy/app/smokescreen.yaml").read_text()
        self.assertIn('resolver_addresses: ["9.9.9.9:53"]', cfg)
        self.assertIn('acl_file: "/etc/smokescreen/acl.yaml"', cfg)

        self.sb.set_features({"push": True, "ics": True, "getresponse": True, "hibp": False},
                             ["calendar.example.org"])
        out = self.render("enforce")
        app = (out / "proxy/app/acl.yaml").read_text()
        for name in ("fcm.googleapis.com", "*.push.apple.com", "calendar.example.org", "api.getresponse.com"):
            self.assertIn(f'"{name}"', app)
        self.assertIn('"api.getresponse.com"', (out / "proxy/functions/acl.yaml").read_text())
        self.assertIn("allowed_domains: []", (out / "proxy/auth/acl.yaml").read_text())
        nft = (out / "egress.nft").read_text()
        self.assertIn("ip saddr 172.30.255.4 tcp dport { 443 } accept", nft)
        self.assertNotIn("ip saddr 172.30.255.3 tcp", nft)
        allow = json.loads((out / "allowlist.json").read_text())
        self.assertEqual(allow["features_active"], ["getresponse", "push", "ics"])
        self.assertNotIn("auth", allow["roles_active"])

    def test_check(self):
        out = self.render("observe")
        res = self.sb.run("check", "--dir", str(out))
        self.assertEqual(res.returncode, 0, res.stderr)
        acl = out / "proxy/app/acl.yaml"
        acl.write_text(acl.read_text().replace("api.resend.com", "evil.example.org"))
        self.assertEqual(self.sb.run("check", "--dir", str(out)).returncode, 42)
        out = self.render("observe")
        nft = out / "egress.nft"
        nft.write_text(nft.read_text() + "\nbroken {\n")
        self.assertEqual(self.sb.run("check", "--dir", str(out)).returncode, 42)

    def test_export_for_e2e(self):
        """Rendered trees for the Smokescreen end-to-end test in run.sh."""
        for mode in ("observe", "enforce"):
            out = self.render(mode)
            dst = WORK / "e2e" / mode
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(out, dst)
        (WORK / "e2e" / "proxy_dir").write_text(self.sb.cfg["paths"]["proxy_dir"])


# --------------------------------------------------------------------------- diff


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.old = self.sb.release(fixture_egress(), "1.4.0")

    def tearDown(self):
        self.sb.cleanup()

    def diff(self, egress: dict, old: Path | None = None) -> tuple[int, dict]:
        new = self.sb.release(egress, "1.5.0")
        res = self.sb.run("diff", "--from", str(old or self.old), "--to", str(new), "--json")
        out = json.loads(res.stdout) if res.stdout.strip() else {}
        return res.returncode, out

    def test_identical(self):
        rc, out = self.diff(fixture_egress())
        self.assertEqual(rc, 0)
        self.assertFalse(out["widening"])
        self.assertEqual((out["added"], out["removed"], out["pinned_removed"]), ([], [], []))

    def test_widening_cases(self):
        def add_host(eg):
            eg["roles"]["app"].append({"host": "api.example.org", "port": 443, "purpose": "new host"})

        def add_port(eg):
            eg["roles"]["host"].append({"host": "updates.legatto.pl", "port": 80, "purpose": "same host, port 80"})

        def add_role(eg):
            eg["roles"]["functions"] = [{"host": "api.resend.com", "port": 443, "purpose": "new role"}]

        def wildcard(eg):
            eg["roles"]["app"] = [{"host": "*.mail.resend.com", "port": 443, "purpose": "wildcard"}]

        def disabled_feature(eg):
            eg["features"]["ai"]["app"].append({"host": "files.anthropic.com", "port": 443, "purpose": "x"})

        def feature_to_base(eg):
            eg["roles"]["app"].append({"host": "api.anthropic.com", "port": 443, "purpose": "now always on"})

        for name, change in {"host": add_host, "port": add_port, "role": add_role, "wildcard": wildcard,
                             "disabled feature": disabled_feature, "feature to base": feature_to_base}.items():
            with self.subTest(case=name):
                eg = fixture_egress()
                change(eg)
                rc, out = self.diff(eg)
                self.assertEqual(rc, 40, f"{name}: {out}")
                self.assertTrue(out["widening"])
                self.assertTrue(out["widening_entries"])
        eg = fixture_egress()
        disabled_feature(eg)
        _, out = self.diff(eg)
        self.assertFalse(out["added"][0]["active"], "ai is disabled by default")

    def test_not_widening(self):
        eg = fixture_egress()
        eg["roles"]["app"] = []
        eg["features"]["push"]["app"].pop()
        rc, out = self.diff(eg)
        self.assertEqual(rc, 0, out)
        self.assertFalse(out["widening"])
        self.assertEqual({(r["host"], r["source"]) for r in out["removed"]},
                         {("api.resend.com", "base"), ("*.push.apple.com", "feature:push")})
        # A feature gaining an entry that is already always-on adds no reach.
        eg = fixture_egress()
        eg["features"]["hibp"]["app"] = [{"host": "api.resend.com", "port": 443, "purpose": "x"}]
        rc, out = self.diff(eg)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(out["added"]), 1)

    def test_pinned_removal(self):
        eg = fixture_egress()
        eg["roles"]["host"] = [e for e in eg["roles"]["host"] if e["host"] != "archive.ubuntu.com"]
        rc, out = self.diff(eg)
        self.assertEqual(rc, 41, out)
        self.assertEqual([e["host"] for e in out["pinned_removed"]], ["archive.ubuntu.com"])

    def test_ip_entry_rejected(self):
        eg = fixture_egress()
        eg["roles"]["app"].append({"host": "203.0.113.7", "port": 443, "purpose": "ip"})
        rc, _ = self.diff(eg)
        self.assertEqual(rc, 42)

    def test_from_none(self):
        new = self.sb.release(fixture_egress(), "1.5.0")
        for old in ("none", str(self.sb.root / "missing")):
            res = self.sb.run("diff", "--from", old, "--to", str(new), "--json")
            self.assertEqual(res.returncode, 40)


# --------------------------------------------------------------------------- apply / nft


class ApplyTests(unittest.TestCase):
    def setUp(self):
        load_base_table()
        self.sb = Sandbox("observe")
        self.rel = self.sb.release(fixture_egress(), "1.4.0")

    def tearDown(self):
        self.sb.cleanup()

    def apply(self, *extra: str) -> subprocess.CompletedProcess:
        return self.sb.run("apply", "--release-dir", str(self.rel), "--json", *extra)

    def applied(self, *extra: str) -> subprocess.CompletedProcess:
        res = self.apply(*extra)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res

    def rules(self, chain: str) -> list[dict]:
        out = json.loads(sh("nft", "-j", "list", "chain", "inet", "legatto", chain).stdout)
        return [i["rule"] for i in out["nftables"] if "rule" in i]

    def test_apply_observe_then_enforce(self):
        res = self.apply("--actor", '{"kind":"vendor","id":"v-test"}')
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout)
        self.assertEqual(out["release"], "1.4.0")
        n_out, n_fwd = len(self.rules("egress_out")), len(self.rules("egress_fwd"))
        self.assertGreater(n_out, 10)
        self.assertIn("accept", json.dumps(self.rules("egress_out")[-1]["expr"][-1]))
        status = json.loads((Path(self.sb.cfg["paths"]["status_dir"]) / "egress.json").read_text())
        self.assertEqual((status["component"], status["mode"], status["release"]), ("egress", "observe", "1.4.0"))
        st = os.stat(Path(self.sb.cfg["paths"]["status_dir"]) / "egress.json")
        self.assertEqual((oct(st.st_mode & 0o777), st.st_gid), ("0o640", TEST_GROUPS["legatto-status"]))
        audit = [json.loads(line) for line in self.sb.audit_log.read_text().splitlines()]
        self.assertEqual(audit[-1][:5], ["append", "--cat", "egress", "--event", "egress.applied"])
        self.assertEqual(json.loads(audit[-1][6]), {"kind": "vendor", "id": "v-test"})
        proxy_dir = Path(self.sb.cfg["paths"]["proxy_dir"])
        self.assertTrue((proxy_dir / "app/acl.yaml").is_file())
        self.assertEqual(oct((proxy_dir / "app/acl.yaml").stat().st_mode & 0o777), "0o644")

        # Re-apply: same rules, counters kept, nothing duplicated.
        before = counters()
        self.applied()
        self.assertEqual((len(self.rules("egress_out")), len(self.rules("egress_fwd"))), (n_out, n_fwd))
        self.assertEqual(set(counters()), set(before))

        self.sb.set_mode("enforce")
        res = self.apply()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("drop", json.dumps(self.rules("egress_out")[-1]["expr"][-1]))
        self.assertIn("drop", json.dumps(self.rules("egress_fwd")[-1]["expr"][-1]))
        self.assertIn("action: enforce", (proxy_dir / "host/acl.yaml").read_text())

    def test_enforce_per_user(self):
        self.sb.set_mode("enforce")
        self.applied()
        uid = {n: int(sh("id", "-u", n).stdout) for n in ("nobody", "_apt", "smokescreen", "legatto-mon")}
        listener = Listener("127.0.0.1", 4750)
        try:
            c0 = counters()
            self.assertTrue(connect("127.0.0.1", 4750, uid["_apt"]), "_apt is a host proxy client")
            self.assertTrue(connect("127.0.0.1", 4750, uid["legatto-mon"]), "legatto-mon is a client")
            self.assertFalse(connect("127.0.0.1", 4750, uid["nobody"]), "nobody is not a client")
            self.assertGreater(counters()["egress_denied_proxy_port"], c0["egress_denied_proxy_port"])
        finally:
            listener.close()
        if not TARGET_IP:
            self.skipTest("TARGET_IP not set")
        c0 = counters()
        self.assertTrue(connect(TARGET_IP, 443, uid["smokescreen"]), "proxy uplink on 443")
        self.assertFalse(connect(TARGET_IP, 8080, uid["smokescreen"]), "proxy uplink only on allowlist ports")
        self.assertFalse(connect(TARGET_IP, 443, uid["nobody"]), "other users have no direct egress")
        self.assertFalse(connect(TARGET_IP, 443, 0), "root has no direct egress either")
        self.assertGreaterEqual(counters()["egress_denied_host"] - c0["egress_denied_host"], 3)

    def test_observe_logs_without_blocking(self):
        self.applied()
        if not TARGET_IP:
            self.skipTest("TARGET_IP not set")
        c0 = counters()["egress_denied_host"]
        self.assertTrue(connect(TARGET_IP, 443, int(sh("id", "-u", "nobody").stdout)))
        self.assertGreater(counters()["egress_denied_host"], c0)

    def test_status_counts_denials_without_names(self):
        self.sb.set_mode("enforce")
        self.applied()
        res = self.sb.run("status", "--write", "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        for _ in range(3):
            connect("127.0.0.1", 4750, int(sh("id", "-u", "nobody").stdout), timeout=0.5)
        res = self.sb.run("status", "--write", "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        status = json.loads(res.stdout)
        self.assertGreaterEqual(status["denied_5m"], 3)
        self.assertEqual(set(status) >= {"v", "component", "ts", "ok", "mode", "release", "denied_5m",
                                         "last_apply_at"}, True)
        denied = [json.loads(line) for line in self.sb.audit_log.read_text().splitlines()
                  if "egress.denied" in line]
        self.assertEqual(len(denied), 1)
        params = json.loads(denied[0][denied[0].index("--params") + 1])
        self.assertGreaterEqual(params["count"], 3)
        self.assertNotIn(".", "".join(params["by_source"]), "no host names in the audit entry")

    def test_failures(self):
        lock = Path(self.sb.cfg["paths"]["lock"])
        lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            self.assertEqual(self.apply().returncode, 3, "lock held by another instance")
        finally:
            os.close(fd)
        self.assertEqual(self.sb.run("apply", "--release-dir", str(self.rel), user=65534).returncode, 4)
        bad = copy.deepcopy(fixture_egress())
        bad["roles"]["app"].append({"host": "198.51.100.1", "port": 443, "purpose": "ip"})
        self.rel = self.sb.release(bad)
        self.assertEqual(self.apply().returncode, 42)
        sh("nft", "delete", "table", "inet", "legatto")
        self.rel = self.sb.release(fixture_egress())
        self.assertEqual(self.apply().returncode, 4, "firewall table missing")

    def test_selftest_reports_each_check(self):
        """No systemd/docker here: the checks that need them fail, nft checks pass."""
        self.sb.set_mode("enforce")
        self.applied()
        res = self.sb.run("selftest", "--json")
        self.assertEqual(res.returncode, 43, res.stderr)
        out = json.loads(res.stdout)
        self.assertEqual(sorted(out["checks"], key=lambda k: int(k[1:])), [f"E{i}" for i in range(1, 11)])
        self.assertTrue(out["checks"]["E1"]["ok"], out["checks"]["E1"])
        self.assertTrue(out["checks"]["E5"]["ok"], out["checks"]["E5"])
        self.assertTrue(out["checks"]["E6"]["ok"], out["checks"]["E6"])
        self.assertFalse(out["checks"]["E2"]["ok"], "no host proxy runs in the test container")
        self.assertFalse(out["ok"])
        self.assertEqual(self.sb.run("selftest", user=65534).returncode, 4)

    def test_bootstrap_without_release(self):
        res = self.sb.run("apply", "--release-dir", str(self.sb.root / "no-current"), "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout)
        self.assertIsNone(out["release"])
        host = (Path(self.sb.cfg["paths"]["proxy_dir"]) / "host/acl.yaml").read_text()
        self.assertIn('"updates.legatto.pl"', host, "pinned entries work before the first release")
        self.assertEqual(out["roles_active"], ["host", "intake", "publish"])


# --------------------------------------------------------------------------- contract


class ContractTests(unittest.TestCase):
    def test_config_matches_contract(self):
        contract = json.loads((WORK / "contract.json").read_text())
        cfg = json.loads((ROLE_OUT / "config.json").read_text())
        self.assertEqual(cfg["host_proxy"]["port"], contract["legatto_ports"]["local"]["egress_proxy"])
        self.assertEqual(f"http://{cfg['host_proxy']['listen']}:{cfg['host_proxy']['port']}",
                         contract["legatto_egress_proxy_url_host"])
        self.assertEqual(cfg["host_proxy"]["clients"], contract["legatto_egress_host_proxy_clients"])
        self.assertEqual(cfg["host_proxy"]["unit"], contract["legatto_units"]["egress_proxy"])
        self.assertEqual(cfg["host_proxy"]["user"], contract["legatto_users"]["egress_proxy"]["name"])
        self.assertEqual(cfg["roles"], contract["legatto_egress_roles"])
        self.assertEqual(cfg["modes"], contract["legatto_egress_modes"])
        self.assertEqual(cfg["feature_names"], contract["legatto_feature_names"])
        self.assertEqual(cfg["dns_blackhole"], contract["legatto_ip_host_net"]["dns_blackhole"])
        nets = contract["legatto_docker_networks"]
        self.assertEqual(cfg["nft"]["egress_ext_bridge"], nets["egress_ext"]["bridge"])
        for role, proxy in contract["legatto_egress_container_proxies"].items():
            self.assertEqual(cfg["container_proxies"][role]["ext_ip"], proxy["ext_ip"])
            self.assertIn(ipaddress.ip_address(proxy["ext_ip"]),
                          ipaddress.ip_network(nets["egress_ext"]["subnet"]))
        paths = contract["legatto_paths"]
        self.assertEqual(cfg["paths"]["pinned"], paths["egress_pinned"])
        self.assertEqual(cfg["paths"]["features"], paths["features"])
        self.assertEqual(cfg["paths"]["status_dir"], paths["status"])
        # Constant in the tool with a "# contract:" comment.
        src = TOOL.read_text()
        self.assertIn(f'DEFAULT_CONFIG = "{paths["egress_etc"]}/config.json"', src)
        self.assertIn("# contract: legatto_paths.egress_etc", src)
        roles = ", ".join(f'"{r}"' for r in contract["legatto_egress_roles"])
        self.assertIn(f"CONTRACT_ROLES = ({roles})  # contract: legatto_egress_roles", src)
        feats = ", ".join(f'"{f}"' for f in contract["legatto_feature_names"])
        self.assertIn(f"CONTRACT_FEATURES = ({feats})  # contract: legatto_feature_names", src)
        pinned = json.loads((ROLE_OUT / "pinned.json").read_text())["entries"]
        self.assertEqual(len(pinned), len(contract["legatto_egress_pinned"]))


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("tests/egress/test_egress.py must run as root inside the test container")
    ensure_accounts()
    unittest.main(verbosity=2)
