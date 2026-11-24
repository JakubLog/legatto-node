#!/usr/bin/python3
"""Platform lane tests that need root on Ubuntu 24.04 (run by tests/platform/run.sh in the
test image as root, linux/amd64). Mounts: the legatto-node checkout (ro; the repository
root is derived from this file's path), /work (rw).

Covers legatto-secrets (init/check/render, real paths and permissions), legatto-acme
(install/status), legatto-stack argument handling and the cron call, and
`systemd-analyze verify` of the release units in bundle/systemd. The helpers (stub
upstreams, certificates, unit verification) are also used by the private deployment
tooling for the units and the Caddyfile its roles render.
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = "/work"
SBIN = REPO + "/sbin"
SECRETS = SBIN + "/legatto-secrets"
STACK = SBIN + "/legatto-stack"
ACME = SBIN + "/legatto-acme"
FIXTURES = REPO + "/tests/platform/fixtures"
OFFICE = {}
for _line in open(FIXTURES + "/office.env", encoding="utf-8"):
    _k, _, _v = _line.rstrip("\n").partition("=")
    OFFICE[_k] = _v
CRM = OFFICE["LEGATTO_HOST_CRM"]
ADMIN = OFFICE["LEGATTO_HOST_ADMIN"]
TS4 = OFFICE["LEGATTO_TS_IP4"]
TS6 = OFFICE["LEGATTO_TS_IP6"]


def run(argv, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(argv, **kw)


def ensure_group(name, gid=None):
    if run(["getent", "group", name]).returncode != 0:
        argv = ["groupadd", "--system"] + (["--gid", str(gid)] if gid else []) + [name]
        subprocess.run(argv, check=True)


def b64url_decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def make_cert(directory, names, ca=None, days=90):
    """Self-signed (ca=None) or CA-signed EC certificate; returns (crt, key)."""
    os.makedirs(directory, exist_ok=True)
    key, crt = os.path.join(directory, "leaf.key"), os.path.join(directory, "leaf.crt")
    san = "subjectAltName=" + ",".join("DNS:" + n for n in names)
    if ca is None:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", str(days), "-subj", "/CN=" + names[0], "-addext", san,
                        "-keyout", key, "-out", crt], check=True, capture_output=True)
    else:
        csr = os.path.join(directory, "leaf.csr")
        ext = os.path.join(directory, "ext.cnf")
        with open(ext, "w") as fh:
            fh.write(san + "\n")
        subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-subj", "/CN=" + names[0], "-keyout", key, "-out", csr], check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca[0], "-CAkey", ca[1], "-CAcreateserial",
                        "-days", str(days), "-extfile", ext, "-out", crt], check=True, capture_output=True)
    return crt, key


def make_ca(directory):
    os.makedirs(directory, exist_ok=True)
    key, crt = os.path.join(directory, "ca.key"), os.path.join(directory, "ca.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "30", "-subj", "/CN=Legatto Test CA", "-keyout", key, "-out", crt],
                   check=True, capture_output=True)
    return crt, key


# --- legatto-secrets ------------------------------------------------------------------------

class T1Secrets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs("/etc/legatto/secrets", mode=0o700, exist_ok=True)
        os.makedirs("/var/lib/legatto/office", exist_ok=True)
        shutil.copy(FIXTURES + "/office.env", "/etc/legatto/office.env")

    def test_1_init_creates_every_secret_once(self):
        proc = run([SECRETS, "init", "--json"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        created = json.loads(proc.stdout)["created"]
        self.assertIn("pgsodium_root.key", created)
        self.assertIn("anon_key", created)
        for name in os.listdir("/etc/legatto/secrets"):
            st = os.stat(os.path.join("/etc/legatto/secrets", name))
            self.assertEqual((st.st_uid, st.st_mode & 0o777), (0, 0o400), name)
        again = run([SECRETS, "init", "--json"])
        self.assertEqual(json.loads(again.stdout)["created"], [], "init must never overwrite")
        self.assertNotIn(open("/etc/legatto/secrets/jwt_secret").read(), proc.stdout + proc.stderr)

    def test_2_check_and_jwt(self):
        proc = run([SECRETS, "check", "--json"])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertTrue(doc["ok"])
        secret = open("/etc/legatto/secrets/jwt_secret").read()
        for name, role in (("anon_key", "anon"), ("service_role_key", "service_role")):
            header, payload, sig = open("/etc/legatto/secrets/" + name).read().split(".")
            expected = hmac.new(secret.encode(), (header + "." + payload).encode(), hashlib.sha256).digest()
            self.assertEqual(b64url_decode(sig), expected)
            claims = json.loads(b64url_decode(payload))
            self.assertEqual((claims["role"], claims["iss"]), (role, "supabase"))
            self.assertGreater(claims["exp"], time.time() + 9 * 365 * 86400)
        self.assertRegex(open("/etc/legatto/secrets/auth_hook_secret").read(), r"^v1,whsec_[A-Za-z0-9+/]{43}=$")
        self.assertEqual(len(base64.b64decode(open("/etc/legatto/secrets/auth_hook_secret").read()[9:])), 32)
        self.assertRegex(open("/etc/legatto/secrets/pgsodium_root.key").read(), r"^[0-9a-f]{64}$")
        self.assertEqual(len(open("/etc/legatto/secrets/realtime_db_enc_key").read()), 16)

    def test_3_check_detects_problems(self):
        path = "/etc/legatto/secrets/cron_secret"
        os.chmod(path, 0o644)
        try:
            proc = run([SECRETS, "check", "--json"])
            self.assertEqual(proc.returncode, 31)
            self.assertIn("permissions:cron_secret", json.loads(proc.stdout)["errors"])
        finally:
            os.chmod(path, 0o400)
        os.rename("/etc/legatto/secrets/jwt_secret", "/tmp/jwt_secret")
        try:
            self.assertEqual(run([SECRETS, "init"]).returncode, 4, "must not mint a new jwt_secret under old keys")
        finally:
            os.rename("/tmp/jwt_secret", "/etc/legatto/secrets/jwt_secret")


class T2Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shutil.copy(FIXTURES + "/features.json", "/var/lib/legatto/office/features.json")
        os.makedirs("/run/legatto/env", exist_ok=True)
        open("/run/legatto/env/stale.env", "w").close()
        cls.proc = run([SECRETS, "render", "--templates", REPO + "/bundle/env", "--json"])
        # Rendered env files for the host-side compose checks (test secrets only).
        os.makedirs(WORK + "/env", exist_ok=True)
        for name in os.listdir("/run/legatto/env"):
            shutil.copy("/run/legatto/env/" + name, WORK + "/env/" + name)
            os.chmod(WORK + "/env/" + name, 0o644)

    def env(self, name):
        values = {}
        for line in open("/run/legatto/env/" + name, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            key, _, value = line.rstrip("\n").partition("=")
            values[key] = value
        return values

    def test_render_writes_private_files(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stderr)
        written = json.loads(self.proc.stdout)["written"]
        self.assertEqual(sorted(written), ["app.env", "auth.env", "compose.env", "functions.env", "migrator.env"])
        self.assertFalse(os.path.exists("/run/legatto/env/stale.env"))
        self.assertEqual(os.stat("/run/legatto/env").st_mode & 0o777, 0o700)
        for name in written:
            st = os.stat("/run/legatto/env/" + name)
            self.assertEqual((st.st_uid, st.st_mode & 0o777), (0, 0o400))
            self.assertNotIn("${", open("/run/legatto/env/" + name).read(), name)
        st = os.stat("/run/legatto/keys/pii_field_key")
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (65532, 65532, 0o400))
        self.assertEqual(os.stat("/run/legatto/keys").st_mode & 0o777, 0o711)
        self.assertEqual(open("/run/legatto/keys/pii_field_key").read(),
                         open("/etc/legatto/secrets/pii_field_key").read())
        self.assertNotIn(open("/etc/legatto/secrets/postgres_password").read(), self.proc.stdout + self.proc.stderr)

    def test_values(self):
        app, auth, compose = self.env("app.env"), self.env("auth.env"), self.env("compose.env")
        self.assertEqual(app["INSTANCE_MCP"], "on")
        self.assertEqual(app["INSTANCE_AI"], "off")
        self.assertEqual(app["INSTANCE_ICS"], "on")
        self.assertEqual(app["ICS_ALLOWED_HOSTS"], "calendar.example.org,ics.example.net")
        self.assertEqual(app["OAUTH_ISSUER"], "https://" + CRM)
        self.assertEqual(app["SUPABASE_ANON_KEY"], open("/etc/legatto/secrets/anon_key").read())
        self.assertEqual(auth["GOTRUE_PASSWORD_HIBP_ENABLED"], "false")
        self.assertEqual(auth["GOTRUE_HOOK_SEND_EMAIL_SECRETS"], open("/etc/legatto/secrets/auth_hook_secret").read())
        self.assertEqual(compose["LEGATTO_HOST_CRM"], CRM)
        # Values with quotes and "$" are double-quoted with \\ \" \$ escapes (compose dotenv dialect).
        self.assertEqual(app["APP_TITLE"], '"Biuro Poselskie \\"Przykład\\" \\$HOME (test)"')
        self.assertTrue(auth["GOTRUE_PASSWORD_REQUIRED_CHARACTERS"].startswith('"abc'))

    def test_check_rejects_bad_templates(self):
        bad = "/tmp/bad-templates"
        os.makedirs(bad, exist_ok=True)
        with open(bad + "/x.env.tmpl", "w") as fh:
            fh.write("A=${LEGATTO_NOPE}\nB=${secret:nope}\nnot a pair\nC=${feature:teleport}\nD=${unterminated\n"
                     "A=dup\n")
        open(bad + "/README", "w").close()
        proc = run([SECRETS, "render", "--check", "--json", "--templates", bad])
        self.assertEqual(proc.returncode, 42)
        errors = json.loads(proc.stdout)["errors"]
        self.assertEqual(len(errors), 7, errors)
        good = run([SECRETS, "render", "--check", "--templates", REPO + "/bundle/env"])
        self.assertEqual(good.returncode, 0, good.stderr)


# --- legatto-acme ---------------------------------------------------------------------------

class T3Acme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_group("caddy")
        ensure_group("legatto-status")
        os.makedirs("/var/lib/legatto/status", exist_ok=True)
        os.makedirs("/etc/caddy/certs", exist_ok=True)
        cls.names = [CRM, "*." + CRM]
        cls.ca = make_ca("/tmp/acme-ca")
        os.environ["LEGATTO_ACME_DOMAINS"] = ",".join(cls.names)

    def lego_cert(self, directory, names, ca):
        crt, key = make_cert(directory, names, ca=ca)
        os.makedirs("/var/lib/legatto-acme/certificates", exist_ok=True)
        shutil.copy(crt, "/var/lib/legatto-acme/certificates/app.crt")
        shutil.copy(key, "/var/lib/legatto-acme/certificates/app.key")
        return crt, key

    def tls(self):
        return json.load(open("/var/lib/legatto/status/tls.json"))

    def test_1_install_and_status(self):
        crt, _ = self.lego_cert("/tmp/acme-ok", self.names, self.ca)
        proc = run([ACME, "install"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(open("/etc/caddy/certs/app.crt").read(), open(crt).read())
        st = os.stat("/etc/caddy/certs/app.key")
        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (0, int(run(["getent", "group", "caddy"])
                                                                               .stdout.split(":")[2]), 0o640))
        self.assertEqual(run([ACME, "status"]).returncode, 0)
        doc = self.tls()
        self.assertEqual((doc["v"], doc["component"], doc["state"], doc["ok"]), (1, "tls", "ok", True))
        self.assertGreaterEqual(doc["days_left"], 88)
        self.assertRegex(doc["not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(os.stat("/var/lib/legatto/status/tls.json").st_mode & 0o777, 0o640)
        self.assertEqual(run([ACME, "install"]).stderr.strip(), "legatto-acme: certificate unchanged")

    def test_2_rejects_mismatch(self):
        before = open("/etc/caddy/certs/app.crt").read()
        crt, _ = make_cert("/tmp/acme-other", self.names, ca=self.ca)
        self.lego_cert("/tmp/acme-key", self.names, self.ca)
        shutil.copy(crt, "/var/lib/legatto-acme/certificates/app.crt")  # cert of another key
        self.assertEqual(run([ACME, "install"]).returncode, 21)
        self.lego_cert("/tmp/acme-names", [CRM], self.ca)  # wildcard missing
        self.assertEqual(run([ACME, "install"]).returncode, 21)
        self.assertEqual(open("/etc/caddy/certs/app.crt").read(), before)

    def test_3_status_fail_states(self):
        crt, key = make_cert("/tmp/acme-self", self.names)
        shutil.copy(crt, "/etc/caddy/certs/app.crt")
        shutil.copy(key, "/etc/caddy/certs/app.key")
        run([ACME, "status"])
        self.assertEqual(self.tls()["state"], "fail", "self-signed bootstrap certificate must alert")
        crt, key = make_cert("/tmp/acme-short", self.names, ca=self.ca, days=5)
        shutil.copy(crt, "/etc/caddy/certs/app.crt")
        run([ACME, "status"])
        self.assertEqual((self.tls()["state"], self.tls()["days_left"] <= 5), ("fail", True))
        crt, key = self.lego_cert("/tmp/acme-ok2", self.names, self.ca)
        shutil.copy(crt, "/etc/caddy/certs/app.crt")
        proc = run([ACME, "status"], env=dict(os.environ, SERVICE_RESULT="exit-code"))
        self.assertEqual((proc.returncode, self.tls()["state"]), (0, "fail"))

    def test_4_renew_preconditions(self):
        env = {"PATH": os.environ["PATH"]}
        self.assertEqual(run([ACME, "renew"], env=env).returncode, 4)
        self.assertEqual(run([ACME, "bogus"]).returncode, 2)


# --- legatto-stack ------------------------------------------------------------------------------

class Stub(http.server.BaseHTTPRequestHandler):
    name = "?"

    def do_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = json.dumps({"upstream": self.name, "path": self.path,
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        status = 503 if "fail" in self.path else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if "set-xfo" in self.path:
            self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_any

    def log_message(self, *args):
        pass


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class UnixStub(Stub):
    def address_string(self):
        return "unix"


def start_stub(name, address):
    handler = type("Stub_" + name.replace("-", "_"), (Stub,), {"name": name})
    if isinstance(address, str):
        if os.path.exists(address):
            os.unlink(address)
        handler = type("UStub_" + name, (UnixStub,), {"name": name})
        server = UnixServer(address, handler)
        os.chmod(address, 0o666)
    else:
        server = ThreadingServer(address, handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def add_addresses():
    for argv in (["ip", "addr", "add", TS4 + "/32", "dev", "lo"],
                 ["ip", "-6", "addr", "add", TS6 + "/128", "dev", "lo"],
                 ["ip", "addr", "add", "172.30.0.10/32", "dev", "lo"],
                 ["ip", "addr", "add", "172.30.0.11/32", "dev", "lo"]):
        proc = run(argv)
        if proc.returncode != 0 and "File exists" not in proc.stderr and "already assigned" not in proc.stderr:
            raise RuntimeError(" ".join(argv) + ": " + proc.stderr)


class T4Stack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        add_addresses()
        cls.app = start_stub("app", ("172.30.0.10", 3000))
        os.makedirs("/tmp/creds", exist_ok=True)
        with open("/tmp/creds/cron_secret", "w") as fh:
            fh.write("s3cret-token")

    def test_cron_sends_secret_from_credential(self):
        creds = "/tmp/creds"
        env = dict(os.environ, CREDENTIALS_DIRECTORY=creds)
        proc = run([STACK, "cron", "poliai-purge"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("cron poliai-purge: HTTP 200", proc.stderr)
        self.assertNotIn("s3cret-token", proc.stderr + proc.stdout)
        self.assertEqual(run([STACK, "cron", "fail-job"], env=env).returncode, 44)
        self.assertEqual(run([STACK, "cron", "../etc"], env=env).returncode, 2)
        self.assertEqual(run([STACK, "cron", "x"], env={"PATH": os.environ["PATH"]}).returncode, 4)

    def test_cron_authorization_header(self):
        seen = {}

        class Capture(Stub):
            def do_GET(self):
                seen["auth"] = self.headers.get("Authorization")
                seen["path"] = self.path
                Stub.do_any(self)

        srv = ThreadingServer(("172.30.0.10", 3005), Capture)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            code = ("import importlib.machinery,importlib.util,sys\n"
                    "l=importlib.machinery.SourceFileLoader('s', %r)\n"
                    "s=importlib.util.spec_from_loader('s', l); m=importlib.util.module_from_spec(s); l.exec_module(m)\n"
                    "m.APP_HTTP=('172.30.0.10', 3005)\n"
                    "sys.exit(m.main(['cron','sync-ics']))\n") % STACK
            env = dict(os.environ, CREDENTIALS_DIRECTORY="/tmp/creds")
            proc = run([sys.executable, "-c", code], env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual((seen["auth"], seen["path"]), ("Bearer s3cret-token", "/api/cron/sync-ics"))
        finally:
            srv.shutdown()

    def test_cli_validation(self):
        self.assertEqual(run([STACK, "probe", "--surface", "crm", "no-slash"]).returncode, 2)
        self.assertEqual(run([STACK, "probe", "--surface", "nope", "/"]).returncode, 2)
        self.assertEqual(run([STACK, "bogus"]).returncode, 2)
        self.assertEqual(run([STACK, "start", "db"]).returncode, 2, "no on-demand services")
        self.assertEqual(run([STACK, "stop", "studio"]).returncode, 2, "studio is not a stack service")


# --- systemd units ------------------------------------------------------------------------------

def install_tools(names):
    """Copy host tools from sbin/ to /opt/legatto/sbin, where the units execute them."""
    os.makedirs("/opt/legatto/sbin", exist_ok=True)
    for name in names:
        shutil.copy(os.path.join(SBIN, name), "/opt/legatto/sbin/" + name)


def stub_units(names):
    """Minimal units of other packages that the units under test order against."""
    for name in names:
        with open("/etc/systemd/system/" + name, "w") as fh:
            fh.write("[Service]\nExecStart=/bin/true\n")


def systemd_verify(directories):
    """Install every unit of the directories and `systemd-analyze verify` them (plus the
    legatto-cron@<job>.service instances of legatto-cron-<job>.timer); returns problems."""
    units = []
    for directory in directories:
        for name in sorted(os.listdir(directory)):
            shutil.copy(os.path.join(directory, name), "/etc/systemd/system/" + name)
            units.append("/etc/systemd/system/" + name)
            if name.startswith("legatto-cron-") and name.endswith(".timer"):
                job = name[len("legatto-cron-"):-len(".timer")]
                units.append("/etc/systemd/system/legatto-cron@%s.service" % job)
    proc = run(["systemd-analyze", "verify", "--man=no"] + units)
    return [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()
            # no running systemd/journald in the test container
            and "Failed to connect" not in line and "Transport endpoint" not in line]


class T5Units(unittest.TestCase):
    def test_systemd_analyze_verify(self):
        install_tools(("legatto-stack", "legatto-secrets"))
        stub_units(("docker.service",))
        problems = systemd_verify([REPO + "/bundle/systemd"])
        self.assertEqual(problems, [], "\n".join(problems))


if __name__ == "__main__":
    # unittest resets warning filters; fixtures are read with short open(...).read() calls.
    unittest.main(verbosity=2, warnings="ignore")
