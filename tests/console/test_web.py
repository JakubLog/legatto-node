"""The panel as deployed: legatto-console user, unix socket, Caddy headers, executor running as root."""

import http.client
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse

import harness
from harness import ADMIN_HOST, OFFICE_IP, STAFF_IP
from legatto_console import contract, crypto, web

PASSWORD = "correct horse battery"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=60)
        self.socket_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(60)
        sock.connect(self.socket_path)
        self.sock = sock


class Browser:
    def __init__(self, socket_path, ip=OFFICE_IP):
        self.socket_path = socket_path
        self.ip = ip
        self.cookies = {}

    def request(self, method, path, form=None, headers=None, raw_body=None):
        conn = UnixHTTPConnection(self.socket_path)
        hdrs = {"Host": ADMIN_HOST, "X-Forwarded-Host": ADMIN_HOST, "X-Forwarded-For": self.ip,
                "X-Forwarded-Proto": "https", "X-Legatto-Surface": "admin"}
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = raw_body
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(headers or {})
        hdrs = {k: v for k, v in hdrs.items() if v is not None}
        conn.request(method, path, body=body, headers=hdrs)
        response = conn.getresponse()
        content = response.read().decode("utf-8", "replace")
        for header in response.headers.get_all("Set-Cookie") or []:
            name, value = header.split(";", 1)[0].split("=", 1)
            if "Max-Age=0" in header:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        conn.close()
        return response.status, response.headers, content

    @staticmethod
    def csrf(html):
        match = re.search(r'name="csrf" value="([^"]+)"', html)
        return match.group(1) if match else ""


class PanelCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not harness.IS_ROOT:
            raise unittest.SkipTest("needs root (run through tests/console/run.sh)")

    def setUp(self):
        self.tree = harness.ServerTree()
        self.tree.add_user("szef", PASSWORD)
        self.tree.add_user("anna", PASSWORD)
        self.sockdir = tempfile.mkdtemp(prefix="legatto-console-sock-")
        os.chown(self.sockdir, self.tree.uid, self.tree.gid)
        self.socket_path = os.path.join(self.sockdir, "office-console.sock")
        env = dict(os.environ, LEGATTO_CONSOLE_PREFIX=self.tree.root)
        self.panel = subprocess.Popen(
            ["setpriv", "--reuid", contract.CONSOLE_USER, "--regid", contract.CONSOLE_GROUP, "--init-groups",
             "python3", "-I", "-B", os.path.join(harness.CONSOLE_SRC, "bin", "legatto-console"), "serve",
             "--listen", self.socket_path], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 15
        while not os.path.exists(self.socket_path):
            if self.panel.poll() is not None or time.monotonic() > deadline:
                self.fail("panel did not start: " + self.panel.stderr.read().decode())
            time.sleep(0.05)
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.executor_loop, daemon=True)
        self.worker.start()

    def executor_loop(self):
        while not self.stop.is_set():
            try:
                self.tree.ex.process(once=True)
            except Exception as exc:  # noqa: BLE001 - surfaced through missing results
                print("executor:", exc)
            time.sleep(0.05)

    def tearDown(self):
        self.stop.set()
        self.worker.join(5)
        self.panel.terminate()
        self.panel.wait(10)
        self.panel.stdout.close()
        self.panel.stderr.close()
        self.tree.cleanup()

    def browser(self, ip=OFFICE_IP):
        return Browser(self.socket_path, ip)

    def login(self, browser, user="szef", password=PASSWORD, totp=None):
        status, _, html = browser.request("GET", "/console/logowanie")
        self.assertEqual(status, 200)
        self.tree.forget_step(user)
        return browser.request("POST", "/console/logowanie", form={
            "csrf": browser.csrf(html), "login": user, "password": password,
            "totp": totp or self.tree.totp(user)})

    def action(self, browser, path, form, user="szef"):
        status, _, html = browser.request("GET", "/console/")
        self.tree.forget_step(user)
        data = dict(form, csrf=browser.csrf(html), totp=self.tree.totp(user))
        return browser.request("POST", path, form=data)

    def follow(self, browser, location):
        return browser.request("GET", urllib.parse.urlsplit(location).path)

    def spool_count(self):
        return len(os.listdir(self.tree.p(contract.REQUESTS_ARCHIVE)))


class EntryChecks(PanelCase):
    def test_caddy_headers_host_and_tailnet_only(self):
        b = self.browser()
        self.assertEqual(b.request("GET", "/console/", headers={"Host": "app.legatto-example.example"})[0], 421)
        self.assertEqual(b.request("GET", "/console/", headers={"X-Forwarded-Host": "evil.example"})[0], 421)
        self.assertEqual(b.request("GET", "/console/", headers={"X-Legatto-Surface": None})[0], 403)
        self.assertEqual(b.request("GET", "/console/", headers={"X-Forwarded-For": "203.0.113.9"})[0], 403)
        self.assertEqual(b.request("GET", "/console/", headers={"X-Forwarded-For": None})[0], 403)
        status, headers, _ = b.request("GET", "/console")
        self.assertEqual((status, headers["Location"]), (308, "/console/"))
        status, headers, _ = b.request("GET", "/console/")
        self.assertEqual((status, headers["Location"]), (303, "/console/logowanie"))
        for name in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                     "Cache-Control"):
            self.assertIn(name, headers)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(b.request("PUT", "/console/")[0], 405)
        self.assertEqual(b.request("POST", "/console/logowanie", raw_body=b"x" * (web.MAX_BODY + 1),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})[0], 413)
        status, headers, css = b.request("GET", "/console/static/app.css")
        self.assertEqual((status, headers["Content-Type"]), (200, "text/css; charset=utf-8"))


class Login(PanelCase):
    def test_login_cookie_flags_and_session(self):
        b = self.browser()
        status, headers, html = b.request("GET", "/console/logowanie")
        pre = headers["Set-Cookie"]
        self.assertTrue(pre.startswith("__Host-lgc_pre="))
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, pre)
        status, headers, _ = self.login(b)
        self.assertEqual((status, headers["Location"]), (303, "/console/"), _)
        session_cookie = [c for c in headers.get_all("Set-Cookie") if c.startswith("__Host-lgc=")][0]
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, session_cookie)
        status, _, html = b.request("GET", "/console/")
        self.assertEqual(status, 200)
        self.assertIn("Status serwera", html)
        self.assertIn("console.login", json.dumps(self.tree.audit_entries()))

    def test_wrong_password_never_reaches_the_executor_and_is_throttled(self):
        b = self.browser()
        before = self.spool_count()
        status, _, html = self.login(b, password="wrong password!")
        self.assertEqual(status, 401)
        self.assertIn("Nieprawidłowy login, hasło lub kod TOTP", html)
        status, _, _ = self.login(b, user="nieistnieje", totp="123456")
        self.assertEqual(status, 401)
        self.assertEqual(self.spool_count(), before)
        for _ in range(web.LOGIN_FAIL_LIMIT):
            self.login(b, password="wrong password!")
        status, _, html = self.login(b)  # even the right password is refused while throttled
        self.assertEqual(status, 429)

    def test_wrong_totp_is_rejected_by_the_executor(self):
        b = self.browser()
        status, _, html = b.request("GET", "/console/logowanie")
        good = self.tree.totp("szef")
        bad = "000000" if good != "000000" else "111111"
        status, _, html = b.request("POST", "/console/logowanie", form={
            "csrf": b.csrf(html), "login": "szef", "password": PASSWORD, "totp": bad})
        self.assertEqual(status, 401)
        self.assertNotIn("__Host-lgc", b.cookies)
        self.assertIn("console.login_failed", json.dumps(self.tree.audit_entries()))

    def test_login_csrf_required(self):
        b = self.browser()
        b.request("GET", "/console/logowanie")
        status, _, _ = b.request("POST", "/console/logowanie", form={
            "csrf": "x" * 43, "login": "szef", "password": PASSWORD, "totp": self.tree.totp("szef")})
        self.assertEqual(status, 403)

    def test_session_bound_to_ip_and_logout(self):
        b = self.browser()
        self.login(b)
        moved = Browser(self.socket_path, STAFF_IP)
        moved.cookies = dict(b.cookies)
        self.assertEqual(moved.request("GET", "/console/")[0], 303)
        self.assertEqual(b.request("GET", "/console/")[0], 303)  # the session was dropped, not just refused
        self.login(b)
        _, _, html = b.request("GET", "/console/")
        token = b.cookies["__Host-lgc"]
        self.assertEqual(b.request("POST", "/console/wyloguj", form={"csrf": b.csrf(html)})[0], 303)
        b.cookies["__Host-lgc"] = token
        self.assertEqual(b.request("GET", "/console/")[0], 303)


class Actions(PanelCase):
    def test_csrf_and_origin_checks(self):
        b = self.browser()
        self.login(b)
        before = self.spool_count()
        self.tree.forget_step("szef")
        form = {"totp": self.tree.totp("szef")}
        self.assertEqual(b.request("POST", "/console/studio/wylacz", form=form)[0], 403)
        self.assertEqual(b.request("POST", "/console/studio/wylacz", form=dict(form, csrf="forged"))[0], 403)
        _, _, html = b.request("GET", "/console/")
        status, _, _ = b.request("POST", "/console/studio/wylacz", form=dict(form, csrf=b.csrf(html)),
                                 headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = b.request("POST", "/console/studio/wylacz", form=dict(form, csrf=b.csrf(html)),
                                 headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertEqual(self.spool_count(), before)
        status, headers, _ = self.action(b, "/console/studio/wylacz", {})
        self.assertEqual(status, 303)
        self.assertRegex(headers["Location"], r"^/console/zadania/[0-9A-Z]{26}$")
        status, _, html = self.follow(b, headers["Location"])
        self.assertEqual(status, 200)
        self.assertIn("Wykonano", html)

    def test_validation_errors_stay_in_the_panel(self):
        b = self.browser()
        self.login(b)
        before = self.spool_count()
        status, headers, _ = self.action(b, "/console/dostep/otworz", {"hours": "2", "reason": "krótko"})
        self.assertEqual((status, headers["Location"]), (303, "/console/dostep"))
        _, _, html = b.request("GET", "/console/dostep")
        self.assertIn("musi mieć od 10 do 500 znaków", html)
        self.assertEqual(self.spool_count(), before)

    def test_breakglass_from_the_panel(self):
        self.tree.fake(contract.CLI_BREAKGLASS, {"enable": {"rc": 0, "stdout": {
            "window_id": "w1", "started_at": "2026-11-21T10:00:00Z", "expires_at": "2026-11-21T12:00:00Z",
            "policy_asserted": True}}})
        b = self.browser()
        self.login(b)
        status, headers, _ = self.action(b, "/console/dostep/otworz", {
            "hours": "3", "reason": "Prośba dostawcy:\r\n aktualizacja   ACL"})
        status, _, html = self.follow(b, headers["Location"])
        self.assertIn("Dostęp serwisowy otwarty", html)
        argv = self.tree.calls(contract.CLI_BREAKGLASS)[-1]["argv"]
        self.assertEqual(argv[:5], ["enable", "--hours", "3", "--reason", "Prośba dostawcy: aktualizacja ACL"])

    def test_result_pages_are_private_and_sensitive_data_expires(self):
        self.tree.fake(contract.CLI_TAILNET, {"enroll": {"rc": 0, "stdout": {
            "kind": "office-device", "user": None, "tags": ["tag:office-device"], "key": "hskey-auth-123",
            "expires_at": "2026-11-21T10:30:00Z", "login_server": "https://vpn.legatto-example.example"}}})
        b = self.browser()
        self.login(b)
        status, headers, _ = self.action(b, "/console/urzadzenia/dodaj", {"kind": "office-device", "login": ""})
        location = headers["Location"]
        status, _, html = self.follow(b, location)
        self.assertEqual(status, 200)
        self.assertIn("<svg", html)
        self.assertIn("hskey-auth-123", html)
        self.assertIn("tailscale up --login-server=https://vpn.legatto-example.example", html)
        other = self.browser()
        self.login(other, user="anna")
        status, _, html = self.follow(other, location)
        self.assertEqual(status, 404)
        self.assertNotIn("hskey-auth-123", html)
        self.tree.clock_offset = contract.SENSITIVE_RESULT_TTL_SECONDS + 1
        self.tree.ex.prune()
        self.tree.clock_offset = 0
        status, _, html = self.follow(b, location)
        self.assertNotIn("hskey-auth-123", html)

    def test_must_change_password_flow(self):
        self.tree.add_user("nowy", "haslo startowe 123", must_change=True)
        b = self.browser()
        status, headers, _ = self.login(b, user="nowy", password="haslo startowe 123")
        self.assertEqual(headers["Location"], "/console/haslo")
        self.assertEqual(b.request("GET", "/console/wydania")[2:] and b.request("GET", "/console/wydania")[0], 303)
        status, _, html = b.request("GET", "/console/haslo")
        self.tree.forget_step("nowy")
        status, headers, _ = b.request("POST", "/console/haslo", form={
            "csrf": b.csrf(html), "totp": self.tree.totp("nowy"), "current": "haslo startowe 123",
            "new": "moje nowe haslo 2026", "new2": "moje nowe haslo 2026"})
        status, _, html = self.follow(b, headers["Location"])
        self.assertIn("Hasło zmienione", html)
        self.assertEqual(b.request("GET", "/console/wydania")[0], 200)
        self.assertFalse(self.tree.ex.users_doc()["users"]["nowy"]["must_change"])

    def test_temporary_password_shown_once_to_the_admin(self):
        b = self.browser()
        self.login(b)
        status, headers, _ = self.action(b, "/console/konta/haslo-tymczasowe", {"login": "anna"})
        status, _, html = self.follow(b, headers["Location"])
        password = re.search(r'<p class="secret">([a-z2-9-]{29})</p>', html).group(1)
        stored = self.tree.ex.users_doc()["users"]["anna"]
        self.assertTrue(crypto.scrypt_verify(password, stored["password"]))
        self.assertTrue(stored["must_change"])

    def test_removed_account_loses_its_session(self):
        a = self.browser()
        self.login(a)
        anna = self.browser(STAFF_IP)
        self.login(anna, user="anna")
        self.assertEqual(anna.request("GET", "/console/")[0], 200)
        self.action(a, "/console/konta/usun", {"login": "anna"})
        self.assertEqual(anna.request("GET", "/console/")[0], 303)


class Pages(PanelCase):
    def write_status(self):
        t = self.tree
        sha = "c" * 64
        t.write_json(contract.STATUS_DIR + "/update.json", {
            "v": 1, "component": "update", "ts": "2026-11-21T10:00:00Z", "ok": True,
            "installed": {"version": "1.4.0", "sequence": 7, "manifest_sha256": "d" * 64,
                          "installed_at": "2026-11-20T01:00:00Z"},
            "channel": "stable", "sig": "ok", "upd": "pending", "auto_security": {"policy": True, "admin_optout": False},
            "last_check": {"ts": "2026-11-21T09:00:00Z", "ok": True, "index_sequence": 9,
                           "index_expires": "2026-12-20T00:00:00Z"},
            "pending": [{"version": "1.5.0", "sequence": 8, "type": "feature", "manifest_sha256": sha,
                         "state": "waiting-approval", "earliest_install_at": "2026-11-22T01:00:00Z",
                         "egress_widening": True, "changelog_url": "https://updates.legatto.pl/v1/notes/1.5.0"}]},
            mode=0o644)
        t.write_json(contract.UPDATE_PENDING + "/1.5.0.json", {
            "v": 1, "version": "1.5.0", "notes_md": "## Zmiany\n<script>alert(1)</script>",
            "signers": {"manifest": ["release-a@legatto.pl"]}, "verify": {"ok": True, "code": "ok", "detail": ""},
            "egress": {"widening": True, "added": [{"role": "app", "host": "api.example.com", "port": 443}],
                       "removed": []}, "advisories": [], "approval": None, "rejection": None}, mode=0o644)
        t.write_json(contract.STATUS_DIR + "/breakglass.json", {
            "v": 1, "component": "breakglass", "ts": "2026-11-21T10:00:00Z", "ok": True, "active": False})
        t.write_json(contract.STATUS_DIR + "/egress.json", {
            "v": 1, "component": "egress", "ts": "2026-11-21T10:00:00Z", "ok": True, "mode": "observe",
            "denied_5m": 3, "last_apply_at": "2026-11-21T09:00:00Z"})
        t.write_json(contract.BREAKGLASS_SUMMARIES + "/w1.json", {
            "v": 1, "window_id": "w1", "actor": {"kind": "office-admin", "id": "szef"}, "reason": "Aktualizacja",
            "started_at": "2026-11-20T10:00:00Z", "expires_at": "2026-11-20T12:00:00Z",
            "closed_at": "2026-11-20T11:00:00Z", "close_reason": "disabled",
            "ssh": {"logins": [{"ts": "2026-11-20T10:05:00Z", "user": "v-jan", "ip": "100.64.0.9",
                                "node": "v-jan-mac", "key_fp": "SHA256:abc"}], "logouts": 1, "fails": 0},
            "sudo": {"count": 1, "commands": [{"ts": "2026-11-20T10:06:00Z", "user": "v-jan",
                                               "command": "/usr/bin/systemctl status"}], "truncated": False},
            "admin_http": {"requests": 0, "paths": {}}, "ansible": [],
            "audit": {"from_seq": 10, "to_seq": 20, "head": "e" * 64, "chain_ok": True}}, mode=0o644)
        t.fake(contract.CLI_TAILNET, {"nodes": {"rc": 0, "stdout": {"nodes": [
            {"id": "1", "name": "srv", "user": "server", "tags": ["tag:server"], "ip4": "100.64.0.1",
             "ip6": "fd7a:115c:a1e0::1", "online": True, "last_seen": None, "expiry": None},
            {"id": "5", "name": "biuro-laptop", "user": "biuro", "tags": ["tag:office-device"], "ip4": "100.64.0.5",
             "ip6": "fd7a:115c:a1e0::5", "online": True, "last_seen": "2026-11-21T10:00:00Z", "expiry": None}]}}})
        t.fake(contract.CLI_STUDIO, {"status": {"rc": 0, "stdout": {"v": 1, "enabled": False, "running": False,
                                                                    "expires_at": None, "url": None, "actor": None}}})
        t.write_json(contract.STAFF_FILE, {"v": 1, "staff": ["anna.nowak"]})
        t.ex.refresh_snapshot()

    def test_every_page_renders(self):
        self.write_status()
        b = self.browser()
        self.login(b)
        expectations = {
            "/console/": ["Status serwera", "1.4.0", "podpis poprawny"],
            "/console/wydania": ["Wydanie 1.5.0", "api.example.com", "Zatwierdź wydanie", "&lt;script&gt;",
                                 "Wyłącz automatyczne poprawki"],
            "/console/dostep": ["Otwórz dostęp serwisowy", "Aktualizacja"],
            "/console/dostep/okno/w1": ["v-jan", "/usr/bin/systemctl status", "SHA256:abc"],
            "/console/funkcje": ["Asystent AI", "Kalendarze ICS", "obserwacja", "1.5.0"],
            "/console/urzadzenia": ["biuro-laptop", "anna.nowak", "Utwórz klucz rejestracji"],
            "/console/studio": ["Włącz Studio"],
            "/console/odzyskiwanie": ["Wygeneruj nowy pakiet"],
            "/console/kontakty": ["UODO", "Inspektor Ochrony Danych"],
            "/console/konta": ["szef", "anna", "Dodaj konto"],
            "/console/haslo": ["Obecne hasło"],
        }
        for path, needles in expectations.items():
            with self.subTest(path=path):
                status, _, html = b.request("GET", path)
                self.assertEqual(status, 200, html[:300])
                self.assertNotIn("<script>", html)
                for needle in needles:
                    self.assertIn(needle, html)
        self.assertEqual(b.request("GET", "/console/nie-ma")[0], 404)
        self.assertEqual(b.request("GET", "/console/dostep/okno/..%2F..%2Fetc")[0], 404)

    def test_releases_page_warns_when_installed_release_is_yanked(self):
        self.write_status()
        path = self.tree.p(contract.STATUS_DIR + "/update.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        b = self.browser()
        self.login(b)
        _status, _, html = b.request("GET", "/console/wydania")
        self.assertNotIn("zostało wycofane przez dostawcę", html)
        doc.update(upd="yanked", ok=False, yanked=True, yanked_reason="Błąd migracji <b>kontaktów</b>")
        self.tree.write_json(contract.STATUS_DIR + "/update.json", doc, mode=0o644)
        status, _, html = b.request("GET", "/console/wydania")
        self.assertEqual(status, 200, html[:300])
        self.assertIn("Zainstalowane wydanie 1.4.0 zostało wycofane przez dostawcę.", html)
        self.assertIn("Błąd migracji &lt;b&gt;kontaktów&lt;/b&gt;", html)
        self.assertIn("zainstalowane wydanie wycofane przez dostawcę", html)
        self.assertIn("Serwer nie wycofuje go sam", html)

    def test_approve_and_features_from_the_panel(self):
        self.write_status()
        self.tree.fake(contract.CLI_UPDATE, {"approve": {"rc": 0, "stdout": {"ok": True, "code": "approved",
                                                                              "message": "OK", "data": {}}}})
        b = self.browser()
        self.login(b)
        self.action(b, "/console/wydania/zatwierdz", {"release": "1.5.0", "manifest_sha256": "c" * 64,
                                                      "not_before": "2026-11-23T03:00"})
        argv = self.tree.calls(contract.CLI_UPDATE)[-1]["argv"]
        self.assertEqual(argv[:7], ["approve", "--release", "1.5.0", "--manifest-sha256", "c" * 64,
                                    "--not-before", "2026-11-23T02:00:00Z"])  # Warsaw (CET) -> UTC
        self.action(b, "/console/funkcje", {"feature": "ics", "enabled": "true",
                                            "ics_hosts": "Kalendarz.Example.pl\n\nsejm.example.pl\n"})
        doc = harness.store.read_json(self.tree.p(contract.FEATURES))
        self.assertEqual(doc["ics_hosts"], ["kalendarz.example.pl", "sejm.example.pl"])
        self.assertTrue(doc["features"]["ics"])


class Setup(PanelCase):
    def setUp(self):
        super().setUp()
        doc = self.tree.ex.users_doc()
        doc["users"] = {}
        self.tree.ex.save_users(doc)

    def test_first_account_from_the_office_device(self):
        code = self.tree.ex.setup_code({"kind": "vendor", "id": "v-jan"})["code"]
        b = self.browser()
        status, _, html = b.request("GET", "/console/logowanie")
        self.assertIn("Załóż pierwsze konto", html)
        status, _, html = b.request("GET", "/console/konfiguracja")
        self.assertEqual(status, 200)
        status, _, html = b.request("POST", "/console/konfiguracja", form={
            "csrf": b.csrf(html), "code": code.lower(), "login": "szef.biura", "display_name": "Szef Biura",
            "password": "bardzo dlugie haslo", "password2": "bardzo dlugie haslo"})
        self.assertEqual(status, 200, html[:500])
        self.assertIn("<svg", html)
        self.assertIn("otpauth", json.dumps(self.tree.result(re.search(r"<code>([0-9A-Z]{26})</code>", html).group(1))))
        self.assertEqual(b.request("GET", "/console/konfiguracja")[0], 303)  # configured now
        status, headers, _ = self.login(b, user="szef.biura", password="bardzo dlugie haslo")
        self.assertEqual((status, headers["Location"]), (303, "/console/"))


class SessionStore(unittest.TestCase):
    def test_idle_absolute_and_ip(self):
        now = [1_000_000.0]
        sessions = web.Sessions(lambda: now[0])
        token, _ = sessions.create("szef", "Szef", OFFICE_IP, False)
        self.assertIsNotNone(sessions.get(token, OFFICE_IP))
        now[0] += web.SESSION_IDLE_SECONDS - 1
        self.assertIsNotNone(sessions.get(token, OFFICE_IP))
        now[0] += web.SESSION_IDLE_SECONDS + 1
        self.assertIsNone(sessions.get(token, OFFICE_IP))
        token, _ = sessions.create("szef", "Szef", OFFICE_IP, False)
        for _ in range(int(web.SESSION_MAX_SECONDS / (web.SESSION_IDLE_SECONDS - 60)) + 1):
            now[0] += web.SESSION_IDLE_SECONDS - 60
            sessions.get(token, OFFICE_IP)
        self.assertIsNone(sessions.get(token, OFFICE_IP))
        token, _ = sessions.create("szef", "Szef", OFFICE_IP, False)
        self.assertIsNone(sessions.get(token, STAFF_IP))
        self.assertIsNone(sessions.get(token, OFFICE_IP))
        self.assertIsNone(sessions.get("x" * 200, OFFICE_IP))

    def test_tokens_are_stored_hashed(self):
        sessions = web.Sessions(time.time)
        token, _ = sessions.create("szef", "Szef", OFFICE_IP, False)
        self.assertNotIn(token, sessions.items)
        self.assertGreaterEqual(len(token), 43)


if __name__ == "__main__":
    unittest.main()
