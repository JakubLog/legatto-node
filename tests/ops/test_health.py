"""tests/ops: legatto-health (runs inside the tests/ops image, Python 3.12).

CONTRACT §6 (ops): `legatto-health --dry-run` keys ⊆ legatto_kuma_fields,
values match the Kuma field expressions, negative test with a name and an e-mail
in application logs and in status files; plus the down conditions and a
real push through a CONNECT proxy to a TLS endpoint.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import select
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from contract_util import kuma_expressions, load_contract  # noqa: E402

REPO = Path(os.environ.get("REPO", Path(__file__).resolve().parents[2]))
TOOL = REPO / "sbin/legatto-health"
PII = ("Kowalski", "jan.kowalski@example.pl", "@", "Nowak")
SERVICES = ["db", "auth", "rest", "realtime", "storage", "functions", "api-gw", "app",
            "egress-app", "egress-auth", "egress-fn", "egress-intake", "egress-publish"]


def ts(delta: timedelta = timedelta()) -> str:
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


class Sandbox:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "root"
        self.status = self.root / "var/lib/legatto/status"
        self.status.mkdir(parents=True)
        (self.root / "etc/legatto/update").mkdir(parents=True)
        (self.root / "proc").mkdir()
        (self.root / "proc/meminfo").write_text("MemTotal: 8000000 kB\nMemFree: 1000 kB\nMemAvailable: 4000000 kB\n")
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        self.calls = Path(self.tmp.name) / "journalctl.args"
        self.ps = Path(self.tmp.name) / "docker.ps"
        self.lines_file = Path(self.tmp.name) / "journal.lines"
        self.journal_lines = 3
        self._script("docker", f'[ "$1" = ps ] || exit 1\ncat "{self.ps}"\n')
        # The tool runs journalctl with a scrubbed environment: the count comes from a file.
        self._script("journalctl", f'printf "%s\\n" "$@" > "{self.calls}"\n'
                     f'n=$(cat "{self.lines_file}")\ni=0\nwhile [ "$i" -lt "$n" ]; do\n'
                     '  echo \'{"MESSAGE":"Błąd zapisu sprawy: Jan Kowalski <jan.kowalski@example.pl>",'
                     '"PRIORITY":"3"}\'\n  i=$((i+1))\ndone\n')
        self.set_containers({s: "healthy" for s in SERVICES})
        self.write_all_good()

    def _script(self, name: str, body: str) -> None:
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)

    def set_containers(self, states: dict[str, str]) -> None:
        lines = []
        for service, health in states.items():
            name = "supabase-edge-functions" if service == "functions" else f"legatto-{service}-1"
            state = "exited" if health == "exited" else "running"
            status = {"healthy": "Up 2 hours (healthy)", "unhealthy": "Up 2 hours (unhealthy)",
                      "none": "Up 2 hours", "exited": "Exited (1) 3 minutes ago"}[health]
            lines.append(f"{service}\tFalse\t{name}\t{state}\t{status}")
        lines.append("migrator\tTrue\tlegatto-migrator-run-1\texited\tExited (0)")
        self.ps.write_text("\n".join(lines) + "\n")

    def put(self, component: str, **fields) -> None:
        doc = {"v": 1, "component": component, "ts": ts(), "ok": True}
        doc.update(fields)
        (self.status / f"{component}.json").write_text(json.dumps(doc))

    def write_all_good(self) -> None:
        (self.root / "etc/legatto/update/policy.json").write_text(json.dumps({"channel": "stable"}))
        self.put("update", installed={"version": "1.5.0"}, channel="stable", sig="ok", upd="ok",
                 last_check={"ts": ts(), "ok": True, "ok_ts": ts(timedelta(minutes=30))})
        self.put("backup", pgdump={"state": "ok", "last_ok_at": ts(timedelta(hours=5)), "last_run_at": ts()},
                 hetzner_window="22-02")
        self.put("restore-test", state="ok", last_run_at=ts(timedelta(days=6)), duration_s=40, checks={})
        self.put("breakglass", active=False)
        self.put("audit", seq=1042, head="ab" * 32, verified_at=ts(), chain_ok=True)
        self.put("tls", days_left=61, state="ok")
        self.put("egress", mode="enforce", denied_5m=2)
        self.put("intake", last_ok_at=ts(timedelta(seconds=94)), backlog=0, failed=0, quarantined=0)
        self.put("publish", state="ok", last_ok_at=ts(timedelta(days=2)))

    def run(self, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        self.lines_file.write_text(str(self.journal_lines))
        full_env = {"PATH": f"{self.bin}:/usr/bin:/bin", "LEGATTO_ROOT": str(self.root)}
        full_env.update(env or {})
        return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True,
                              env=full_env, timeout=60)

    def dry(self) -> dict:
        proc = self.run("--dry-run")
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)


def parse_msg(msg: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in msg.split(" ")) if msg else {}


class HealthPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract(REPO)
        cls.fields = cls.contract["legatto_kuma_fields"]
        cls.expr = kuma_expressions(REPO)

    def setUp(self) -> None:
        self.box = Sandbox()
        self.addCleanup(self.box.tmp.cleanup)

    def assert_clean(self, payload: dict) -> dict[str, str]:
        self.assertIn(payload["status"], ("up", "down"))
        for word in PII:
            self.assertNotIn(word, payload["msg"])
        fields = parse_msg(payload["msg"])
        self.assertLessEqual(set(fields), set(self.fields), "keys outside legatto_kuma_fields")
        order = [k for k in self.fields if k in fields]
        self.assertEqual(list(fields), order, "keys out of contract order")
        for key, value in fields.items():
            if value != "ERR":
                self.assertRegex(value, self.expr[key], key)
        return fields

    def test_all_good_is_up_and_complete(self) -> None:
        payload = self.box.dry()
        fields = self.assert_clean(payload)
        self.assertEqual(payload["status"], "up", payload)
        self.assertEqual(set(fields), set(self.fields))
        self.assertEqual(fields["v"], "1.5.0")
        self.assertEqual(fields["sig"], "ok")
        self.assertEqual(fields["ch"], "stable")
        self.assertEqual(fields["bk"], "ok")
        self.assertEqual(fields["bk_age"], "5h")
        self.assertEqual(fields["rt"], "ok/6d")
        self.assertEqual(fields["ct"], "13/13")
        self.assertEqual(fields["ctbad"], "")
        self.assertEqual(fields["ahead"], "ab" * 8)
        self.assertEqual(fields["ram"], "50")
        self.assertNotIn("ERR", payload["msg"])

    def test_application_log_with_pii_only_counts(self) -> None:
        self.box.journal_lines = 7
        payload = self.box.dry()
        fields = self.assert_clean(payload)
        self.assertEqual(fields["err"], "7")
        args = self.box.calls.read_text().split("\n")
        self.assertIn("--output-fields=PRIORITY", args)
        self.assertIn("--priority=0..3", args)
        self.assertIn("CONTAINER_NAME=legatto-app-1", args)
        self.assertIn("CONTAINER_NAME=supabase-edge-functions", args)
        self.assertFalse(any("MESSAGE" in a for a in args))

    def test_pii_in_status_files_becomes_err(self) -> None:
        self.box.put("update", installed={"version": "Jan Kowalski <jan.kowalski@example.pl>"}, sig="ok", upd="ok",
                     last_check={"ok_ts": ts()})
        self.box.put("intake", last_ok_at=ts(), backlog="Nowak@example.pl", failed=0)
        self.box.put("egress", mode="enforce jan.kowalski@example.pl", denied_5m=1)
        self.box.put("audit", seq=5, head="Kowalski" * 8, chain_ok=True)
        payload = self.box.dry()
        fields = self.assert_clean(payload)
        for key in ("v", "in_q", "egress", "ahead"):
            self.assertEqual(fields[key], "ERR", key)

    def test_down_conditions(self) -> None:
        cases = [
            ("sig", lambda b: b.put("update", installed={"version": "1.5.0"}, sig="bad", upd="ok",
                                    last_check={"ok_ts": ts()})),
            ("upd", lambda b: b.put("update", installed={"version": "1.5.0"}, sig="ok", upd="rb",
                                    last_check={"ok_ts": ts()})),
            ("chk_age", lambda b: b.put("update", installed={"version": "1.5.0"}, sig="ok", upd="ok",
                                        last_check={"ok_ts": ts(timedelta(hours=25))})),
            ("chk_age", lambda b: b.put("update", installed={"version": "1.5.0"}, sig="ok", upd="ok",
                                        last_check={"ok_ts": None})),
            ("containers", lambda b: b.set_containers(dict({s: "healthy" for s in SERVICES}, app="unhealthy"))),
            ("containers", lambda b: b.set_containers({s: "healthy" for s in SERVICES if s != "db"})),
            ("backup", lambda b: b.put("backup", pgdump={"state": "ok", "last_ok_at": ts(timedelta(hours=27))},
                                       hetzner_window="22-02")),
            ("backup", lambda b: b.put("backup", pgdump={"state": "ok", "last_ok_at": ts()}, hetzner_window=None)),
            ("backup", lambda b: (b.status / "backup.json").unlink()),
            ("intake", lambda b: b.put("intake", last_ok_at=ts(timedelta(seconds=1000)), backlog=0, failed=0)),
            ("cert", lambda b: b.put("tls", days_left=13, state="ok")),
            ("audit", lambda b: b.put("audit", seq=9, head="cd" * 32, chain_ok=False)),
        ]
        for reason, mutate in cases:
            with self.subTest(reason=reason):
                box = Sandbox()
                self.addCleanup(box.tmp.cleanup)
                mutate(box)
                payload = box.dry()
                self.assert_clean(payload)
                self.assertEqual(payload["status"], "down", (reason, payload))
                proc = box.run("collect", "--json")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(reason, json.loads(proc.stdout)["reasons"])

    def test_unhealthy_service_is_named(self) -> None:
        self.box.set_containers(dict({s: "healthy" for s in SERVICES}, app="unhealthy", rest="exited"))
        fields = self.assert_clean(self.box.dry())
        self.assertEqual(fields["ctbad"], "rest,app")
        self.assertEqual(fields["ct"], "11/13")

    def test_on_demand_studio_counts_only_when_present(self) -> None:
        self.box.set_containers(dict({s: "healthy" for s in SERVICES}, studio="healthy", meta="healthy"))
        self.assertEqual(parse_msg(self.box.dry()["msg"])["ct"], "15/15")

    def test_uninstalled_components_are_omitted(self) -> None:
        for name in ("intake", "publish", "tls", "egress", "breakglass"):
            (self.box.status / f"{name}.json").unlink()
        fields = self.assert_clean(self.box.dry())
        for key in ("in_age", "in_q", "in_fail", "pub_age", "cert", "egress", "eg_deny", "bg"):
            self.assertNotIn(key, fields)

    def test_collect_writes_health_json(self) -> None:
        proc = self.box.run("collect")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads((self.box.status / "health.json").read_text())
        self.assertEqual(doc["component"], "health")
        self.assertEqual(doc["status"], "up")
        self.assertEqual(parse_msg(doc["msg"]), doc["fields"])
        self.assertEqual(stat.S_IMODE((self.box.status / "health.json").stat().st_mode), 0o640)

    def test_missing_docker_is_err_and_down(self) -> None:
        (self.box.bin / "docker").unlink()
        payload = self.box.dry()
        fields = self.assert_clean(payload)
        self.assertEqual((fields["ct"], fields["ctbad"], fields["err"]), ("ERR", "ERR", "ERR"))
        self.assertEqual(payload["status"], "down")

    def test_bad_arguments(self) -> None:
        self.assertEqual(self.box.run().returncode, 2)
        self.assertEqual(self.box.run("bogus").returncode, 2)


# --- push through a CONNECT proxy to a TLS "Kuma" ----------------------------------------

class KumaHandler(http.server.BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        KumaHandler.requests.append(self.path)
        body = json.dumps({"ok": self.path.startswith("/api/push/goodtoken123")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class ConnectProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ConnectHandler(socketserver.StreamRequestHandler):
    targets: list[str] = []
    upstream: tuple[str, int] = ("127.0.0.1", 0)

    def handle(self) -> None:
        line = self.rfile.readline().decode()
        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
            pass
        method, target, _ = line.split(" ", 2)
        ConnectHandler.targets.append(f"{method} {target}")
        if method != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        upstream = socket.create_connection(ConnectHandler.upstream)
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        sockets = [self.connection, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 10)
            if not readable:
                break
            for s in readable:
                data = s.recv(65536)
                if not data:
                    upstream.close()
                    return
                (upstream if s is self.connection else self.connection).sendall(data)


class HealthPush(unittest.TestCase):
    def setUp(self) -> None:
        self.box = Sandbox()
        self.addCleanup(self.box.tmp.cleanup)
        tmp = Path(self.box.tmp.name)
        self.ca = tmp / "ca.pem"
        key, cert = tmp / "kuma.key", tmp / "kuma.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
                        "-subj", "/CN=status.example.test", "-addext", "subjectAltName=DNS:status.example.test",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        self.ca.write_bytes(cert.read_bytes())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.kuma = http.server.ThreadingHTTPServer(("127.0.0.1", 0), KumaHandler)
        self.kuma.socket = ctx.wrap_socket(self.kuma.socket, server_side=True)
        threading.Thread(target=self.kuma.serve_forever, daemon=True).start()
        self.addCleanup(self.kuma.server_close)
        self.addCleanup(self.kuma.shutdown)
        ConnectHandler.upstream = self.kuma.server_address
        ConnectHandler.targets = []
        KumaHandler.requests = []
        self.proxy = ConnectProxy(("127.0.0.1", 4750), ConnectHandler)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self.proxy.shutdown)
        (self.box.root / "etc/legatto/ops.json").write_text(json.dumps({"kuma_host": "status.example.test"}))
        self.creds = tmp / "creds"
        self.creds.mkdir()
        self.box.journal_lines = 2
        self.assertEqual(self.box.run("collect").returncode, 0)

    def push(self, token: str | None = "goodtoken123") -> subprocess.CompletedProcess:
        env = {"SSL_CERT_FILE": str(self.ca)}
        if token is not None:
            (self.creds / "kuma-push-token").write_text(token + "\n")
            env["CREDENTIALS_DIRECTORY"] = str(self.creds)
        return self.box.run("push", env=env)

    def test_push_goes_through_proxy_with_allowlisted_msg(self) -> None:
        proc = self.push()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(ConnectHandler.targets, ["CONNECT status.example.test:443"])
        self.assertEqual(len(KumaHandler.requests), 1)
        url = urllib.parse.urlsplit(KumaHandler.requests[0])
        self.assertEqual(url.path, "/api/push/goodtoken123")
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        stored = json.loads((self.box.status / "health.json").read_text())
        self.assertEqual(query["status"], ["up"])
        self.assertEqual(query["msg"], [stored["msg"]])
        self.assertIn("err=2", stored["msg"])
        self.assertNotIn("goodtoken123", proc.stderr + proc.stdout)

    def test_kuma_rejecting_token_is_exit_10(self) -> None:
        proc = self.push("wrongtoken99")
        self.assertEqual(proc.returncode, 10, proc.stderr)
        self.assertNotIn("wrongtoken99", proc.stderr)

    def test_stale_health_is_pushed_down(self) -> None:
        doc = json.loads((self.box.status / "health.json").read_text())
        doc["ts"] = ts(timedelta(hours=1))
        (self.box.status / "health.json").write_text(json.dumps(doc))
        self.assertEqual(self.push().returncode, 0)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(KumaHandler.requests[0]).query)
        self.assertEqual(query["status"], ["down"])

    def test_tampered_msg_is_never_sent(self) -> None:
        doc = json.loads((self.box.status / "health.json").read_text())
        doc["msg"] += " note=jan.kowalski@example.pl"
        (self.box.status / "health.json").write_text(json.dumps(doc))
        self.assertEqual(self.push().returncode, 11)
        self.assertEqual(KumaHandler.requests, [])
        doc["msg"] = "v=Jan.Kowalski"
        (self.box.status / "health.json").write_text(json.dumps(doc))
        self.assertEqual(self.push().returncode, 11)
        self.assertEqual(KumaHandler.requests, [])

    def test_missing_credential_is_precondition(self) -> None:
        self.assertEqual(self.push(token=None).returncode, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
