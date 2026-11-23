"""legatto-cf-bootstrap against a fake Cloudflare API reached through a
CONNECT proxy with a throwaway CA (pinned bundle): resources, IP-filtered
tokens straight into the credstore, nothing secret on stdout/stderr."""

from __future__ import annotations

import json
import select
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fixture import SBIN, Harness

BOOTSTRAP_TOKEN = "bootstrapTOKEN_abcdefghijklmnopqrstuvwxyz0123"
ACCOUNT = "1" * 32
ZONE = "2" * 32


class FakeCf:
    def __init__(self) -> None:
        self.queues: list[dict] = []
        self.consumers: dict[str, list] = {}
        self.widgets: list[dict] = []
        self.projects: dict[str, list] = {}
        self.tokens: list[dict] = []
        self.deleted: list[str] = []
        self.requests: list[tuple[str, str, dict | None]] = []
        self.seq = 0

    def next_id(self) -> str:
        self.seq += 1
        return f"{self.seq:032x}"

    def handle(self, method: str, path: str, auth: str, body: dict | None) -> tuple[int, object]:
        self.requests.append((method, path, body))
        if auth != f"Bearer {BOOTSTRAP_TOKEN}":
            return 403, None
        p = path.split("?")[0]
        a = f"/client/v4/accounts/{ACCOUNT}"
        if p == "/client/v4/accounts":
            return 200, [{"id": ACCOUNT, "name": "Biuro"}]
        if p == "/client/v4/zones":
            return 200, [{"id": ZONE, "name": "posel-kowalski.pl"}] if "name=posel-kowalski.pl" in path else []
        if p == f"{a}/queues" and method == "GET":
            return 200, self.queues
        if p == f"{a}/queues" and method == "POST":
            q = {"queue_id": self.next_id(), "queue_name": body["queue_name"], "settings": body["settings"]}
            self.queues.append(q)
            return 200, q
        if p.startswith(f"{a}/queues/") and p.endswith("/consumers"):
            qid = p.split("/")[-2]
            if method == "POST":
                self.consumers.setdefault(qid, []).append(body)
            return 200, self.consumers.get(qid, [])
        if p == f"{a}/challenges/widgets" and method == "GET":
            return 200, self.widgets
        if p == f"{a}/challenges/widgets" and method == "POST":
            w = {**body, "sitekey": "0x4AAAAAAAsitekey", "secret": "0x4AAAAAAAturnstileSECRET"}
            self.widgets.append({k: v for k, v in w.items() if k != "secret"})
            return 200, w
        if p.endswith("/rotate_secret"):
            return 200, {"sitekey": "0x4AAAAAAAsitekey", "secret": "0x4AAAAAAArotatedSECRET"}
        if p.startswith(f"{a}/pages/projects"):
            parts = p[len(f"{a}/pages/projects"):].strip("/").split("/")
            if parts == [""] and method == "POST":
                self.projects[body["name"]] = []
                return 200, {"name": body["name"]}
            name = parts[0]
            if name not in self.projects:
                return 404, None
            if len(parts) == 2:
                if method == "POST":
                    self.projects[name].append(body)
                return 200, self.projects[name]
            return 200, {"name": name}
        if p == f"{a}/tokens/permission_groups":
            names = ["Queues Write", "Pages Write", "Workers Scripts Write", "Workers Routes Write", "DNS Write", "Zone Read"]
            return 200, [{"id": f"pg-{i}", "name": n} for i, n in enumerate(names)]
        if p == f"{a}/tokens" and method == "GET":
            return 200, [{"id": t["id"], "name": t["name"]} for t in self.tokens]
        if p == f"{a}/tokens" and method == "POST":
            t = {**body, "id": self.next_id(), "value": f"officeTOKEN{self.seq:040d}"}
            self.tokens.append(t)
            return 200, t
        if p == f"{a}/tokens/verify":
            return 200, {"id": "bootstrap-token-id", "status": "active"}
        if p.startswith(f"{a}/tokens/") and method == "DELETE":
            tid = p.rsplit("/", 1)[1]
            self.deleted.append(tid)
            self.tokens = [t for t in self.tokens if t["id"] != tid]
            return 200, {"id": tid}
        return 404, None


def make_pki(tmp: Path) -> tuple[Path, Path, Path]:
    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True)

    (tmp / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                              "subjectKeyIdentifier=hash\n")
    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp / "ca.key"), "-out", str(tmp / "ca.csr"), "-subj", "/CN=test CA")
    run("x509", "-req", "-in", str(tmp / "ca.csr"), "-signkey", str(tmp / "ca.key"), "-sha256", "-out", str(tmp / "ca.pem"),
        "-days", "2", "-extfile", str(tmp / "ca.ext"))
    run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp / "leaf.key"), "-out", str(tmp / "leaf.csr"),
        "-subj", "/CN=api.cloudflare.com")
    (tmp / "leaf.ext").write_text("subjectAltName=DNS:api.cloudflare.com\nextendedKeyUsage=serverAuth\n"
                                "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    run("x509", "-req", "-in", str(tmp / "leaf.csr"), "-CA", str(tmp / "ca.pem"), "-CAkey", str(tmp / "ca.key"),
        "-CAcreateserial", "-sha256", "-out", str(tmp / "leaf.pem"), "-days", "2", "-extfile", str(tmp / "leaf.ext"))
    return tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"


class CfBootstrapTest(Harness):
    def setUp(self) -> None:
        super().setUp()
        for name in list((self.root / "etc/credstore.encrypted").iterdir()):
            name.unlink()
        (self.root / "etc/legatto/publicsite/cloudflare.json").unlink()
        ca, cert, key = make_pki(self.tmp)
        (self.root / "etc/legatto/ca/cloudflare-api.pem").write_bytes(ca.read_bytes())
        self.cf = FakeCf()
        cf = self.cf

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                return

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                status, result = cf.handle(self.command, self.path, self.headers.get("Authorization", ""), body)
                payload = {"success": status < 400, "errors": [] if status < 400 else [{"code": status, "message": "x"}],
                           "result": result}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        self.api = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.api.socket = context.wrap_socket(self.api.socket, server_side=True)
        threading.Thread(target=self.api.serve_forever, daemon=True).start()
        self.connects: list[str] = []
        self.proxy = socket.socket()
        self.proxy.bind(("127.0.0.1", 0))
        self.proxy.listen(8)
        threading.Thread(target=self._proxy_loop, daemon=True).start()
        self.env["HTTPS_PROXY"] = f"http://127.0.0.1:{self.proxy.getsockname()[1]}"

    def _proxy_loop(self) -> None:
        while True:
            try:
                client, _ = self.proxy.accept()
            except OSError:
                return
            threading.Thread(target=self._tunnel, args=(client,), daemon=True).start()

    def _tunnel(self, client: socket.socket) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(4096)
            if not chunk:
                return
            head += chunk
        target = head.split(b" ")[1].decode()
        self.connects.append(target)
        if target != "api.cloudflare.com:443":
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            client.close()
            return
        upstream = socket.create_connection(("127.0.0.1", self.api.server_address[1]))
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        with client, upstream:
            sockets = [client, upstream]
            while True:
                readable, _, _ = select.select(sockets, [], [], 10)
                if not readable:
                    return
                for s in readable:
                    try:
                        data = s.recv(65536)
                        if data:
                            (upstream if s is client else client).sendall(data)
                    except OSError:  # the client aborted the TLS handshake (untrusted CA test)
                        return
                    if not data:
                        return

    def tearDown(self) -> None:
        self.api.shutdown()
        self.api.server_close()
        self.proxy.close()
        super().tearDown()

    def bootstrap(self, *args: str, stdin: str = BOOTSTRAP_TOKEN + "\n") -> tuple[int, dict, str]:
        result = subprocess.run([sys.executable, str(SBIN / "legatto-cf-bootstrap"), *args], input=stdin,
                                capture_output=True, text=True, env=self.env, timeout=120)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        return result.returncode, json.loads(lines[-1]) if lines else {}, result.stderr

    def test_creates_resources_and_ip_filtered_tokens(self) -> None:
        code, out, err = self.bootstrap()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.connects and set(self.connects), {"api.cloudflare.com:443"})
        self.assertEqual([q["queue_name"] for q in self.cf.queues], ["forms-dlq", "forms"])
        self.assertTrue(all(q["settings"]["message_retention_period"] == 1_209_600 for q in self.cf.queues))
        forms_consumer = self.cf.consumers[out["queue_id"]][0]
        self.assertEqual((forms_consumer["type"], forms_consumer["dead_letter_queue"]), ("http_pull", "forms-dlq"))
        self.assertEqual(self.cf.widgets[0]["domains"], ["posel-kowalski.pl"])
        self.assertEqual(self.cf.projects[out["pages_project"]], [{"name": "posel-kowalski.pl"}])

        tokens = {t["name"]: t for t in self.cf.tokens}
        self.assertEqual(set(tokens), {"legatto-kowalski-queues", "legatto-kowalski-pages", "legatto-kowalski-dns"})
        for token in tokens.values():
            self.assertEqual(token["condition"], {"request_ip": {"in": ["198.51.100.23/32"]}})
        dns = tokens["legatto-kowalski-dns"]["policies"]
        self.assertEqual([list(p["resources"]) for p in dns], [[f"com.cloudflare.api.account.zone.{ZONE}"]])
        queues = tokens["legatto-kowalski-queues"]["policies"]
        self.assertEqual([list(p["resources"]) for p in queues], [[f"com.cloudflare.api.account.{ACCOUNT}"]])

        store = self.root / "etc/credstore.encrypted"
        for name, purpose in (("legatto-cf-queues-token", "queues"), ("legatto-cf-pages-token", "pages"),
                              ("legatto-cf-dns-token", "dns")):
            self.assertEqual((store / name).read_bytes(), b"FAKE-CREDS\n" + tokens[f"legatto-kowalski-{purpose}"]["value"].encode())
        self.assertEqual(self.cf.deleted, ["bootstrap-token-id"])
        self.assertTrue(out["bootstrap_token_deleted"])

        pending = json.loads((self.root / "var/lib/legatto/worker/secrets-pending.json").read_text())
        self.assertEqual(pending["TURNSTILE_SECRET"], "0x4AAAAAAAturnstileSECRET")
        self.assertEqual(oct((self.root / "var/lib/legatto/worker/secrets-pending.json").stat().st_mode & 0o777), "0o600")
        config = json.loads((self.root / "etc/legatto/publicsite/cloudflare.json").read_text())
        self.assertEqual((config["account_id"], config["zone_id"], config["turnstile"]["sitekey"]),
                         (ACCOUNT, ZONE, "0x4AAAAAAAsitekey"))

        leaked = [BOOTSTRAP_TOKEN, "SECRET", "officeTOKEN", pending["SIGNING_KEY"]]
        visible = json.dumps(out) + err + json.dumps(config)
        for value in leaked:
            self.assertNotIn(value, visible)

    def test_second_run_is_idempotent(self) -> None:
        self.assertEqual(self.bootstrap()[0], 0)
        tokens_before = [t["id"] for t in self.cf.tokens]
        code, out, err = self.bootstrap()
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.cf.queues), 2)
        self.assertEqual(len(self.cf.widgets), 1)
        self.assertEqual(len(self.cf.projects), 1)
        self.assertEqual([t["id"] for t in self.cf.tokens], tokens_before)
        self.assertEqual(out["credentials_created"], [])
        self.assertIsNone(out["worker_signer_kid"])

    def test_rotate_tokens_replaces_them(self) -> None:
        self.assertEqual(self.bootstrap()[0], 0)
        before = {t["id"] for t in self.cf.tokens}
        code, out, err = self.bootstrap("--rotate-tokens")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.cf.tokens), 3)
        self.assertFalse(before & {t["id"] for t in self.cf.tokens})

    def test_token_only_from_stdin(self) -> None:
        code, out, _ = self.bootstrap(stdin="not a token\n")
        self.assertEqual(code, 2)
        self.assertEqual(self.cf.requests, [])

    def test_rejects_an_untrusted_certificate(self) -> None:
        other = self.tmp / "other"
        other.mkdir()
        (self.root / "etc/legatto/ca/cloudflare-api.pem").write_bytes(make_pki(other)[0].read_bytes())
        code, out, err = self.bootstrap()
        self.assertEqual(code, 40)
        self.assertEqual(self.cf.requests, [])
        self.assertNotIn(BOOTSTRAP_TOKEN, err + json.dumps(out))
