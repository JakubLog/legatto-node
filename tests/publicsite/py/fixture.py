"""Shared fixture for the publicsite host-tool tests: a throwaway LEGATTO_ROOT
tree, fake docker/systemd-creds/systemctl/audit, and envelope builders."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SBIN = REPO / "site-publisher" / "sbin"
FAKES = REPO / "tests" / "publicsite" / "fakes"
sys.path.insert(0, str(SBIN))

from legatto_publicsite import ed25519, envelope  # noqa: E402

OFFICE_ENV = {
    "LEGATTO_CONTRACT_VERSION": "1",
    "LEGATTO_SLUG": "kowalski",
    "LEGATTO_ENV": "test",
    "LEGATTO_OFFICE_TITLE": "Biuro Posła Kowalskiego",
    "LEGATTO_OFFICE_DOMAIN": "posel-kowalski.pl",
    "LEGATTO_HOST_SITE": "posel-kowalski.pl",
    "LEGATTO_HOST_VPN": "vpn.posel-kowalski.pl",
    "LEGATTO_HOST_CRM": "app.posel-kowalski.pl",
    "LEGATTO_HOST_ADMIN": "admin.app.posel-kowalski.pl",
    "LEGATTO_TS_IP4": "100.64.0.1",
    "LEGATTO_TS_IP6": "fd7a:115c:a1e0::1",
    "LEGATTO_PUBLIC_IPV4": "198.51.100.23",
    "LEGATTO_TZ": "Europe/Warsaw",
}
APP_DIGEST = "sha256:" + "a" * 64
SIGNER_SEED = hashlib.sha256(b"test worker signer").digest()
SIGNER_PUB = ed25519.public_key(SIGNER_SEED)
OFFICE_PUB = hashlib.sha256(b"fake x25519 public").digest()  # fake keygen returns this key
OFFICE_KID = ed25519.key_id(OFFICE_PUB)


def make_envelope(kind: int = 1, *, seed: bytes = SIGNER_SEED, office_kid: bytes = OFFICE_KID,
                  received_at_ms: int | None = None, form: bytes | None = None) -> bytes:
    """Envelope v1 with a random (not decryptable) meta/form ciphertext; the gate never decrypts."""
    received = int(time.time() * 1000) if received_at_ms is None else received_at_ms
    header = (envelope.MAGIC + bytes([envelope.VERSION, kind]) + office_kid
              + ed25519.key_id(ed25519.public_key(seed)) + received.to_bytes(8, "big"))
    meta_ct = os.urandom(envelope.META_CT_SIZE)
    form_ct = form if form is not None else os.urandom(envelope.FORM_CT_SIZE)
    sig = ed25519.sign(seed, envelope.SIGNATURE_DOMAIN + header + meta_ct + form_ct)
    return header + sig + meta_ct + form_ct


class Harness(unittest.TestCase):
    """Builds the server tree under a temp LEGATTO_ROOT for each test."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="legatto-publicsite-"))
        self.root = self.tmp / "root"
        self.state = self.tmp / "fake"
        self.state.mkdir()
        self.root.mkdir()
        r = self.root
        (r / "etc/legatto").mkdir(parents=True)
        (r / "etc/legatto/office.env").write_text("".join(f"{k}={v}\n" for k, v in OFFICE_ENV.items()))
        (r / "etc/legatto/ca").mkdir()
        (r / "etc/legatto/ca/cloudflare-api.pem").write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
        (r / "etc/legatto/publicsite").mkdir()
        (r / "etc/legatto/publicsite/cloudflare.json").write_text(json.dumps({
            "v": 1, "account_id": "1" * 32, "zone_id": "2" * 32, "zone_name": "posel-kowalski.pl",
            "site_host": "posel-kowalski.pl", "queue": {"name": "forms", "id": "3" * 32},
            "dlq": {"name": "forms-dlq", "id": "4" * 32}, "pages": {"project": "legatto-kowalski-abc123"},
            "turnstile": {"sitekey": "0x4AAAAAAAtestsitekey"}, "script_name": "legatto-forms"}))
        signers = r / "etc/legatto/intake/signers.d"
        signers.mkdir(parents=True)
        (signers / f"{ed25519.key_id(SIGNER_PUB).hex()}.pub").write_text(base64.b64encode(SIGNER_PUB).decode() + "\n")
        (r / "etc/legatto/intake/keys").mkdir()
        (r / "etc/legatto/intake/keys/current.json").write_text(json.dumps(
            {"v": 1, "kid": OFFICE_KID.hex(), "x25519": base64.b64encode(OFFICE_PUB).decode()}))
        selftest_pub = ed25519.public_key(hashlib.sha256(b"selftest").digest())
        (r / "etc/legatto/intake/selftest.pub").write_text(base64.b64encode(selftest_pub).decode() + "\n")
        creds = r / "etc/credstore.encrypted"
        creds.mkdir(parents=True)
        for name in ("legatto-cf-queues-token", "legatto-cf-pages-token", "legatto-form-x25519",
                     "legatto-selftest-ed25519", "legatto-db-intake", "legatto-db-publisher"):
            (creds / name).write_bytes(b"FAKE-CREDS\n" + f"secret-value-of-{name}".encode())
        release = r / "opt/legatto/releases/1.4.0"
        release.mkdir(parents=True)
        (release / "manifest.json").write_text(json.dumps({
            "version": "1.4.0", "images": [{"name": "app", "ref": "ghcr.io/jakublog/legatto/app:1.4.0",
                                             "digest": APP_DIGEST, "platform": "linux/amd64", "artifact": "app.oci.tar"}],
            "artifacts": []}))
        os.symlink(release, r / "opt/legatto/current")
        self.env = {
            "PATH": os.environ["PATH"],
            "LEGATTO_ROOT": str(r),
            "LEGATTO_DOCKER": str(FAKES / "fake_docker.py"),
            "LEGATTO_SYSTEMD_CREDS": str(FAKES / "fake_systemd_creds.py"),
            "LEGATTO_SYSTEMCTL": str(FAKES / "fake_systemctl.py"),
            "LEGATTO_AUDIT_BIN": str(FAKES / "fake_audit.py"),
            "LEGATTO_INTAKE_BIN": str(SBIN / "legatto-intake"),
            "FAKE_STATE": str(self.state),
            "FAKE_SBIN": str(SBIN),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers ---------------------------------------------------------------------------

    def tool(self, name: str, *args: str, env: dict[str, str] | None = None) -> tuple[int, dict, str]:
        result = subprocess.run([sys.executable, str(SBIN / name), *args], capture_output=True, text=True,
                                env={**self.env, **(env or {})}, timeout=120)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        out = json.loads(lines[-1]) if lines else {}
        return result.returncode, out, result.stderr

    def push(self, body: bytes, msg_id: str) -> None:
        queue = self.fake_json("queue.json", {"messages": []})
        queue["messages"].append({"id": msg_id, "body_b64": base64.b64encode(body).decode(), "lease": None,
                                  "leased_until": 0, "acked": False, "attempts": 0, "sent": time.time()})
        (self.state / "queue.json").write_text(json.dumps(queue))

    def fake_json(self, name: str, default=None):
        target = self.state / name
        return json.loads(target.read_text()) if target.exists() else default

    def jsonl(self, name: str) -> list:
        target = self.state / name
        return [json.loads(line) for line in target.read_text().splitlines()] if target.exists() else []

    def queue_messages(self) -> dict:
        return {m["id"]: m for m in self.fake_json("queue.json", {"messages": []})["messages"]}

    def expire_leases(self) -> None:
        queue = self.fake_json("queue.json")
        for msg in queue["messages"]:
            msg["leased_until"] = 0
        (self.state / "queue.json").write_text(json.dumps(queue))

    def flag(self, name: str, on: bool = True) -> None:
        target = self.state / name
        if on:
            target.write_text("1")
        else:
            target.unlink(missing_ok=True)

    def status(self, component: str) -> dict:
        return json.loads((self.root / f"var/lib/legatto/status/{component}.json").read_text())

    def intake_dir(self, sub: str) -> Path:
        return self.root / "var/lib/legatto/intake" / sub

    def install_release(self, version: str, worker_js: bytes = b"export default {}") -> Path:
        """Release dir as legatto-update leaves it (manifest + artifacts/worker.tar.gz), made current."""
        files = {"worker.js": worker_js, "tools.mjs": b"// tools " + version.encode()}
        bundle = {"v": 1, "script_name": "legatto-forms", "entry": "worker.js",
                  "entry_sha256": hashlib.sha256(files["worker.js"]).hexdigest(), "tools": "tools.mjs",
                  "tools_sha256": hashlib.sha256(files["tools.mjs"]).hexdigest(), "compatibility_date": "2026-11-01"}
        files["bundle.json"] = json.dumps(bundle).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        release = self.root / "opt/legatto/releases" / version
        (release / "artifacts").mkdir(parents=True, exist_ok=True)
        (release / "artifacts/worker.tar.gz").write_bytes(buffer.getvalue())
        manifest = {"version": version,
                    "images": [{"name": "app", "ref": f"ghcr.io/jakublog/legatto/app:{version}", "digest": APP_DIGEST,
                                "platform": "linux/amd64", "artifact": "app.oci.tar"}],
                    "artifacts": [{"name": "worker.tar.gz", "kind": "worker-bundle", "size": len(buffer.getvalue()),
                                   "sha256": hashlib.sha256(buffer.getvalue()).hexdigest(),
                                   "worker": {"script_name": "legatto-forms", "entry_sha256": bundle["entry_sha256"]}}]}
        (release / "manifest.json").write_text(json.dumps(manifest))
        current = self.root / "opt/legatto/current"
        current.unlink()
        os.symlink(release, current)
        return release
