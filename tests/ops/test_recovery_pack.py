"""tests/ops: legatto-recovery-pack generate -> verify (inside the tests/ops image).

Covers CONTRACT §6 (ops) `generate` -> `verify`, plus: wrong passphrase,
damaged ciphertext, the printed card decoded back from its QR codes
(rsvg-convert + zbarimg) and from its numbered text lines, CRC detection of
a typo, missing key sources, and that no secret reaches stderr or the card.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(os.environ.get("REPO", Path(__file__).resolve().parents[2]))
FILES = REPO / "sbin"
TOOL = FILES / "legatto-recovery-pack"
# Throw-away values generated per run (no literal secrets in the repository).
PGSODIUM = secrets.token_hex(32)
PII_KEY = secrets.token_hex(32)
RECOVERY_PW = "Odzyskanie-" + secrets.token_urlsafe(12)
FORM_KEY = base64.b64encode(secrets.token_bytes(32)).decode()
EMERGENCY_PW = "Panel-" + secrets.token_urlsafe(12)


class Sandbox:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "root"
        for d in ("etc/legatto/secrets", "etc/credstore.encrypted", "var/lib/legatto/recovery",
                  "var/lib/legatto/office", "usr/local/sbin", "opt/legatto/share/recovery-pack"):
            (self.root / d).mkdir(parents=True)
        shutil.copy(FILES / "eff_large_wordlist.txt", self.root / "opt/legatto/share/recovery-pack/")
        (self.root / "etc/legatto/office.env").write_text("LEGATTO_SLUG=biuro-testowe\nLEGATTO_ENV=test\n")
        (self.root / "etc/credstore.encrypted/legatto-form-x25519").write_text(FORM_KEY)
        (self.root / "etc/legatto/secrets/pgsodium_root.key").write_text(PGSODIUM)
        (self.root / "etc/legatto/secrets/pii_field_key").write_text(PII_KEY)
        (self.root / "etc/legatto/secrets/recovery-password").write_text(RECOVERY_PW)
        (self.root / "var/lib/legatto/office/contacts.json").write_text(json.dumps(
            {"v": 1, "primary": {"name": "Anna Nowak", "email": "anna@biuro.example", "phone": "+48 600 000 000"},
             "secondary": None, "iod": None, "notes": "dyżur 8-16"}))
        self.calls = base / "calls"
        self._script("legatto-console-exec",
                     f'echo "$@" >> "{self.calls}"\n'
                     f'echo \'{{"login":"awaryjny","password":"{EMERGENCY_PW}","totp_secret":"JBSWY3DPEHPK3PXP",'
                     '"otpauth_uri":"otpauth://totp/Legatto:awaryjny?secret=JBSWY3DPEHPK3PXP"}\'\n')
        self._script("legatto-audit", f'echo "$@" >> "{self.calls}"\necho \'{{"seq":12,"hash":"00"}}\'\n')

    def _script(self, name: str, body: str) -> None:
        p = self.root / "usr/local/sbin" / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)

    def run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(TOOL), *args], input=stdin, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LEGATTO_ROOT": str(self.root)}, timeout=120)


class RecoveryPack(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.box = Sandbox()
        proc = cls.box.run("generate", "--json")
        assert proc.returncode == 0, proc.stderr
        cls.stderr = proc.stderr
        cls.result = json.loads(proc.stdout)
        cls.pack = cls.box.root / cls.result["file"].lstrip("/")
        cls.card = cls.box.root / cls.result["card"].lstrip("/")
        cls.words = {line.split("\t")[1] for line in
                     (FILES / "eff_large_wordlist.txt").read_text().splitlines()}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.box.tmp.cleanup()

    def verify(self, path: Path, passphrase: str | None = None) -> subprocess.CompletedProcess:
        return self.box.run("verify", str(path), "--passphrase-stdin", "--json",
                            stdin=(passphrase or self.result["password"]) + "\n")

    def test_result_shape_and_passphrase(self) -> None:
        r = self.result
        self.assertEqual(set(r), {"v", "file", "card", "sha256", "bytes", "password", "items", "audit_seq"})
        self.assertRegex(r["file"], r"^/var/lib/legatto/recovery/legatto-recovery-biuro-testowe-[0-9]{8}T[0-9]{6}Z"
                                    r"\.tar\.age$")
        words = r["password"].split(" ")
        self.assertEqual(len(words), 10)
        self.assertLessEqual(set(words), self.words)
        self.assertEqual(r["items"], ["form-x25519", "console-emergency", "recovery-account", "pgsodium-root-key",
                                      "pii-field-key"])
        self.assertEqual(stat.S_IMODE(self.pack.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.card.stat().st_mode), 0o640)
        self.assertTrue(self.pack.read_text().startswith("-----BEGIN AGE ENCRYPTED FILE-----"))

    def test_no_secret_outside_the_result(self) -> None:
        hidden = [PGSODIUM, PII_KEY, RECOVERY_PW, FORM_KEY, EMERGENCY_PW, self.result["password"]]
        card = self.card.read_text()
        pack = self.pack.read_text()
        for value in hidden:
            self.assertNotIn(value, self.stderr)
            self.assertNotIn(value, card)
            self.assertNotIn(value, pack)
        calls = self.box.calls.read_text()
        self.assertIn("emergency-credentials --json", calls)
        self.assertIn("--event backup.recovery_pack", calls)
        for value in hidden:
            self.assertNotIn(value, calls)

    def test_verify_ok_and_current(self) -> None:
        proc = self.verify(self.pack)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["slug"], "biuro-testowe")
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["sha256"], self.result["sha256"])
        currents = {i["name"]: i.get("current") for i in report["items"]}
        self.assertEqual(currents, {"form-x25519": True, "console-emergency": None, "recovery-account": True,
                                    "pgsodium-root-key": True, "pii-field-key": True})
        for value in (PGSODIUM, PII_KEY, RECOVERY_PW, EMERGENCY_PW):
            self.assertNotIn(value, proc.stdout + proc.stderr)

    def test_verify_detects_rotated_key(self) -> None:
        key = self.box.root / "etc/legatto/secrets/pii_field_key"
        key.write_text("c3" * 32)
        try:
            report = json.loads(self.verify(self.pack).stdout)
        finally:
            key.write_text(PII_KEY)
        self.assertTrue(report["ok"])
        self.assertFalse({i["name"]: i.get("current") for i in report["items"]}["pii-field-key"])

    def test_wrong_passphrase(self) -> None:
        proc = self.verify(self.pack, "jeden dwa trzy cztery pięć sześć siedem osiem dziewięć dziesięć")
        self.assertEqual(proc.returncode, 20)

    def test_damaged_ciphertext(self) -> None:
        lines = self.pack.read_text().split("\n")
        body = lines[2]
        lines[2] = ("A" if body[0] != "A" else "B") + body[1:]
        damaged = Path(self.box.tmp.name) / "damaged.age"
        damaged.write_text("\n".join(lines))
        self.assertEqual(self.verify(damaged).returncode, 20)

    def test_card_qr_codes_decode_back(self) -> None:
        svgs = re.findall(r"<svg.*?</svg>", self.card.read_text(), re.S)
        self.assertGreaterEqual(len(svgs), 1)
        payloads = []
        work = Path(self.box.tmp.name) / "qr"
        work.mkdir(exist_ok=True)
        for i, svg in enumerate(svgs):
            (work / f"{i}.svg").write_text(svg)
            subprocess.run(["rsvg-convert", "-z", "4", "-b", "white", "-o", str(work / f"{i}.png"),
                            str(work / f"{i}.svg")], check=True)
            out = subprocess.run(["zbarimg", "--raw", "-q", "-Sbinary", str(work / f"{i}.png")],
                                 capture_output=True, check=True).stdout.decode("ascii")
            payloads.append(out.rstrip("\n"))
        self.assertTrue(all(p.startswith("LGTRP1 ") for p in payloads))
        random.Random(7).shuffle(payloads)
        scanned = work / "scanned.txt"
        scanned.write_text("\n".join(payloads) + "\n")
        proc = self.verify(scanned)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])
        partial = work / "partial.txt"
        partial.write_text("\n".join(payloads[1:]) + "\n" if len(payloads) > 1 else "LGTRP1 2/2 00000000 1\nx\n")
        self.assertEqual(self.verify(partial).returncode, 21)

    def test_qr_body_length_drops_decoder_junk(self) -> None:
        # zbar reads the padding of an almost full symbol as a numeric segment and
        # appends digits to the last line (seen ~1 in 75 cards); the declared body
        # length must cut it off, and a body shorter than declared must fail.
        svgs = re.findall(r"<svg.*?</svg>", self.card.read_text(), re.S)
        work = Path(self.box.tmp.name) / "qr-junk"
        work.mkdir(exist_ok=True)
        payloads = []
        for i, svg in enumerate(svgs):
            (work / f"{i}.svg").write_text(svg)
            subprocess.run(["rsvg-convert", "-z", "4", "-b", "white", "-o", str(work / f"{i}.png"),
                            str(work / f"{i}.svg")], check=True)
            out = subprocess.run(["zbarimg", "--raw", "-q", "-Sbinary", str(work / f"{i}.png")],
                                 capture_output=True, check=True).stdout.decode("ascii").rstrip("\n")
            payloads.append(out[:out.rindex("\n") + 1] + out[out.rindex("\n") + 1:][:64])
        junk = [p + "0193575681681522" for p in payloads]
        scanned = work / "junk.txt"
        scanned.write_text("\n".join(junk) + "\n")
        proc = self.verify(scanned)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        short = list(payloads)
        short[0] = short[0][:-5]
        (work / "short.txt").write_text("\n".join(short) + "\n")
        proc = self.verify(work / "short.txt")
        self.assertEqual(proc.returncode, 21)
        self.assertIn("incomplete", proc.stderr)

    def test_card_text_lines_and_crc(self) -> None:
        pre = re.findall(r"<pre>(.*?)</pre>", self.card.read_text(), re.S)[0]
        import html
        text = html.unescape(pre)
        typed = Path(self.box.tmp.name) / "typed.txt"
        typed.write_text(text + "\n")
        proc = self.verify(typed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = text.split("\n")
        number, body, crc = lines[3].split()
        typo = body[:-1] + ("x" if body[-1] != "x" else "y")
        lines[3] = f"{number}  {typo}  {crc}"
        typed.write_text("\n".join(lines) + "\n")
        proc = self.verify(typed)
        self.assertEqual(proc.returncode, 21)
        self.assertIn(f"line {int(number)}", proc.stderr)

    def test_card_has_instructions_and_contacts(self) -> None:
        card = self.card.read_text()
        self.assertIn("Anna Nowak", card)
        self.assertIn("recovery", card)
        self.assertIn(self.result["sha256"], card)

    def test_generate_requires_json_and_sources(self) -> None:
        box = Sandbox()
        self.addCleanup(box.tmp.cleanup)
        self.assertEqual(box.run("generate").returncode, 2)
        (box.root / "etc/legatto/secrets/pgsodium_root.key").unlink()
        proc = box.run("generate", "--json")
        self.assertEqual(proc.returncode, 4)
        self.assertIn("pgsodium-root-key", proc.stderr)
        self.assertFalse(box.calls.exists(), "emergency credentials must not rotate when a source is missing")
        self.assertEqual(list((box.root / "var/lib/legatto/recovery").iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
