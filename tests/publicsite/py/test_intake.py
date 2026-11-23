"""Two-process intake on a fake Cloudflare queue (CONTRACT §6 publicsite):
duplicate rejected, bad signature quarantined, ack only after the write."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import unittest
from pathlib import Path

from fixture import OFFICE_KID, Harness, make_envelope

from legatto_publicsite import envelope
from legatto_publicsite.intake import scram_verifier


class IntakeTest(Harness):
    def fetch(self) -> tuple[int, dict, str]:
        """One timer run: fetch container, host gate, then (fake systemctl) the processor unit."""
        return self.tool("legatto-intake", "fetch")

    def runs(self, command: str) -> list[dict]:
        return [d for d in self.jsonl("docker.jsonl") if d["command"][:2] == ["/app/server/intake.mjs", command]]

    def test_r9_isolation_of_the_two_containers(self) -> None:
        self.push(make_envelope(), "m1")
        code, out, err = self.fetch()
        self.assertEqual(code, 0, err)
        fetch, process = self.runs("fetch")[0], self.runs("process")[0]

        self.assertEqual(fetch["network"], "legatto-egress-intake")
        self.assertEqual(fetch["env"]["HTTPS_PROXY"], "http://egress-intake:4750")
        self.assertIn("/run/credentials/legatto-cf-queues-token", fetch["mounts"])
        self.assertNotIn("/run/credentials/legatto-form-x25519", fetch["mounts"])
        self.assertNotIn("/run/credentials/legatto-db-intake", fetch["mounts"])
        self.assertNotIn("/intake/quarantine", fetch["mounts"])

        self.assertEqual(process["network"], "legatto-int")
        self.assertNotIn("HTTPS_PROXY", process["env"])
        self.assertNotIn("/run/credentials/legatto-cf-queues-token", process["mounts"])
        self.assertIn("/run/credentials/legatto-form-x25519", process["mounts"])
        self.assertIn("/run/credentials/legatto-db-intake", process["mounts"])
        self.assertTrue(process["readonly"]["/etc/legatto/intake/signers.d"])
        # The processor sees only gate-approved envelopes (ready/), mounted as its inbox.
        self.assertTrue(process["mounts"]["/intake/inbox"].endswith("/intake/ready"))

        for spec in (fetch, process):
            self.assertEqual(spec["user"], "65532:65532")
            self.assertIn("--read-only", spec["flags"])
            self.assertIn("--cap-drop=ALL", spec["flags"])
            self.assertIn("--security-opt=no-new-privileges", spec["flags"])
            self.assertEqual(spec["image"], "ghcr.io/jakublog/legatto/app@sha256:" + "a" * 64)
            for dst, src in spec["mounts"].items():
                if dst.startswith("/run/credentials/"):
                    self.assertTrue(spec["readonly"][dst], dst)
                    self.assertTrue(src.startswith(str(self.root / "run/legatto/credentials")), src)
        # Staged credentials are removed after each run.
        self.assertEqual(list((self.root / "run/legatto/credentials").rglob("legatto-*")), [])

    def test_valid_message_is_stored_once_and_acked_only_after_the_write(self) -> None:
        self.push(make_envelope(), "m1")
        code, out, err = self.fetch()
        self.assertEqual(code, 0, err)
        self.assertEqual(out["gate"]["ready"], 1)
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)
        # Processed and committed, but the ack goes out only with the next fetch.
        self.assertFalse(self.queue_messages()["m1"]["acked"])
        ack = json.loads((self.intake_dir("acks") / "m1.json").read_text())
        self.assertEqual((ack["action"], ack["outcome"]), ("ack", "inserted"))
        code, out, _ = self.fetch()
        self.assertEqual(out["fetch"]["acked"], 1)
        self.assertTrue(self.queue_messages()["m1"]["acked"])
        self.assertEqual(list(self.intake_dir("acks").iterdir()), [])
        status = self.status("intake")
        self.assertEqual((status["component"], status["ok"], status["backlog"], status["failed"], status["quarantined"]),
                         ("intake", True, 0, 0, 0))
        self.assertRegex(status["last_ok_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_database_down_means_no_ack_and_redelivery(self) -> None:
        self.push(make_envelope(), "m1")
        self.flag("db_down")
        self.fetch()
        self.assertEqual(self.fake_json("db.json", {"cases": []})["cases"], [])
        self.fetch()  # sends the retry, not an ack
        msg = self.queue_messages()["m1"]
        self.assertFalse(msg["acked"])
        self.flag("db_down", False)
        self.fetch()  # redelivered -> stored
        self.fetch()  # ack
        self.assertTrue(self.queue_messages()["m1"]["acked"])
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)
        self.assertGreaterEqual(self.status("intake")["failed"], 1)

    def test_processor_crash_leaves_the_message_in_the_queue(self) -> None:
        self.push(make_envelope(), "m1")
        self.flag("process_crash")
        code, _, _ = self.fetch()
        self.assertEqual(code, 0)
        self.assertEqual(self.fake_json("db.json", {"cases": []})["cases"], [])
        self.assertEqual(list(self.intake_dir("acks").iterdir()), [])
        self.assertFalse(self.status("intake")["ok"])
        self.flag("process_crash", False)
        self.tool("legatto-intake", "process")  # e.g. the unit restarted
        self.fetch()
        self.assertTrue(self.queue_messages()["m1"]["acked"])
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)

    def test_duplicate_envelope_is_rejected(self) -> None:
        body = make_envelope()
        self.push(body, "m1")
        self.fetch()
        self.fetch()
        self.push(body, "m2")  # replay of a valid, already stored envelope
        code, out, _ = self.fetch()
        self.assertEqual(out["gate"]["duplicate"], 1)
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)
        self.fetch()
        self.assertTrue(self.queue_messages()["m2"]["acked"])
        self.assertEqual(len(self.runs("process")), 1, "the replay never reached the key-holding process")

    def test_same_envelope_twice_in_one_batch_is_held_then_rejected(self) -> None:
        body = make_envelope()
        self.push(body, "m1")
        self.push(body, "m2")
        code, out, _ = self.fetch()
        self.assertEqual((out["gate"]["ready"], out["gate"]["held"]), (1, 1))
        self.fetch()
        self.fetch()
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)
        self.assertTrue(all(m["acked"] for m in self.queue_messages().values()))

    def test_app_level_duplicate_of_a_new_envelope_is_rejected_by_the_processor(self) -> None:
        form = os.urandom(envelope.FORM_CT_SIZE)
        self.push(make_envelope(form=form), "m1")
        self.fetch()
        self.push(make_envelope(form=form), "m2")  # re-wrapped same sealed form, different envelope bytes
        self.fetch()
        self.fetch()
        self.assertEqual(len(self.fake_json("db.json")["cases"]), 1)
        self.assertTrue(self.queue_messages()["m2"]["acked"])

    def test_bad_signature_goes_to_quarantine(self) -> None:
        tampered = bytearray(make_envelope())
        tampered[-1] ^= 0x01
        self.push(bytes(tampered), "bad")
        code, out, _ = self.fetch()
        self.assertEqual(out["gate"]["quarantined"], 1)
        meta = json.loads((self.intake_dir("quarantine") / "bad.json").read_text())
        self.assertEqual((meta["reason"], meta["gate"]), ("bad_signature", "host"))
        self.assertEqual((self.intake_dir("quarantine") / "bad.bin").read_bytes(), bytes(tampered))
        self.assertEqual(oct((self.intake_dir("quarantine") / "bad.bin").stat().st_mode & 0o777), "0o600")
        self.assertEqual(self.runs("process"), [], "nothing reached the key-holding process")
        self.fetch()
        self.assertTrue(self.queue_messages()["bad"]["acked"])
        audit = [a for a in self.jsonl("audit.jsonl") if a["event"] == "intake.quarantine"]
        self.assertEqual(audit[0]["params"], {"count": 1, "reasons": {"bad_signature": 1}, "gate": "host"})
        self.assertEqual(audit[0]["actor"], {"kind": "system", "id": "legatto-intake"})
        status = self.status("intake")
        self.assertEqual((status["quarantined"], status["failed"]), (1, 1))

    def test_other_gate_rejections(self) -> None:
        cases = {
            "size": make_envelope()[:-1],
            "magic": b"XXXX" + make_envelope()[4:],
            "signer": make_envelope(seed=hashlib.sha256(b"rogue worker").digest()),
            "office": make_envelope(office_kid=b"\x00" * 8),
            "old": make_envelope(received_at_ms=1_600_000_000_000),
        }
        for msg_id, body in cases.items():
            self.push(body, msg_id)
        self.fetch()
        reasons = {p.stem: json.loads(p.read_text())["reason"] for p in self.intake_dir("quarantine").glob("*.json")}
        self.assertEqual(reasons, {"size": "bad_size", "magic": "bad_magic", "signer": "unknown_signer",
                                   "office": "unknown_office_kid", "old": "expired"})
        self.assertEqual(self.fake_json("db.json", {"cases": []})["cases"], [])

    def test_worker_generated_vectors_pass_the_gate(self) -> None:
        vectors_file = os.environ.get("LEGATTO_VECTOR_FILE")
        if not vectors_file:
            self.skipTest("LEGATTO_VECTOR_FILE not set (run.sh sets it after the Worker tests)")
        vectors = json.loads(Path(vectors_file).read_text())
        signers = {bytes.fromhex(vectors["signer_kid"]): base64.b64decode(vectors["signer_ed25519_pub"])}
        kids = {bytes.fromhex(vectors["office_kid"])}
        for v in vectors["envelopes"]:
            body = base64.b64decode(v["envelope_b64"])
            verdict = envelope.check(body, kids, signers, int(time.time() * 1000))
            self.assertTrue(verdict.ok, verdict.reason)
            self.assertEqual(verdict.kind, {1: "submission", 2: "selftest"}[v["kind"]])
            self.assertEqual(verdict.digest, v["sha256"])
            flipped = bytearray(body)
            flipped[100] ^= 0x80
            self.assertEqual(envelope.check(bytes(flipped), kids, signers, int(time.time() * 1000)).reason, "bad_signature")

    def test_missing_cloudflare_bootstrap_is_a_precondition(self) -> None:
        (self.root / "etc/legatto/publicsite/cloudflare.json").unlink()
        code, out, _ = self.fetch()
        self.assertEqual(code, 4)
        self.assertFalse(out["ok"])

    def test_keygen_refuses_to_overwrite_and_writes_credstore(self) -> None:
        code, out, _ = self.tool("legatto-intake", "keygen")
        self.assertEqual(code, 31)
        (self.root / "etc/credstore.encrypted/legatto-form-x25519").unlink()
        (self.root / "etc/credstore.encrypted/legatto-selftest-ed25519").unlink()
        code, out, err = self.tool("legatto-intake", "keygen")
        self.assertEqual(code, 0, err)
        self.assertEqual(out["kid"], OFFICE_KID.hex())
        stored = (self.root / "etc/credstore.encrypted/legatto-form-x25519").read_bytes()
        self.assertTrue(stored.startswith(b"FAKE-CREDS\n"))
        self.assertNotIn("x25519_secret", json.dumps(out))
        keygen = [d for d in self.jsonl("docker.jsonl") if d["command"][1] == "keygen"][0]
        self.assertEqual(keygen["network"], "none")
        self.assertTrue((self.root / "etc/credstore.encrypted/legatto-selftest-ed25519").exists())

    def test_db_role_password_is_sent_only_as_a_scram_verifier(self) -> None:
        (self.root / "etc/credstore.encrypted/legatto-db-publisher").unlink()
        code, out, err = self.tool("legatto-intake", "db-role", "--role", "legatto_publisher")
        self.assertEqual((code, out["changed"]), (0, True), err)
        stored = (self.root / "etc/credstore.encrypted/legatto-db-publisher").read_bytes()
        password = stored[len(b"FAKE-CREDS\n"):].decode()
        self.assertRegex(password, r"^[0-9a-f]{64}$")
        call = self.jsonl("db_exec.jsonl")[0]
        self.assertEqual(call["argv"][:3], ["exec", "-i", "supabase-db"])
        self.assertNotIn(password, json.dumps(call))
        verifier = call["sql"].split("PASSWORD '")[1].split("'")[0]
        _, rest = verifier.split("$", 1)
        iterations_salt, _keys = rest.split("$")
        salt = base64.b64decode(iterations_salt.split(":")[1])
        self.assertEqual(scram_verifier(password, salt), verifier)
        self.assertIn("SET log_statement = 'none'", call["sql"])
        # Idempotent: same password -> nothing sent.
        code, out, _ = self.tool("legatto-intake", "db-role", "--role", "legatto_publisher")
        self.assertEqual((code, out["changed"]), (0, False))
        self.assertEqual(len(self.jsonl("db_exec.jsonl")), 1)

    def test_db_role_missing_role_is_a_precondition(self) -> None:
        (self.state / "db_roles.json").write_text("[]")
        code, out, _ = self.tool("legatto-intake", "db-role", "--role", "legatto_intake")
        self.assertEqual(code, 4)


if __name__ == "__main__":
    unittest.main()
