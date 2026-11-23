"""legatto-audit: append, verify, tamper detection, concurrency (CONTRACT §4.2, §6 net)."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from harness import ToolTestCase

ACTOR = json.dumps({"kind": "system", "id": "legatto-test"})
LOG = "var/log/legatto/audit.log"


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class AuditTest(ToolTestCase):
    with_policy_inputs = False

    def append(self, n: int = 1, event: str = "fw.apply", params: dict | None = None) -> list:
        results = []
        for i in range(n):
            proc = self.run_tool("legatto-audit", "append", "--cat", event.split(".")[0], "--event", event,
                                 "--actor", ACTOR, "--params", json.dumps(params or {"i": i}))
            self.assert_ok(proc)
            results.append(json.loads(proc.stdout))
        return results

    def lines(self) -> list:
        with open(self.path(LOG), "rb") as fh:
            return fh.read().splitlines(keepends=True)

    def write_lines(self, lines: list) -> None:
        with open(self.path(LOG), "wb") as fh:
            fh.writelines(lines)

    def verify(self) -> tuple:
        proc = self.run_tool("legatto-audit", "verify", "--json")
        return proc.returncode, json.loads(proc.stdout)

    def test_append_builds_chain_with_contract_hash(self) -> None:
        out = self.append(3)
        self.assertEqual([o["seq"] for o in out], [1, 2, 3])
        entries = self.audit_entries()
        self.assertEqual(entries[0]["prev"], "0" * 64)
        for prev, entry in zip([None] + entries, entries):
            self.assertEqual(list(sorted(entry)), sorted(
                ["seq", "ts", "host", "cat", "event", "actor", "node", "params", "prev", "hash"]))
            body = {k: v for k, v in entry.items() if k != "hash"}
            self.assertEqual(entry["hash"], hashlib.sha256(canonical(body)).hexdigest())
            if prev:
                self.assertEqual(entry["prev"], prev["hash"])
            self.assertEqual(entry["host"], "testoffice")
            self.assertRegex(entry["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(out[-1]["hash"], entries[-1]["hash"])

    def test_verify_ok_writes_status(self) -> None:
        self.append(5)
        code, result = self.verify()
        self.assertEqual(code, 0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["last_seq"], 5)
        status = self.read("var/lib/legatto/status/audit.json")
        self.assertEqual((status["component"], status["seq"], status["chain_ok"], status["ok"]),
                         ("audit", 5, True, True))
        self.assertEqual(status["head"], self.audit_entries()[-1]["hash"])
        head = json.loads(self.run_tool("legatto-audit", "head", "--json").stdout)
        self.assertEqual(head, {"seq": 5, "hash": status["head"]})

    def test_modification_detected(self) -> None:
        self.append(4)
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["params"] = {"i": 99}
        lines[1] = canonical(entry) + b"\n"
        self.write_lines(lines)
        code, result = self.verify()
        self.assertEqual(code, 30)
        self.assertIn("hash mismatch", json.dumps(result["errors"]))

    def test_modification_with_recomputed_hash_detected(self) -> None:
        self.append(4)
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["params"] = {"i": 99}
        entry["hash"] = hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "hash"})).hexdigest()
        lines[1] = canonical(entry) + b"\n"
        self.write_lines(lines)
        code, result = self.verify()
        self.assertEqual(code, 30)
        self.assertIn("prev does not match", json.dumps(result["errors"]))

    def test_deletion_detected(self) -> None:
        self.append(5)
        lines = self.lines()
        del lines[2]
        self.write_lines(lines)
        code, result = self.verify()
        self.assertEqual(code, 30)
        self.assertIn("seq gap", json.dumps(result["errors"]))

    def test_swap_detected(self) -> None:
        self.append(5)
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.write_lines(lines)
        code, _ = self.verify()
        self.assertEqual(code, 30)

    def test_tail_truncation_detected_against_anchor(self) -> None:
        self.append(5)
        self.assertEqual(self.verify()[0], 0)
        self.write_lines(self.lines()[:-2])
        code, result = self.verify()
        self.assertEqual(code, 30)
        self.assertIn("entries removed", json.dumps(result["errors"]))
        # the broken run must not move the anchor: still broken next time
        self.assertEqual(self.verify()[0], 30)
        self.assertFalse(self.read("var/lib/legatto/status/audit.json")["chain_ok"])

    def test_rewrite_from_scratch_detected_against_anchor(self) -> None:
        self.append(3)
        self.assertEqual(self.verify()[0], 0)
        os.unlink(self.path(LOG))
        self.append(3, params={"forged": True})
        code, result = self.verify()
        self.assertEqual(code, 30)
        self.assertIn("chain rewritten", json.dumps(result["errors"]))

    def test_torn_write_refused(self) -> None:
        self.append(2)
        with open(self.path(LOG), "ab") as fh:
            fh.write(b'{"seq":3,')
        proc = self.run_tool("legatto-audit", "append", "--cat", "fw", "--event", "fw.apply", "--actor", ACTOR,
                             "--params", "{}")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.verify()[0], 30)

    def test_parallel_appends_are_serialised(self) -> None:
        def worker(i: int) -> list:
            return [self.run_tool("legatto-audit", "append", "--cat", "ssh", "--event", "ssh.login", "--actor",
                                  ACTOR, "--params", json.dumps({"w": i, "n": n})).returncode for n in range(10)]

        with ThreadPoolExecutor(max_workers=8) as pool:
            codes = [c for result in pool.map(worker, range(8)) for c in result]
        self.assertEqual(set(codes), {0})
        code, result = self.verify()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["entries"], 80)
        self.assertEqual([e["seq"] for e in self.audit_entries()], list(range(1, 81)))

    def test_lock_busy_exit_3(self) -> None:
        self.append(1)
        with open(self.path(LOG) + ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            start = time.monotonic()
            proc = self.run_tool("legatto-audit", "append", "--cat", "fw", "--event", "fw.apply", "--actor", ACTOR,
                                 "--params", "{}")
            elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 3)
        self.assertGreaterEqual(elapsed, 9.5)

    def test_argument_validation(self) -> None:
        cases = [
            ("--cat", "nope", "--event", "nope.x", "--actor", ACTOR, "--params", "{}"),
            ("--cat", "fw", "--event", "ssh.login", "--actor", ACTOR, "--params", "{}"),
            ("--cat", "fw", "--event", "fw.apply", "--actor", "{}", "--params", "{}"),
            ("--cat", "fw", "--event", "fw.apply", "--actor", json.dumps({"kind": "vendor", "id": "jan"}),
             "--params", "{}"),
            ("--cat", "fw", "--event", "fw.apply", "--actor", ACTOR, "--params", "[]"),
            ("--cat", "device", "--event", "device.enroll", "--actor", ACTOR, "--params",
             json.dumps({"preauth_key": "x"})),
            ("--cat", "console", "--event", "console.login", "--actor", ACTOR, "--params",
             json.dumps({"auth": {"totp": "123456"}})),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(self.run_tool("legatto-audit", "append", *args).returncode, 2)
        self.assertFalse(os.path.exists(self.path(LOG)))

    def test_ssh_follow_parses_sshd_and_sudo(self) -> None:
        journal = [
            {"_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd",
             "MESSAGE": "Accepted publickey for v-jan from 100.64.0.4 port 51234 ssh2: SK-ED25519 "
                        "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"},
            {"SYSLOG_IDENTIFIER": "sudo",
             "MESSAGE": "   v-jan : PWD=/home/v-jan ; USER=root ; COMMAND=/usr/bin/systemctl status headscale"},
            {"_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd",
             "MESSAGE": "Failed publickey for v-ola from 100.64.0.9 port 40000 ssh2: ED25519 SHA256:zz"},
            {"_SYSTEMD_UNIT": "ssh.service", "SYSLOG_IDENTIFIER": "sshd",
             "MESSAGE": "Disconnected from user v-jan 100.64.0.4 port 51234"},
        ]
        self.set_fake({"journal": journal})
        proc = self.run_tool("legatto-audit", "ssh-follow")
        self.assert_ok(proc)
        entries = self.audit_entries()
        self.assertEqual([e["event"] for e in entries], ["ssh.login", "sudo.command", "ssh.fail", "ssh.logout"])
        login = entries[0]
        self.assertEqual(login["actor"], {"kind": "vendor", "id": "v-jan"})
        self.assertEqual(login["node"], "fake-node")
        self.assertTrue(login["params"]["key_fp"].startswith("SHA256:"))
        self.assertEqual(entries[1]["params"]["command"], "/usr/bin/systemctl status headscale")
        self.assertTrue(os.path.exists(self.path("var/lib/legatto/audit")))


if __name__ == "__main__":
    unittest.main()
