"""tests/ops: the ops tools agree with contract.yml (CONTRACT §1 pkt 1)."""

from __future__ import annotations

import hashlib
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from contract_util import load_contract, load_tool, service_list_expression  # noqa: E402

REPO = Path(os.environ.get("REPO", Path(__file__).resolve().parents[2]))
SBIN = REPO / "sbin"
TOOLS = {
    "legatto-health": SBIN / "legatto-health",
    "legatto-pgdump": SBIN / "legatto-pgdump",
    "legatto-restore-test": SBIN / "legatto-restore-test",
    "legatto-recovery-pack": SBIN / "legatto-recovery-pack",
}
INLINE = re.compile(r'^([A-Z_]+) = "([^"]*)"\s+# contract: ([a-z_]+(?:\.[a-z_0-9]+)?)\s*$')
ANY_REF = re.compile(r"# contract: ([a-z_]+(?:\.[a-z_0-9]+)?)")


def resolve(contract: dict, ref: str):
    node = contract
    for part in ref.split("."):
        if not isinstance(node, dict) or part not in node:
            raise KeyError(ref)
        node = node[part]
    return node


class ContractConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_contract(REPO)

    def test_every_reference_exists(self) -> None:
        for name, path in TOOLS.items():
            for ref in ANY_REF.findall(path.read_text(encoding="utf-8")):
                with self.subTest(tool=name, ref=ref):
                    resolve(self.contract, ref)

    def test_inline_constants_match(self) -> None:
        checked = 0
        for name, path in TOOLS.items():
            for line in path.read_text(encoding="utf-8").splitlines():
                m = INLINE.match(line)
                if not m:
                    continue
                const, value, ref = m.groups()
                expected = resolve(self.contract, ref)
                with self.subTest(tool=name, const=const):
                    if ref.startswith("legatto_cli."):
                        self.assertEqual(value, f"/usr/local/sbin/{expected}")
                    elif ref.startswith("legatto_credentials."):
                        self.assertEqual(value, expected)
                    elif ref == "legatto_paths.share":
                        self.assertTrue(value.startswith(expected + "/"), value)
                    else:
                        self.assertEqual(value, expected)
                checked += 1
        self.assertGreater(checked, 25)

    def test_health_lists(self) -> None:
        health = load_tool(TOOLS["legatto-health"])
        self.assertEqual(list(health.COMPOSE_SERVICES), self.contract["legatto_compose_services"])
        self.assertLessEqual(set(health.ON_DEMAND_SERVICES), set(health.COMPOSE_SERVICES))
        self.assertEqual([k for k, _ in health.KUMA_FIELDS], self.contract["legatto_kuma_fields"])
        self.assertEqual(self.contract["legatto_kuma_interval"], f"{health.INTERVAL_SECONDS // 60}min")
        self.assertEqual(dict(health.KUMA_FIELDS)["ctbad"],
                         service_list_expression(self.contract["legatto_compose_services"]))

    def test_checksum_sql_identical(self) -> None:
        pgdump = load_tool(TOOLS["legatto-pgdump"])
        restore = load_tool(TOOLS["legatto-restore-test"])
        self.assertEqual(pgdump.CHECKSUM_SQL, restore.CHECKSUM_SQL)

    def test_audit_events_are_contract_events(self) -> None:
        events = {"backup.pgdump", "backup.restore_test", "backup.recovery_pack"}
        self.assertIn("backup", self.contract["legatto_audit"]["categories"])
        found = set()
        for path in TOOLS.values():
            found |= set(re.findall(r'"(backup\.[a-z_]+)"', path.read_text(encoding="utf-8")))
        self.assertEqual(found, events)

    def test_wordlist_pinned(self) -> None:
        pack = load_tool(TOOLS["legatto-recovery-pack"])
        data = (SBIN / "eff_large_wordlist.txt").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), pack.WORDLIST_SHA256)

    def test_cli_names(self) -> None:
        cli = self.contract["legatto_cli"]
        for key in ("health", "pgdump", "restore_test", "recovery_pack"):
            with self.subTest(cli=key):
                self.assertTrue((SBIN / cli[key]).is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
