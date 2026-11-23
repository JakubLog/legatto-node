"""Every `# contract: <key>` constant in the publicsite host tools equals
contract/contract.yml. run.sh converts the YAML to JSON with yq and passes it
in LEGATTO_CONTRACT_JSON."""

from __future__ import annotations

import ast
import ipaddress
import json
import os
import re
import unittest
from pathlib import Path

from fixture import SBIN

from legatto_publicsite import common, guard

COMMENT_RE = re.compile(r"#\s*contract:\s*([a-z0-9_.]+)")


def lookup(contract: dict, dotted: str):
    value = contract
    for part in dotted.split("."):
        value = value[part]
    return value


def template(value: str) -> str:
    """Jinja `{{ var }}` in contract.yml and Python `{var}` in f-strings both become `{}`."""
    return re.sub(r"\{[^{}]*\}", "{}", re.sub(r"\{\{[^}]*\}\}", "{}", value))


def literals(line: str) -> list[str]:
    code = line.split("#", 1)[0]
    found = []
    for match in re.finditer(r"\"[^\"]*\"|\b\d+\b", code):
        token = match.group(0)
        found.append(ast.literal_eval(token) if token.startswith('"') else token)
    return [template(str(v)) for v in found]


@unittest.skipUnless(os.environ.get("LEGATTO_CONTRACT_JSON"), "LEGATTO_CONTRACT_JSON not set (run.sh sets it)")
class ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(Path(os.environ["LEGATTO_CONTRACT_JSON"]).read_text())

    def test_contract_comments_match(self) -> None:
        checked = 0
        for source in sorted((SBIN / "legatto_publicsite").glob("*.py")):
            for number, line in enumerate(source.read_text().splitlines(), 1):
                match = COMMENT_RE.search(line)
                if not match:
                    continue
                expected = template(str(lookup(self.contract, match.group(1))))
                with self.subTest(file=source.name, line=number, key=match.group(1)):
                    self.assertIn(expected, literals(line))
                checked += 1
        self.assertGreater(checked, 30)

    def test_derived_constants(self) -> None:
        v6 = ipaddress.ip_network(self.contract["legatto_tailnet_prefix_v6"])
        self.assertEqual(v6.prefixlen, 48)
        self.assertTrue(ipaddress.ip_address(guard.TAILNET_V6_PREFIX + ":1") in v6)
        self.assertEqual(str(guard.TAILNET_V4), self.contract["legatto_tailnet_prefix_v4"])
        self.assertEqual(common.ENV_KEYS_REQUIRED, tuple(k for k in common.ENV_KEYS_REQUIRED
                                                         if k in self.contract["legatto_office_env"]))
        self.assertIn("legatto-intake-fetch.service", self.contract["legatto_units"].values())
        for event in ("intake.quarantine", "publish.deployed", "publish.failed", "publish.worker_deployed",
                      "publish.worker_failed", "publish.drift"):
            self.assertIn(event.split(".")[0], self.contract["legatto_audit"]["categories"])

    def test_cli_names(self) -> None:
        for key in ("intake", "site_publish", "worker_deploy", "cf_bootstrap"):
            self.assertTrue((SBIN / self.contract["legatto_cli"][key]).is_file(), key)

    def test_tool_events_are_listed_in_contract_md(self) -> None:
        text = (SBIN.parents[1] / "docs" / "CONTRACT.md").read_text()
        for event in ("intake.quarantine", "publish.deployed", "publish.worker_deployed", "publish.drift"):
            self.assertIn(event.split(".")[0] + "." , text)
