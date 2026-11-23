"""Constants annotated `# contract: <key>` equal contract.yml; the spool layout matches CONTRACT §4.3."""

import os
import re
import unittest

import harness
from legatto_console import contract, executor

try:
    import yaml
except ImportError:  # pragma: no cover - the test image ships python3-yaml
    yaml = None

CONTRACT_YML = os.path.join(harness.REPO, "contract", "contract.yml")
ANNOTATION = re.compile(r"^([A-Z_][A-Z0-9_]*) = .*# contract: ([a-z_.]+)( \(.*\))?$")


def lookup(doc, dotted):
    node = doc
    for part in dotted.split("."):
        node = node[part]
    return node


@unittest.skipIf(yaml is None, "PyYAML missing")
class ContractValues(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CONTRACT_YML, encoding="utf-8") as handle:
            cls.doc = yaml.safe_load(handle)

    def annotations(self):
        with open(contract.__file__, encoding="utf-8") as handle:
            for line in handle:
                match = ANNOTATION.match(line.rstrip("\n"))
                if match:
                    yield match.group(1), match.group(2), bool(match.group(3))

    def test_annotated_constants_match(self):
        seen = 0
        for name, key, membership in self.annotations():
            seen += 1
            value = getattr(contract, name)
            expected = lookup(self.doc, key)
            with self.subTest(constant=name, key=key):
                if membership:
                    self.assertIn(value, expected)
                elif isinstance(value, tuple):
                    self.assertEqual(list(value), expected)
                else:
                    self.assertEqual(value, expected)
        self.assertGreater(seen, 40)

    def test_request_types_have_handlers(self):
        self.assertEqual(set(contract.REQUEST_TYPES), set(self.doc["legatto_requests"]["types"]))

    def test_unit_names(self):
        units = self.doc["legatto_units"]
        for key, name in (("console", "legatto-console.service"), ("console_socket", "legatto-console.socket"),
                          ("console_exec", "legatto-console-exec.path"),
                          ("console_exec_service", "legatto-console-exec.service"),
                          ("console_exec_maint", "legatto-console-exec-maint.timer")):
            self.assertEqual(units[key], name)


class SpoolLayout(unittest.TestCase):
    def test_contract_spool_modes(self):
        # CONTRACT §4.3 table
        modes = {spec.path: (spec.mode, spec.group) for spec in executor.SPOOL_LAYOUT}
        self.assertEqual(modes[contract.REQUESTS_INCOMING], (0o730, contract.CONSOLE_GROUP))
        self.assertEqual(modes[contract.REQUESTS_PROCESSING], (0o700, None))
        self.assertEqual(modes[contract.REQUESTS_RESULTS], (0o750, contract.CONSOLE_GROUP))
        self.assertEqual(modes[contract.REQUESTS_ARCHIVE], (0o700, None))


if __name__ == "__main__":
    unittest.main()
