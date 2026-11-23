"""Every `# contract: <key>` constant in the net tools equals contract/contract.yml."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

import yaml

from harness import LIB, REPO, TOOLS

CONTRACT = os.path.join(REPO, "contract", "contract.yml")
COMMENT = re.compile(r"^(?P<name>[A-Z][A-Z0-9_]*)\s*=.*#\s*contract:\s*(?P<key>[a-z0-9_.]+)")


def load_module(path: str, name: str) -> object:
    saved_path = os.environ.get("PATH")
    os.environ.pop("LEGATTO_TEST_ROOT", None)
    sys.path.insert(0, LIB)
    try:
        spec = spec_from_loader(name, SourceFileLoader(name, path))
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.environ["PATH"] = saved_path or ""
        sys.path.remove(LIB)


def lookup(contract: dict, key: str) -> object:
    value: object = contract
    for part in key.split("."):
        value = value[part]
    return value


def normalise(value: object) -> object:
    if isinstance(value, re.Pattern):
        return value.pattern
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    if isinstance(value, tuple):
        return [normalise(v) for v in value]
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items()}
    return value


class ContractConstantsTest(unittest.TestCase):
    def test_constants_match_contract(self) -> None:
        with open(CONTRACT, encoding="utf-8") as fh:
            contract = yaml.safe_load(fh)
        files = {"legatto_net": os.path.join(LIB, "legatto_net.py")}
        files.update({name.replace("-", "_"): path for name, path in TOOLS.items()})
        checked = 0
        for module_name, path in files.items():
            module = load_module(path, module_name)
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    match = COMMENT.match(line)
                    if not match:
                        continue
                    with self.subTest(file=os.path.basename(path), constant=match["name"]):
                        expected = lookup(contract, match["key"])
                        # ROOT is "" here, so path constants compare as on the server
                        self.assertEqual(normalise(getattr(module, match["name"])), expected)
                        checked += 1
        self.assertGreater(checked, 30)


if __name__ == "__main__":
    unittest.main()
