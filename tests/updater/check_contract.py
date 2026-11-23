"""Static check of legatto-update against the contract.

Every `# contract: <key>` constant in updater/legatto_update/const.py equals
the value in contract/contract.yml (passed as JSON, converted by yq).
"""

import ast
import json
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def lookup(data, dotted):
    node = data
    for part in dotted.split("."):
        node = node[part]
    return node


def contract_constants(contract):
    path = os.path.join(REPO, "updater", "legatto_update", "const.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    lines = source.splitlines()
    errors, checked = [], 0
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) else node.target
        comment = " ".join(lines[node.lineno - 1:node.end_lineno])
        m = re.search(r"# contract: ([A-Za-z0-9_.]+)", comment)
        if not m:
            continue
        value = ast.literal_eval(node.value)
        expected = lookup(contract, m.group(1))
        if m.group(1) == "legatto_office_env":
            ok = sorted(value) == sorted(expected)  # values are per-office templates
        else:
            ok = json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)
        if not ok:
            errors.append("%s = %r, contract %s = %r" % (target.id, value, m.group(1), expected))
        checked += 1
    return errors, checked


def main():
    with open(sys.argv[1], encoding="utf-8") as fh:
        contract = json.load(fh)
    errors, checked = contract_constants(contract)
    for e in errors:
        print("contract mismatch: " + e)
    print("checked %d contract constants" % checked)
    return 1 if errors or checked < 40 else 0


if __name__ == "__main__":
    sys.exit(main())
