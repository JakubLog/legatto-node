#!/usr/bin/env python3
"""Stand-in for `legatto-audit append`: records entries in $FAKE_STATE/audit.jsonl."""
import json
import os
import sys

args = sys.argv[1:]
assert args[0] == "append"
entry = {args[i].lstrip("-"): args[i + 1] for i in range(1, len(args), 2)}
entry["actor"] = json.loads(entry["actor"])
entry["params"] = json.loads(entry["params"])
path = os.path.join(os.environ.get("FAKE_STATE", "/var/lib/fake-cloud"), "audit.jsonl")
with open(path, "a") as handle:
    handle.write(json.dumps(entry) + "\n")
print(json.dumps({"seq": 1, "hash": "0" * 64}))
