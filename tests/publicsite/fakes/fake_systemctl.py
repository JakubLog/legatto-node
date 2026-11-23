#!/usr/bin/env python3
"""Stand-in for systemctl: `start <unit>` runs the unit's ExecStart (the tool) synchronously."""
import json
import os
import subprocess
import sys

args = sys.argv[1:]
with open(os.path.join(os.environ["FAKE_STATE"], "systemctl.jsonl"), "a") as handle:
    handle.write(json.dumps(args) + "\n")
units = {
    "legatto-intake-process.service": ["legatto-intake", "process"],
    "legatto-intake-fetch.service": ["legatto-intake", "fetch"],
}
if args[0] == "start" and args[1] in units:
    tool, command = units[args[1]]
    sbin = os.environ["FAKE_SBIN"]
    result = subprocess.run([sys.executable, os.path.join(sbin, tool), command], check=False,
                            stdout=subprocess.DEVNULL)
    sys.exit(0 if result.returncode == 0 else 1)
sys.exit(0)
