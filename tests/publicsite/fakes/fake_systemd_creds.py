#!/usr/bin/env python3
"""Stand-in for systemd-creds in tests: "encryption" is a plain copy marked with a header."""
import sys
from pathlib import Path

HEADER = b"FAKE-CREDS\n"
args = sys.argv[1:]
command, name = args[0], args[1].split("=", 1)[1]
if command == "encrypt":
    Path(args[3]).write_bytes(HEADER + sys.stdin.buffer.read())
elif command == "decrypt":
    data = Path(args[2]).read_bytes()
    assert data.startswith(HEADER), "not a credential"
    Path(args[3]).write_bytes(data[len(HEADER):])
else:
    sys.exit(2)
