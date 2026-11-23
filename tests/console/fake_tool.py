#!/usr/bin/python3
"""Stand-in for the host tools of other lanes in the console tests.

Installed under <prefix>/opt/legatto/sbin/<name> and <prefix>/usr/bin/tailscale.
Every call is appended to <prefix>/fake/calls.jsonl. Behaviour per tool and
subcommand comes from <prefix>/fake/<name>.json: {"<subcommand>": {"rc": N,
"stdout": <json>}}. legatto-audit and tailscale have built-in behaviour that
mirrors the real interfaces (CONTRACT §4.2, `tailscale whois --json`).
"""

import hashlib
import json
import os
import sys

name = os.path.basename(sys.argv[0])
here = os.path.abspath(sys.argv[0])
for suffix in ("/opt/legatto/sbin/" + name, "/usr/bin/" + name):
    if here.endswith(suffix):
        prefix = here[: -len(suffix)]
        break
else:
    sys.exit("fake_tool: unknown install location " + here)
fake = os.path.join(prefix, "fake")
args = sys.argv[1:]
with open(os.path.join(fake, "calls.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": name, "argv": args}) + "\n")
# Cross-lane CLI contract test (tests/integration): exact argv of every call. The
# executor clears the environment of its tools, so the recorder is a directory
# mounted only by tests/integration/run.sh.
if os.path.isdir("/legatto-cli-record"):
    with open("/legatto-cli-record/console.jsonl", "a", encoding="utf-8") as record:
        record.write(json.dumps({"caller": "legatto-console-exec", "tool": name, "argv": args}) + "\n")

FORBIDDEN = ("password", "passwd", "totp", "secret", "token", "authkey", "auth_key", "preauth", "private")


def forbidden(obj):
    if isinstance(obj, dict):
        return any(any(p in str(k).lower() for p in FORBIDDEN) or forbidden(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(forbidden(v) for v in obj)
    return False


if name == "legatto-audit":
    opts = dict(zip(args[1::2], args[2::2]))
    cat, event = opts.get("--cat"), opts.get("--event", "")
    actor, params = json.loads(opts["--actor"]), json.loads(opts["--params"])
    if args[0] != "append" or event.split(".", 1)[0] != cat or forbidden(params) \
            or set(actor) - {"kind", "id", "node", "ip", "user"}:
        sys.stderr.write("fake legatto-audit: invalid entry\n")
        sys.exit(2)
    path = os.path.join(prefix, "var/log/legatto/audit.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    seq = 1
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            seq = sum(1 for _ in handle) + 1
    entry = {"seq": seq, "ts": "2026-11-21T10:00:00Z", "host": "test", "cat": cat, "event": event, "actor": actor,
             "node": opts.get("--node"), "params": params, "prev": "0" * 64}
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    print(json.dumps({"seq": seq, "hash": entry["hash"]}))
    sys.exit(0)

if name == "tailscale":
    with open(os.path.join(fake, "whois.json"), encoding="utf-8") as handle:
        table = json.load(handle)
    node = table.get(args[-1])
    if args[:2] != ["whois", "--json"] or node is None:
        sys.exit(1)
    print(json.dumps({"Node": node, "UserProfile": {"LoginName": "x"}}))
    sys.exit(0)

config_path = os.path.join(fake, name + ".json")
config = {}
if os.path.exists(config_path):
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
behaviour = config.get(args[0] if args else "")
if behaviour is None:
    behaviour = {"rc": 0} if name == "legatto-recovery-pack" else {"rc": 0, "stdout": {}}
if name == "legatto-recovery-pack" and args[:1] == ["generate"] and behaviour.get("rc", 0) == 0 \
        and "stdout" not in behaviour:
    directory = os.path.join(prefix, "var/lib/legatto/recovery")
    os.makedirs(directory, exist_ok=True)
    pack = os.path.join(directory, "legatto-recovery-test-20261121T100000Z.tar.age")
    card = os.path.join(directory, "legatto-recovery-test-20261121T100000Z-karta.html")
    for path, content in ((pack, b"age-encrypted-test-pack"), (card, b"<html>card</html>")):
        with open(path, "wb") as handle:
            handle.write(content)
    behaviour = {"rc": 0, "stdout": {"v": 1, "file": pack, "card": card, "sha256": hashlib.sha256(b"x").hexdigest(),
                                     "bytes": 23, "password": "jeden dwa trzy cztery piec szesc siedem osiem dziewiec dziesiec",
                                     "items": ["console-emergency"]}}
if behaviour.get("stdout") is not None:
    print(json.dumps(behaviour["stdout"]))
sys.exit(int(behaviour.get("rc", 0)))
