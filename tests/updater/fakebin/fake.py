#!/usr/bin/env python3
"""Stand-ins for host tools the updater calls (docker, systemctl, legatto-audit,
legatto-egress, legatto-stack, legatto-secrets, legatto-worker-deploy,
systemd-analyze). Dispatches on the name it was called as; every call is
appended to $LEGATTO_TEST_ROOT/fake/calls.log. Behaviour is steered by files
in $LEGATTO_TEST_ROOT/fake/. Python >= 3.9."""

import hashlib
import json
import os
import sys
import tarfile

ROOT = os.environ["LEGATTO_TEST_ROOT"]
FAKE = os.path.join(ROOT, "fake")


def path(*parts):
    return os.path.join(FAKE, *parts)


def log(tool, args):
    os.makedirs(FAKE, exist_ok=True)
    with open(path("calls.log"), "a") as fh:
        fh.write(json.dumps([tool] + args) + "\n")
    # Cross-lane CLI contract test (tests/integration): exact argv of every call.
    record = os.environ.get("LEGATTO_CLI_RECORD")
    if record:
        with open(record, "a") as fh:
            fh.write(json.dumps({"caller": "legatto-update", "tool": tool, "argv": args}) + "\n")


def flag(name):
    return os.path.exists(path(name))


def read_json(p, default):
    try:
        with open(p) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_json(p, data):
    with open(p, "w") as fh:
        json.dump(data, fh)


def opt(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    return default


def current_version():
    cur = os.path.join(ROOT, "opt/legatto/current/manifest.json")
    try:
        with open(cur) as fh:
            return json.load(fh)["version"]
    except FileNotFoundError:
        return None


def healthy():
    unhealthy = read_json(path("unhealthy.json"), [])
    return current_version() not in unhealthy


def audit(args):
    if flag("audit_fail"):
        return 1
    if args[:1] != ["append"]:
        return 2
    logp = os.path.join(ROOT, "var/log/legatto/audit.log")
    os.makedirs(os.path.dirname(logp), exist_ok=True)
    seq = 1
    if os.path.exists(logp):
        with open(logp) as fh:
            seq = sum(1 for _ in fh) + 1
    entry = {"seq": seq, "cat": opt(args, "--cat"), "event": opt(args, "--event"),
             "actor": json.loads(opt(args, "--actor")), "node": opt(args, "--node"),
             "params": json.loads(opt(args, "--params"))}
    with open(logp, "a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    print(json.dumps({"seq": seq, "hash": hashlib.sha256(json.dumps(entry).encode()).hexdigest()}))
    return 0


def docker(args):
    images = set(read_json(path("images.json"), []))
    if args[:1] == ["load"]:
        with tarfile.open(opt(args, "-i")) as tf:
            index = json.load(tf.extractfile("index.json"))
        for desc in index["manifests"]:
            ref = desc["annotations"]["io.containerd.image.name"]
            images.add("%s@%s" % (ref.rsplit(":", 1)[0], desc["digest"]))
        write_json(path("images.json"), sorted(images))
        return 0
    if args[:2] == ["image", "inspect"]:
        return 0 if args[-1] in images else 1
    if args[:2] == ["image", "rm"]:
        images.discard(args[-1])
        write_json(path("images.json"), sorted(images))
        return 0
    if args[:1] == ["compose"] and "config" in args:
        compose = os.path.dirname(opt(args, "--project-directory").rstrip("/"))
        with open(os.path.join(compose, "fake-config.json")) as fh:
            text = fh.read()
        print(text.replace("@COMPOSE@", compose).replace("@ROOT@", ROOT))
        return 0
    if args[:2] == ["exec", "supabase-db"]:
        level = read_json(path("db.json"), {"level": ""})["level"]
        print(level)
        return 0
    return 3


def stack(args):
    cmd = args[0]
    if cmd == "check":
        return 42 if flag("stack_check_fail") else 0
    if cmd == "migrate":
        if "--check" in args:
            return 10 if flag("migrate_check_fail") else 0
        mig = os.path.join(os.path.dirname(opt(args, "--compose-dir").rstrip("/")), "migrations")
        db = read_json(path("db.json"), {"level": "", "applied": []})
        for name in sorted(os.listdir(mig)) if os.path.isdir(mig) else []:
            if name not in db.setdefault("applied", []):
                db["applied"].append(name)
            db["level"] = max(db["level"], name[:14])
        write_json(path("db.json"), db)
        return 0
    if cmd == "stop":
        return 0
    if cmd == "status":
        print(json.dumps({"v": 1, "ok": healthy(), "services": {}}))
        return 0
    if cmd == "probe":
        return 0 if healthy() else 43
    return 2


def secrets(args):
    if args[:1] != ["render"]:
        return 2
    tdir = opt(args, "--templates")
    if "--check" in args:
        for name in os.listdir(tdir):
            with open(os.path.join(tdir, name)) as fh:
                if "FORBIDDEN" in fh.read():
                    return 42
    return 0


def triples(manifest_dir):
    if manifest_dir == "none" or not os.path.isfile(os.path.join(manifest_dir, "manifest.json")):
        return set()
    with open(os.path.join(manifest_dir, "manifest.json")) as fh:
        eg = json.load(fh)["egress"]
    out = set()
    for role, entries in eg["roles"].items():
        out |= {("base", role, e["host"], e["port"]) for e in entries}
    for feat, roles in eg["features"].items():
        for role, entries in roles.items():
            out |= {("feature:" + feat, role, e["host"], e["port"]) for e in entries}
    return out


def egress(args):
    cmd = args[0]
    if cmd == "render":
        os.makedirs(opt(args, "--out"), exist_ok=True)
        return 0
    if cmd == "check":
        return 0
    if cmd == "diff":
        old, new = triples(opt(args, "--from")), triples(opt(args, "--to"))
        added = [{"source": s, "role": r, "host": h, "port": p, "active": s == "base"} for s, r, h, p in sorted(new - old)]
        removed = [{"source": s, "role": r, "host": h, "port": p, "active": s == "base"} for s, r, h, p in sorted(old - new)]
        print(json.dumps({"widening": bool(added), "added": added, "removed": removed, "pinned_removed": []}))
        if any(e["host"] == "updates.legatto.pl" for e in removed):
            return 41
        return 40 if added else 0
    if cmd == "apply":
        with open(path("egress_applied"), "w") as fh:
            fh.write(opt(args, "--release-dir"))
        return 0
    if cmd == "selftest":
        return 43 if flag("egress_selftest_fail") else 0
    return 2


def worker(args):
    rc = read_json(path("worker_rc.json"), 0)
    return rc


def main():
    tool = os.path.basename(sys.argv[0])
    args = sys.argv[1:]
    log(tool, args)
    if tool == "legatto-audit":
        return audit(args)
    if tool == "docker":
        return docker(args)
    if tool == "legatto-stack":
        return stack(args)
    if tool == "legatto-secrets":
        return secrets(args)
    if tool == "legatto-egress":
        return egress(args)
    if tool == "legatto-worker-deploy":
        return worker(args)
    if tool in ("systemctl", "systemd-analyze", "apt-get"):
        return 0
    if tool == "dpkg-query":
        return 1  # package not installed: the updater installs it
    return 127


if __name__ == "__main__":
    sys.exit(main())
