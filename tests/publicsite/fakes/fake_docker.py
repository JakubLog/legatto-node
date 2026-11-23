#!/usr/bin/env python3
"""Stand-in for `docker run` of the app image in tests/publicsite.

Records every invocation (argv parsed into network, env, mounts, command) to
$FAKE_STATE/docker.jsonl and emulates the container side of the agreed
interfaces:
  intake.mjs fetch|process|selftest|keygen   (legatto-app server/intake)
  site.mjs claim|snapshot|build|finish       (legatto-app site generator)
  tools.mjs worker-deploy|worker-rollback|worker-state|pages-deploy|pages-state  (worker bundle)
The queue is a JSON model of Cloudflare Queues HTTP pull (lease, ack, retry).
Behaviour switches are files in $FAKE_STATE (db_down, process_crash, ...).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

STATE = Path(os.environ.get("FAKE_STATE", "/var/lib/fake-cloud"))  # default: inside the roles test container
STATE.mkdir(parents=True, exist_ok=True)
LEASE_SECONDS = 900


def parse(argv: list[str]) -> dict:
    assert argv[0] == "run", argv
    spec = {"network": None, "env": {}, "mounts": {}, "readonly": {}, "user": None, "flags": []}
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in ("--rm", "--read-only"):
            spec["flags"].append(arg)
            i += 1
        elif arg.startswith("--pull="):
            spec["flags"].append(arg)
            i += 1
        elif arg in ("--name", "--network", "--user", "--cap-drop", "--security-opt", "--pids-limit", "--memory",
                     "--tmpfs", "--entrypoint", "--log-driver", "-e", "--mount"):
            value = argv[i + 1]
            if arg == "--network":
                spec["network"] = value
            elif arg == "--user":
                spec["user"] = value
            elif arg == "-e":
                key, _, val = value.partition("=")
                spec["env"][key] = val
            elif arg == "--mount":
                parts = dict(p.split("=", 1) if "=" in p else (p, True) for p in value.split(","))
                spec["mounts"][parts["dst"]] = parts["src"]
                spec["readonly"][parts["dst"]] = "readonly" in parts
            else:
                spec["flags"].append(f"{arg}={value}")
            i += 2
        else:
            spec["image"] = arg
            spec["command"] = argv[i + 1:]
            break
    return spec


def load(name: str, default):
    target = STATE / name
    return json.loads(target.read_text()) if target.exists() else default


def save(name: str, obj) -> None:
    (STATE / name).write_text(json.dumps(obj, indent=1))


def out(obj, code: int = 0) -> None:
    print(json.dumps(obj))
    sys.exit(code)


def host(spec: dict, container_path: str) -> Path:
    for dst, src in spec["mounts"].items():
        if container_path == dst or container_path.startswith(dst + "/"):
            return Path(src + container_path[len(dst):])
    raise SystemExit(f"fake_docker: {container_path} is not mounted")


def write_json(target: Path, obj) -> None:
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj))
    os.replace(tmp, target)


# --- intake ----------------------------------------------------------------------------


def intake_fetch(spec: dict) -> None:
    queue = load("queue.json", {"messages": []})
    now = time.time()
    acked = retried = 0
    acks = host(spec, "/intake/acks")
    by_id = {m["id"]: m for m in queue["messages"]}
    lease_rejected = (STATE / "ack_lease_invalid").exists()  # Cloudflare: lease no longer valid
    for ack_file in sorted(acks.glob("*.json")):
        ack = json.loads(ack_file.read_text())
        msg = by_id.get(ack["msg_id"])
        if (msg and not lease_rejected and not msg["acked"] and msg["lease"] == ack["lease_id"]
                and msg["leased_until"] > now):
            if ack["action"] == "ack":
                msg["acked"] = True
                acked += 1
            else:
                msg["leased_until"] = 0
                retried += 1
        ack_file.unlink()  # sent (or the lease was no longer valid)
    pulled = 0
    inbox = host(spec, "/intake/inbox")
    for msg in queue["messages"]:
        if msg["acked"] or msg["leased_until"] > now:
            continue
        msg["lease"] = uuid.uuid4().hex
        msg["leased_until"] = now + LEASE_SECONDS
        msg["attempts"] += 1
        record = {"v": 1, "queue": "forms", "msg_id": msg["id"], "lease_id": msg["lease"], "attempts": msg["attempts"],
                  "timestamp_ms": int(msg["sent"] * 1000), "body_b64": msg["body_b64"]}
        write_json(inbox / f"{msg['id']}.json", record)
        pulled += 1
    save("queue.json", queue)
    backlog = sum(1 for m in queue["messages"] if not m["acked"])
    out({"ok": True, "acked": acked, "retried": retried, "pulled": pulled, "backlog": backlog})


def intake_process(spec: dict) -> None:
    if (STATE / "process_crash").exists():
        print("simulated crash", file=sys.stderr)
        sys.exit(1)
    db = load("db.json", {"cases": [], "receipts": []})
    markers = load("pending_markers.json", [])
    inbox = host(spec, "/intake/inbox")
    acks = host(spec, "/intake/acks")
    counts = {"processed": 0, "inserted": 0, "duplicate": 0, "retry": 0, "selftest": []}
    db_down = (STATE / "db_down").exists()
    for entry in sorted(inbox.glob("*.json")):
        msg = json.loads(entry.read_text())
        body = base64.b64decode(msg["body_b64"])
        receipt = hashlib.sha256(body[654:]).hexdigest()  # app receipts are keyed on the sealed form
        if db_down:
            outcome, action = "retry", "retry"
            counts["retry"] += 1
        elif body[5] == 2:
            outcome, action = "selftest", "ack"
            if markers:
                counts["selftest"].append({"marker": markers.pop(0), "outcome": "selftest"})
        elif receipt in db["receipts"]:
            outcome, action = "duplicate", "ack"
            counts["duplicate"] += 1
        else:
            db["cases"].append(receipt)
            db["receipts"].append(receipt)
            outcome, action = "inserted", "ack"
            counts["inserted"] += 1
        save("db.json", db)  # commit before the ack exists
        write_json(acks / f"{msg['msg_id']}.json", {"v": 1, "queue": msg["queue"], "msg_id": msg["msg_id"],
                                                    "lease_id": msg["lease_id"], "action": action, "outcome": outcome})
        entry.unlink()
        counts["processed"] += 1
    save("pending_markers.json", markers)
    out({"ok": True, **counts}, 10 if db_down else 0)


def intake_selftest(spec: dict, args: list[str]) -> None:
    marker = args[args.index("--marker") + 1]
    if (STATE / "selftest_lost").exists():
        out({"ok": True, "status": 202, "ref": "deadbeef"})
    markers = load("pending_markers.json", [])
    markers.append(marker)
    save("pending_markers.json", markers)
    # The Worker would now enqueue a selftest envelope (selftest_plaintext: a
    # broken Worker that lets the frame text into the queue).
    form_key = json.loads(host(spec, "/etc/legatto/intake/form-key.json").read_text())
    leak = ('{"kind":"selftest","marker":"%s"}' % marker).encode() if (STATE / "selftest_plaintext").exists() else b""
    envelope = worker_envelope(2, bytes.fromhex(form_key["kid"]), leak)
    queue = load("queue.json", {"messages": []})
    queue["messages"].append({"id": f"selftest-{marker[:8]}", "body_b64": base64.b64encode(envelope).decode(), "lease": None,
                              "leased_until": 0, "acked": False, "attempts": 0, "sent": time.time()})
    save("queue.json", queue)
    out({"ok": True, "status": 202, "ref": hashlib.sha256(envelope[654:]).hexdigest()[:8]})  # sha256 of the sealed form


def intake_keygen(spec: dict, args: list[str]) -> None:
    key_out = host(spec, args[args.index("--out") + 1])
    pub = hashlib.sha256(b"fake x25519 public").digest()
    key_out.write_text(f"{hashlib.sha256(pub).hexdigest()[:16]} {base64.b64encode(b'k' * 32).decode()}\n")
    out({"kid": hashlib.sha256(pub).hexdigest()[:16], "x25519": base64.b64encode(pub).decode()})


def worker_envelope(kind: int, office_kid: bytes, leak: bytes = b"") -> bytes:
    """Envelope signed with the Worker key that worker-deploy uploaded (like the real Worker)."""
    sys.path.insert(0, os.environ.get("FAKE_SBIN", "/opt/legatto/sbin"))
    from legatto_publicsite import ed25519, envelope

    seed = base64.b64decode((STATE / "worker_signing_key").read_text())
    header = (envelope.MAGIC + bytes([envelope.VERSION, kind]) + office_kid
              + ed25519.key_id(ed25519.public_key(seed)) + int(time.time() * 1000).to_bytes(8, "big"))
    rest = os.urandom(envelope.META_CT_SIZE + envelope.FORM_CT_SIZE)
    rest = rest[:envelope.META_CT_SIZE] + leak + rest[envelope.META_CT_SIZE + len(leak):]
    return header + ed25519.sign(seed, envelope.SIGNATURE_DOMAIN + header + rest) + rest


# --- site ------------------------------------------------------------------------------------


def site(spec: dict, args: list[str]) -> None:
    command = args[0]
    if command == "claim":
        jobs = load("jobs.json", [])
        job = jobs.pop(0) if jobs else None
        save("jobs.json", jobs)
        out({"job": job, "reason": "manual"})
    if command == "snapshot":
        target = host(spec, args[args.index("--out") + 1])
        (target / "snapshot.json").write_text(json.dumps({"identity": {"name": "Jan Poseł"}}))
        out({"ok": True, "assets": 0, "sha256": "0" * 64})
    if command == "build":
        dist = host(spec, args[args.index("--out") + 1])
        config = json.loads(host(spec, args[args.index("--site-config") + 1]).read_text())
        (dist / "data").mkdir(exist_ok=True)
        (dist / "index.html").write_text("<!doctype html><h1>Jan Poseł</h1><script src=/app.js></script>")
        (dist / "app.js").write_text(Path(STATE / "site_js.txt").read_text() if (STATE / "site_js.txt").exists() else "console.log(1)")
        (dist / "data" / "form-key.json").write_text(json.dumps(config["form_key"]))
        (dist / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'\n")
        out({"ok": True, "files": 3, "bytes": 100})
    if command == "finish":
        finished = load("finished.json", [])
        finished.append(args[1:])
        save("finished.json", finished)
        out({"ok": True})
    raise SystemExit(f"fake site: unknown {command}")


# --- tools.mjs ----------------------------------------------------------------------------------


def tools(spec: dict, args: list[str]) -> None:
    command = args[0]
    cf = load("cf.json", {"worker_versions": [], "pages": None, "deploy_fail": False, "seq": 0})
    if command == "worker-deploy":
        config = json.loads(host(spec, "/cfg/deploy.json").read_text())
        secrets_given = "--secrets" in args
        if secrets_given:  # Cloudflare keeps the Worker secret; the fake Worker signs with it
            uploaded = json.loads(host(spec, "/cfg/secrets.json").read_text())
            (STATE / "worker_signing_key").write_text(uploaded["SIGNING_KEY"])
        if not cf["worker_versions"] and not secrets_given:
            out({"ok": False, "error": "first deployment needs the Worker secrets"}, 1)
        cf["seq"] += 1
        previous = cf["worker_versions"]
        version = f"{cf['seq']:032x}"
        cf["worker_versions"] = [{"version_id": version, "percentage": 100}]
        cf.setdefault("deploys", []).append({"release": config["release"], "secrets": secrets_given})
        if cf["deploy_fail"] and previous:
            cf["worker_versions"] = previous
            save("cf.json", cf)
            out({"ok": False, "version_id": version, "previous_versions": previous, "rolled_back": True, "error": "unhealthy"}, 60)
        save("cf.json", cf)
        out({"ok": True, "version_id": version, "previous_versions": previous, "rolled_back": False})
    if command == "worker-rollback":
        cf["worker_versions"] = json.loads(host(spec, "/cfg/versions.json").read_text())
        cf.setdefault("rollbacks", 0)
        cf["rollbacks"] += 1
        save("cf.json", cf)
        out({"ok": True})
    if command == "worker-state":
        out({"ok": True, "deployment_id": "d", "versions": cf["worker_versions"]})
    if command == "pages-deploy":
        cf["seq"] += 1
        cf["pages"] = f"pages-{cf['seq']}"
        dist = host(spec, args[args.index("--dir") + 1])
        cf["pages_files"] = sorted(p.relative_to(dist).as_posix() for p in dist.rglob("*") if p.is_file())
        save("cf.json", cf)
        out({"ok": True, "deployment_id": cf["pages"], "files": len(cf["pages_files"]), "uploaded": 1})
    if command == "pages-state":
        out({"ok": True, "latest": {"id": cf["pages"], "created_on": "2026-11-21T00:00:00Z"} if cf["pages"] else None})
    raise SystemExit(f"fake tools: unknown {command}")


def db_exec(argv: list[str]) -> None:
    """`docker exec -i supabase-db psql ...` with SQL on stdin."""
    sql = sys.stdin.read()
    with open(STATE / "db_exec.jsonl", "a") as log:
        log.write(json.dumps({"argv": argv, "sql": sql}) + "\n")
    roles = load("db_roles.json", ["legatto_intake", "legatto_publisher"])
    if not any(f"rolname = '{r}'" in sql for r in roles):
        print("ERROR:  legatto_role_missing", file=sys.stderr)
        sys.exit(3)
    sys.exit(0)


def main() -> None:
    if sys.argv[1] == "exec":
        db_exec(sys.argv[1:])
    spec = parse(sys.argv[1:])
    with open(STATE / "docker.jsonl", "a") as log:
        log.write(json.dumps(spec) + "\n")
    command = spec["command"]
    if command[0] == "/app/server/intake.mjs":
        {"fetch": lambda: intake_fetch(spec), "process": lambda: intake_process(spec),
         "selftest": lambda: intake_selftest(spec, command[2:]), "keygen": lambda: intake_keygen(spec, command[2:])}[command[1]]()
    elif command[0] == "/app/server/site.mjs":
        site(spec, command[1:])
    elif command[0] == "/w/tools.mjs":
        tools(spec, command[1:])
    raise SystemExit(f"fake_docker: unexpected command {command}")


if __name__ == "__main__":
    main()
