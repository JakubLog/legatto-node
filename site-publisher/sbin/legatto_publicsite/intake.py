"""legatto-intake — office side of the public form queue (R9: two processes).

  fetch     unit legatto-intake-fetch.service (timer, every 2 min)
            1. container `intake.mjs fetch`: network legatto-egress-intake via the
               intake proxy, Queues token, NO key, NO database. It acks every
               acks/<msg>.json and pulls new messages into inbox/.
            2. host gate (this file): outer envelope check with public keys only
               (size, magic, Worker signature against signers.d, office key id,
               age, replay ledger). Bad -> quarantine/ + ack; good -> ready/.
            3. starts legatto-intake-process.service when ready/ is not empty.
  process   unit legatto-intake-process.service
            container `intake.mjs process`: network legatto-int (database only),
            office X25519 key and DB role legatto_intake, NO external network.
            Reads ready/ (mounted as /intake/inbox), writes acks/ after commit.
  selftest  signed POST /api/selftest through the Worker (--mode verify: the
            processor also files a "[VERIFY] <marker>" case in the CRM).
            --wait S follows the envelope and proves, within S seconds:
              queue    the message the Queues token pulled is a fixed-size
                       ciphertext without the marker or any frame text (the
                       host gate keeps a copy of self-test envelopes only);
              received the processor stored it and reported the marker;
              removed  Cloudflare accepted the ack (gone from the queue).
  keygen    office X25519 form key (container, no network) + self-test key.
  db-role   password of the DB roles legatto_intake / legatto_publisher (SCRAM verifier).
  status    contents of status/intake.json.

Exit codes: 0 OK, 1 error, 2 usage, 3 locked, 4 precondition (no Cloudflare
bootstrap, no release, no keys), 30 self-test not received or not removed in
time, 31 key already exists (keygen without --rotate), 32 self-test proof
failed (plaintext in the queue, or the ack was not accepted).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

from . import common, ed25519, envelope
from .common import ContainerSpec, Credentials, Mount, fail, path

TOOL = "legatto-intake"
EXIT_SELFTEST_TIMEOUT = 30
EXIT_KEY_EXISTS = 31
EXIT_SELFTEST_FAILED = 32

INTAKE_CLI = "/app/server/intake.mjs"
CONTAINER_STATE = "/intake"
CONTAINER_CREDENTIALS = "/run/credentials"
CONTAINER_CA = "/etc/legatto/ca/cloudflare-api.pem"  # contract: legatto_paths.cf_ca_bundle
CONTAINER_SIGNERS = "/etc/legatto/intake/signers.d"
LEDGER_TTL_SECONDS = 17 * 24 * 3600  # > envelope max age (16 days)
STATS_WINDOW_SECONDS = 24 * 3600
FINAL_ACTIONS = {"ack"}
MSG_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MARKER_RE = re.compile(r"^[0-9a-f]{32}$")
REF_RE = re.compile(r"^[0-9a-f]{8}$")
UNIT_INTAKE_FETCH = "legatto-intake-fetch.service"  # contract: legatto_units.intake_fetch_service


# --- state ------------------------------------------------------------------------------


class Dirs:
    def __init__(self) -> None:
        base = path(common.P_INTAKE)
        self.base = base
        self.inbox = base / "inbox"
        self.ready = base / "ready"
        self.acks = base / "acks"
        self.quarantine = base / "quarantine"
        self.state = base / "state"
        self.selftest = self.state / "selftest"  # gate copies of self-test envelopes (root only)

    def prepare(self) -> None:
        common.ensure_dir(self.base, 0o750)
        # Written by the containers (uid 65532): private to that uid.
        for directory in (self.inbox, self.ready, self.acks, self.quarantine):
            common.ensure_dir(directory, 0o700, common.CONTAINER_UID, common.CONTAINER_UID)
        common.ensure_dir(self.state, 0o700, 0, 0)
        common.ensure_dir(self.selftest, 0o700, 0, 0)


def _load_state(dirs: Dirs) -> dict[str, Any]:
    state = common.read_json(dirs.state / "state.json", {})
    state.setdefault("ledger", {})  # envelope sha256 -> finalised at (epoch s)
    state.setdefault("inflight", {})  # msg_id -> envelope sha256 (file in ready/)
    state.setdefault("events", [])  # [epoch s, "quarantined"|"retry"] for the 24 h failure count
    state.setdefault("selftest", {})  # marker -> {"outcome", "at"}
    state.setdefault("selftest_queue", {})  # form ref -> {"msg_id", "at", "ack"}: self-test trace
    state.setdefault("backlog", None)
    state.setdefault("last_ok_at", None)
    return state


def _save_state(dirs: Dirs, state: dict[str, Any]) -> None:
    now = time.time()
    state["ledger"] = {k: v for k, v in state["ledger"].items() if now - v < LEDGER_TTL_SECONDS}
    state["events"] = [e for e in state["events"] if now - e[0] < STATS_WINDOW_SECONDS]
    state["selftest"] = {k: v for k, v in state["selftest"].items() if now - v["at"] < STATS_WINDOW_SECONDS}
    for ref, trace in list(state["selftest_queue"].items()):
        if now - trace["at"] >= STATS_WINDOW_SECONDS:
            del state["selftest_queue"][ref]
            (dirs.selftest / f"{ref}.bin").unlink(missing_ok=True)
    common.write_json_atomic(dirs.state / "state.json", state, 0o600)


def _write_status(dirs: Dirs, state: dict[str, Any], ok: bool) -> None:
    quarantined = len(list(dirs.quarantine.glob("*.bin")))
    failed = sum(1 for e in state["events"] if time.time() - e[0] < STATS_WINDOW_SECONDS)
    common.write_status("intake", ok, {
        "last_ok_at": state["last_ok_at"],
        "backlog": state["backlog"],
        "failed": failed,
        "quarantined": quarantined,
    })


def _office_kids() -> set[bytes]:
    """Key ids of every office X25519 key the processor holds (current + previous)."""
    kids: set[bytes] = set()
    for entry in sorted((path(common.P_INTAKE_ETC) / "keys").glob("*.json")):
        data = common.read_json(entry, {})
        try:
            pub = base64.b64decode(data.get("x25519", ""), validate=True)
        except (binascii.Error, AttributeError):
            continue
        if len(pub) == 32 and data.get("kid") == ed25519.key_id(pub).hex():
            kids.add(ed25519.key_id(pub))
    return kids


def _write_ack(dirs: Dirs, msg: dict[str, Any], outcome: str) -> None:
    ack = {"v": 1, "queue": msg["queue"], "msg_id": msg["msg_id"], "lease_id": msg["lease_id"],
           "action": "ack", "outcome": outcome}
    common.write_json_atomic(dirs.acks / f"{msg['msg_id']}.json", ack, 0o600, common.CONTAINER_UID, common.CONTAINER_UID)


def _quarantine(dirs: Dirs, msg: dict[str, Any], body: bytes, verdict: envelope.Verdict) -> None:
    name = msg["msg_id"]
    common.write_atomic(dirs.quarantine / f"{name}.bin", body, 0o600, common.CONTAINER_UID, common.CONTAINER_UID)
    meta = {"reason": verdict.reason, "at": common.utc_now(), "queue": msg["queue"], "kind": verdict.kind,
            "sha256": verdict.digest, "gate": "host"}
    common.write_json_atomic(dirs.quarantine / f"{name}.json", meta, 0o600, common.CONTAINER_UID, common.CONTAINER_UID)


def form_ref(body: bytes) -> str:
    """Receipt number the Worker returns for an envelope: sha256 of the sealed form (worker/src/index.ts)."""
    return hashlib.sha256(body[envelope.HEADER_SIZE + envelope.META_CT_SIZE:]).hexdigest()[:8]


def _trace_selftest(dirs: Dirs, state: dict[str, Any], msg_id: str, body: bytes) -> None:
    """Keeps the self-test envelope exactly as the Queues token pulled it, for `selftest --wait`.

    Only outer kind 2 is copied; the Worker sets it on /api/selftest alone, which
    the office self-test key authenticates, so no citizen submission is copied."""
    ref = form_ref(body)
    common.write_atomic(dirs.selftest / f"{ref}.bin", body, 0o600)
    state["selftest_queue"][ref] = {"msg_id": msg_id, "at": time.time(), "ack": None}



def gate(dirs: Dirs, state: dict[str, Any], now_ms: int | None = None) -> dict[str, Any]:
    """Moves inbox/ messages to ready/ or quarantine/ (+ ack); returns counters."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    signers = envelope.load_signers(path(common.P_INTAKE_ETC) / "signers.d")
    office_kids = _office_kids()
    if not signers or not office_kids:
        fail("no Worker signer keys or office form keys configured (signers.d / keys)", common.EXIT_PRECONDITION)
    inflight_digests = {digest: msg_id for msg_id, digest in state["inflight"].items()}
    counts = {"ready": 0, "quarantined": 0, "duplicate": 0, "held": 0, "invalid": 0}
    reasons: dict[str, int] = {}
    for entry in sorted(dirs.inbox.glob("*.json")):
        try:
            msg = json.loads(entry.read_text(encoding="utf-8"))
            if not (isinstance(msg, dict) and msg.get("v") == 1 and MSG_ID_RE.match(str(msg.get("msg_id")))
                    and isinstance(msg.get("lease_id"), str) and msg.get("queue") in ("forms", "dlq")):
                raise ValueError("bad inbox record")
            body = base64.b64decode(msg["body_b64"], validate=True)
        except (ValueError, KeyError, binascii.Error, json.JSONDecodeError):
            # Without a trustworthy msg_id/lease the message cannot be acked; it
            # returns after its lease expires and ends in the DLQ.
            entry.rename(dirs.quarantine / f"{entry.stem}.invalid")
            counts["invalid"] += 1
            continue
        msg_id = msg["msg_id"]
        if msg_id in state["inflight"]:
            continue  # still waiting for the processor
        verdict = envelope.check(body, office_kids, signers, now_ms)
        if not verdict.ok:
            _quarantine(dirs, msg, body, verdict)
            _write_ack(dirs, msg, "quarantined")
            entry.unlink()
            counts["quarantined"] += 1
            reasons[verdict.reason] = reasons.get(verdict.reason, 0) + 1
            state["events"].append([time.time(), "quarantined"])
            continue
        if verdict.digest in state["ledger"]:
            # Replay of an envelope already finalised (CF redelivery or re-push).
            _write_ack(dirs, msg, "duplicate")
            entry.unlink()
            counts["duplicate"] += 1
            continue
        if verdict.digest in inflight_digests:
            counts["held"] += 1  # same envelope already queued for the processor; decide after it
            continue
        os.replace(entry, dirs.ready / entry.name)
        state["inflight"][msg_id] = verdict.digest
        inflight_digests[verdict.digest] = msg_id
        counts["ready"] += 1
        if verdict.kind == "selftest":
            _trace_selftest(dirs, state, msg_id, body)
    counts["reasons"] = reasons
    return counts


def collect_acks(dirs: Dirs, state: dict[str, Any]) -> dict[str, Any]:
    """After the processor: finalise inflight messages from acks/ and count outcomes."""
    outcomes: dict[str, int] = {}
    reasons: dict[str, int] = {}
    for msg_id, digest in list(state["inflight"].items()):
        if (dirs.ready / f"{msg_id}.json").exists():
            continue  # not processed yet
        ack = common.read_json(dirs.acks / f"{msg_id}.json")
        del state["inflight"][msg_id]
        if not isinstance(ack, dict):
            continue  # processor dropped it without an ack: the lease expires and CF redelivers
        outcome = str(ack.get("outcome", "unknown"))
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if ack.get("action") in FINAL_ACTIONS:
            state["ledger"][digest] = time.time()
        else:
            state["events"].append([time.time(), "retry"])
        if outcome == "quarantined":
            state["events"].append([time.time(), "quarantined"])
            meta = common.read_json(dirs.quarantine / f"{msg_id}.json", {})
            reason = str(meta.get("reason", "unknown")) if isinstance(meta, dict) else "unknown"
            reasons[reason] = reasons.get(reason, 0) + 1
    return {"outcomes": outcomes, "reasons": reasons}


# --- containers ------------------------------------------------------------------------------


def _image() -> common.Image:
    image, _manifest = common.release_image(path(common.P_CURRENT))
    return image


def _fetch_spec(dirs: Dirs, cf: dict[str, Any], creds: Credentials, image: common.Image) -> ContainerSpec:
    env = {
        "LEGATTO_CF_ACCOUNT_ID": cf["account_id"],
        "LEGATTO_CF_QUEUE_ID": cf["queue"]["id"],
        "LEGATTO_CF_DLQ_ID": cf["dlq"]["id"],
        "LEGATTO_CF_QUEUES_TOKEN_FILE": f"{CONTAINER_CREDENTIALS}/{common.CRED_CF_QUEUES}",
        "LEGATTO_CF_CA_FILE": CONTAINER_CA,
    }
    env.update(common.proxy_env(common.PROXY_INTAKE))
    return ContainerSpec(
        image=image,
        command=[INTAKE_CLI, "fetch"],
        network=common.NET_EGRESS_INTAKE,
        mounts=[
            Mount(dirs.inbox, f"{CONTAINER_STATE}/inbox", readonly=False),
            Mount(dirs.acks, f"{CONTAINER_STATE}/acks", readonly=False),
            Mount(creds.get(common.CRED_CF_QUEUES), f"{CONTAINER_CREDENTIALS}/{common.CRED_CF_QUEUES}"),
            Mount(path(common.P_CF_CA_BUNDLE), CONTAINER_CA),
        ],
        env=env,
        name_prefix="legatto-intake-fetch",
    )


def _process_spec(dirs: Dirs, creds: Credentials, image: common.Image) -> ContainerSpec:
    return ContainerSpec(
        image=image,
        command=[INTAKE_CLI, "process"],
        network=common.NET_INT,
        mounts=[
            Mount(dirs.ready, f"{CONTAINER_STATE}/inbox", readonly=False),
            Mount(dirs.acks, f"{CONTAINER_STATE}/acks", readonly=False),
            Mount(dirs.quarantine, f"{CONTAINER_STATE}/quarantine", readonly=False),
            Mount(creds.get(common.CRED_FORM_X25519), f"{CONTAINER_CREDENTIALS}/{common.CRED_FORM_X25519}"),
            Mount(creds.get(common.CRED_DB_INTAKE), f"{CONTAINER_CREDENTIALS}/{common.CRED_DB_INTAKE}"),
            Mount(path(common.P_INTAKE_ETC) / "signers.d", CONTAINER_SIGNERS),
        ],
        env={
            "LEGATTO_FORM_KEY_FILE": f"{CONTAINER_CREDENTIALS}/{common.CRED_FORM_X25519}",
            "LEGATTO_SIGNERS_DIR": CONTAINER_SIGNERS,
            "LEGATTO_DB_PASSWORD_FILE": f"{CONTAINER_CREDENTIALS}/{common.CRED_DB_INTAKE}",
            "PGHOST": "db",
            "PGPORT": "5432",  # contract: legatto_ports.local.db
            "PGDATABASE": "postgres",
            "PGUSER": "legatto_intake",
        },
        name_prefix="legatto-intake-process",
    )


def _start_processor() -> None:
    systemctl = os.environ.get("LEGATTO_SYSTEMCTL", "systemctl")
    result = subprocess.run([systemctl, "start", common.UNIT_INTAKE_PROCESS], capture_output=True, text=True,
                            check=False, timeout=900)
    if result.returncode != 0:
        common.log(f"systemctl start {common.UNIT_INTAKE_PROCESS} failed (exit {result.returncode})")


def _audit_quarantine(actor: dict[str, Any], count: int, reasons: dict[str, int], gate_name: str) -> None:
    if count:
        common.audit("intake", "intake.quarantine", actor, {"count": count, "reasons": reasons, "gate": gate_name})


def _ack_actions(dirs: Dirs) -> dict[str, str]:
    """msg_id -> action of every ack waiting in acks/ (what the next fetch run sends)."""
    actions: dict[str, str] = {}
    for entry in dirs.acks.glob("*.json"):
        ack = common.read_json(entry)
        actions[entry.stem] = str(ack.get("action")) if isinstance(ack, dict) else "?"
    return actions


def _trace_acks(dirs: Dirs, state: dict[str, Any], before: dict[str, str], out: dict[str, Any] | None) -> None:
    """Self-test trace: did Cloudflare accept the ack of a traced self-test message?

    The fetch container removes an ack file when Cloudflare accepted it or
    rejected its lease, and reports only counters. When acked + retried equals
    the number of files it removed and nothing is pending, every removed ack
    was accepted; otherwise the outcome of each one is unknown ("unconfirmed")."""
    sent = {m for m in before if not (dirs.acks / f"{m}.json").exists()}
    traced = {t["msg_id"]: t for t in state["selftest_queue"].values() if t.get("ack") in (None, "retry")}
    hits = sent & traced.keys()
    if not hits:
        return
    accepted = (out is not None and not out.get("ack_pending")
                and int(out.get("acked") or 0) + int(out.get("retried") or 0) == len(sent))
    for msg_id in hits:
        if before[msg_id] == "retry":
            traced[msg_id]["ack"] = "retry"  # the processor failed; Cloudflare redelivers it
        else:
            traced[msg_id]["ack"] = "accepted" if accepted and before[msg_id] == "ack" else "unconfirmed"
        traced[msg_id]["ack_at"] = time.time()



# --- commands --------------------------------------------------------------------------------


def cmd_fetch(args: argparse.Namespace) -> int:
    common.require_root()
    actor = common.parse_actor(args.actor, TOOL)
    dirs = Dirs()
    with common.Lock("intake-fetch"):
        dirs.prepare()
        state = _load_state(dirs)
        cf = common.cloudflare_config()
        image = _image()
        acks_before = _ack_actions(dirs)
        with Credentials(TOOL) as creds:
            code, out = common.run_container(_fetch_spec(dirs, cf, creds, image), timeout=600)
        _trace_acks(dirs, state, acks_before, out)
        fetch_ok = code in (0, 10) and out is not None
        if out is not None and out.get("backlog") is not None:
            state["backlog"] = out.get("backlog")
        counts = gate(dirs, state)
        _audit_quarantine(actor, counts["quarantined"], counts["reasons"], "host")
        _save_state(dirs, state)
        _write_status(dirs, state, fetch_ok)
        pending = state["inflight"] != {}
    if pending and not args.no_process:
        _start_processor()
    common.emit({"ok": fetch_ok, "fetch_exit": code, "fetch": out, "gate": counts})
    return common.EXIT_OK if fetch_ok else common.EXIT_ERROR


def cmd_process(args: argparse.Namespace) -> int:
    common.require_root()
    actor = common.parse_actor(args.actor, TOOL)
    dirs = Dirs()
    with common.Lock("intake-process"):
        dirs.prepare()
        state = _load_state(dirs)
        if not state["inflight"]:
            _write_status(dirs, state, True)
            common.emit({"ok": True, "processed": 0})
            return common.EXIT_OK
        image = _image()
        with Credentials(TOOL) as creds:
            code, out = common.run_container(_process_spec(dirs, creds, image), timeout=900)
        result = collect_acks(dirs, state)
        for item in (out or {}).get("selftest", []) or []:
            marker = item.get("marker") if isinstance(item, dict) else None
            if isinstance(marker, str) and MARKER_RE.match(marker):
                state["selftest"][marker] = {"outcome": str(item.get("outcome", "")), "at": time.time()}
        ok = code in (0, 10) and out is not None
        if ok:
            state["last_ok_at"] = common.utc_now()
        app_quarantined = result["outcomes"].get("quarantined", 0)
        _audit_quarantine(actor, app_quarantined, result["reasons"], "process")
        _save_state(dirs, state)
        _write_status(dirs, state, ok)
    common.emit({"ok": ok, "process_exit": code, "outcomes": result["outcomes"]})
    return common.EXIT_OK if ok else common.EXIT_ERROR


def _site_origin() -> str:
    return f"https://{common.office_env()['LEGATTO_HOST_SITE']}"


def cmd_selftest(args: argparse.Namespace) -> int:
    common.require_root()
    marker = args.marker or secrets.token_hex(16)
    if not MARKER_RE.match(marker):
        fail("--marker must be 32 lowercase hex characters", common.EXIT_USAGE)
    form_pub = path(common.P_INTAKE_ETC) / "keys" / "current.json"
    if not form_pub.is_file():
        fail(f"{form_pub} is missing; run legatto-intake keygen", common.EXIT_PRECONDITION)
    image = _image()
    env = {"LEGATTO_SELFTEST_KEY_FILE": f"{CONTAINER_CREDENTIALS}/{common.CRED_SELFTEST}",
           "LEGATTO_FORM_PUB_FILE": "/etc/legatto/intake/form-key.json",
           "LEGATTO_CF_CA_FILE": CONTAINER_CA}
    env.update(common.proxy_env(common.PROXY_INTAKE))
    with Credentials(TOOL) as creds:
        spec = ContainerSpec(
            image=image,
            command=[INTAKE_CLI, "selftest", "--site", _site_origin(), "--marker", marker, "--mode", args.mode],
            network=common.NET_EGRESS_INTAKE,
            mounts=[
                Mount(creds.get(common.CRED_SELFTEST), f"{CONTAINER_CREDENTIALS}/{common.CRED_SELFTEST}"),
                Mount(form_pub, "/etc/legatto/intake/form-key.json"),
                Mount(path(common.P_CF_CA_BUNDLE), CONTAINER_CA),
            ],
            env=env,
            name_prefix="legatto-intake-selftest",
        )
        code, out = common.run_container(spec, timeout=120)
    sent = code == 0 and out is not None and out.get("status") == 202
    result: dict[str, Any] = {"ok": sent, "marker": marker, "sent": out}
    if not sent:
        common.emit(result)
        return common.EXIT_ERROR
    if not args.wait:
        common.emit(result)
        return common.EXIT_OK
    ref = out.get("ref")
    if not isinstance(ref, str) or not REF_RE.match(ref):
        result.update(ok=False, error="the Worker answered without a receipt number (ref)")
        common.emit(result)
        return common.EXIT_ERROR
    result.update(follow_selftest(marker, ref, args.wait))
    queue, removed = result["queue"], result["removed"]
    result["ok"] = bool(queue and queue["opaque"] and result["received"] and removed == "accepted")
    common.emit(result)
    if result["ok"]:
        return common.EXIT_OK
    if (queue and not queue["opaque"]) or removed == "unconfirmed":
        return EXIT_SELFTEST_FAILED
    return EXIT_SELFTEST_TIMEOUT


def queue_view(body: bytes, marker: str, site: str) -> dict[str, Any]:
    """What the queue held: the envelope as the Queues token pulled it, judged without any key.

    Opaque = the fixed envelope size of every submission, the LGF1 magic, and
    none of the plaintext the self-test frame or the Worker metadata carry."""
    tokens = {"marker": marker.encode(), "marker_bytes": bytes.fromhex(marker), "kind": b"selftest",
              "frame": b'"marker"'}
    if site:
        tokens["site"] = site.encode()
    found = sorted(name for name, token in tokens.items() if token in body)
    fixed = len(body) == envelope.ENVELOPE_SIZE
    return {"bytes": len(body), "fixed_size": fixed, "plaintext": found,
            "opaque": fixed and body[:4] == envelope.MAGIC and not found}


def follow_selftest(marker: str, ref: str, timeout_s: int) -> dict[str, Any]:
    """Kicks the fetch unit until the self-test envelope was seen in the queue
    (gate copy), stored by the processor (marker report) and acked in the queue."""
    dirs = Dirs()
    deadline = time.monotonic() + timeout_s
    systemctl = os.environ.get("LEGATTO_SYSTEMCTL", "systemctl")
    site = common.office_env().get("LEGATTO_HOST_SITE", "")
    queue: dict[str, Any] | None = None
    received = removed = msg_id = None
    progress: tuple | None = None
    while True:
        # Each fetch run sends waiting acks, pulls, gates and (via the unit)
        # processes; the processor reports self-test markers it decrypted.
        subprocess.run([systemctl, "start", UNIT_INTAKE_FETCH], capture_output=True, check=False, timeout=900)
        state = _load_state(dirs)
        trace = state["selftest_queue"].get(ref)
        if trace is not None:
            msg_id, removed = trace["msg_id"], trace.get("ack")
            if queue is None:
                copy = dirs.selftest / f"{ref}.bin"
                if copy.is_file():
                    queue = queue_view(copy.read_bytes(), marker, site)
                    copy.unlink()
                else:
                    queue = {"opaque": False, "error": "no copy of the queued envelope"}
        entry = state["selftest"].get(marker)
        received = str(entry["outcome"]) if entry else None
        if received and removed in ("accepted", "unconfirmed"):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        stage = (queue is not None, received, removed)
        if stage != progress:  # a step was reached: the next one is ready to run now
            progress = stage
            continue
        time.sleep(min(15.0, remaining))
    return {"ref": ref, "msg_id": msg_id, "queue": queue, "received": received, "removed": removed}


def cmd_keygen(args: argparse.Namespace) -> int:
    """Office X25519 form key via the app image (no network) + Ed25519 self-test key."""
    common.require_root()
    common.parse_actor(args.actor, TOOL)  # validated; key events have no audit category of their own
    keys_dir = common.ensure_dir(path(common.P_INTAKE_ETC) / "keys", 0o755)
    exists = (path(common.P_CREDSTORE) / common.CRED_FORM_X25519).is_file()
    if exists and not args.rotate:
        fail("form key exists; use --rotate to add a new current key", EXIT_KEY_EXISTS)
    image = _image()
    with common.Lock("intake-keygen"), Credentials(TOOL) as creds:
        work = common.ensure_dir(path(common.P_RUN) / "credentials" / f"keygen-{os.getpid()}", 0o700,
                                 common.CONTAINER_UID, common.CONTAINER_UID)
        try:
            mounts = [Mount(work, "/out", readonly=False)]
            command = [INTAKE_CLI, "keygen", "--out", "/out/key"]
            if exists:
                mounts.append(Mount(creds.get(common.CRED_FORM_X25519), "/prev/key"))
                command += ["--previous", "/prev/key"]
            spec = ContainerSpec(image=image, command=command, network="none", mounts=mounts, env={},
                                 name_prefix="legatto-intake-keygen")
            code, out = common.run_container(spec, timeout=120)
            if code != 0 or out is None or not re.match(r"^[0-9a-f]{16}$", str(out.get("kid"))):
                fail(f"keygen container failed (exit {code})")
            pub = base64.b64decode(str(out.get("x25519")), validate=True)
            if len(pub) != 32 or ed25519.key_id(pub).hex() != out["kid"]:
                fail("keygen returned an inconsistent public key")
            common.encrypt_credential(common.CRED_FORM_X25519, (work / "key").read_bytes())
        finally:
            for entry in work.iterdir():
                entry.unlink()
            work.rmdir()
    current = keys_dir / "current.json"
    if exists and current.is_file():
        previous = common.read_json(current, {})
        common.write_json_atomic(keys_dir / f"previous-{previous.get('kid', 'unknown')}.json", previous, 0o644)
    form_key = {"v": 1, "kid": out["kid"], "x25519": base64.b64encode(pub).decode()}
    common.write_json_atomic(current, form_key, 0o644)
    selftest_kid = ensure_selftest_key()
    common.emit({"ok": True, "kid": form_key["kid"], "x25519": form_key["x25519"], "selftest_kid": selftest_kid,
                 "rotated": exists})
    return common.EXIT_OK


def ensure_selftest_key() -> str:
    """Ed25519 self-test key: private only in credstore, public in intake_etc/selftest.pub."""
    pub_file = path(common.P_INTAKE_ETC) / "selftest.pub"
    if (path(common.P_CREDSTORE) / common.CRED_SELFTEST).is_file() and pub_file.is_file():
        pub = base64.b64decode(pub_file.read_text(encoding="ascii").strip())
        return ed25519.key_id(pub).hex()
    seed = ed25519.generate_seed()
    pub = ed25519.public_key(seed)
    common.encrypt_credential(common.CRED_SELFTEST, base64.b64encode(seed))
    common.write_atomic(pub_file, base64.b64encode(pub) + b"\n", 0o644)
    return ed25519.key_id(pub).hex()


DB_ROLES = {"legatto_intake": common.CRED_DB_INTAKE, "legatto_publisher": common.CRED_DB_PUBLISHER}
SCRAM_ITERATIONS = 4096


def scram_verifier(password: str, salt: bytes) -> str:
    """PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677): the plaintext never reaches the database."""
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, SCRAM_ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731
    return f"SCRAM-SHA-256${SCRAM_ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def cmd_db_role(args: argparse.Namespace) -> int:
    """Password of a LOGIN role created by the legatto-app migrations.

    The password is generated on the server (R10), kept only in the credstore
    and given to Postgres as a SCRAM verifier through `docker exec psql` on
    stdin (never on argv, never as plaintext in SQL, logs or pg_stat_statements).
    """
    common.require_root()
    credential = DB_ROLES[args.role]
    state_file = path(common.P_INTAKE) / "state" / "db-roles.json"
    if not (path(common.P_CREDSTORE) / credential).is_file():
        common.encrypt_credential(credential, secrets.token_hex(32).encode())
    with Credentials(TOOL) as creds:
        password = creds.read(credential).decode().strip()
    marker = hashlib.sha256(f"{args.role}:{password}".encode()).hexdigest()
    applied = common.read_json(state_file, {}) or {}
    if applied.get(args.role) == marker and not args.force:
        common.emit({"ok": True, "role": args.role, "changed": False})
        return common.EXIT_OK
    verifier = scram_verifier(password, os.urandom(16))
    sql = (
        "SET log_statement = 'none';\n"
        "SET log_min_duration_statement = -1;\n"
        f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{args.role}') THEN "
        f"RAISE EXCEPTION 'legatto_role_missing'; END IF; END $$;\n"
        f"ALTER ROLE {args.role} WITH LOGIN PASSWORD '{verifier}';\n"
    )
    docker = os.environ.get("LEGATTO_DOCKER", "docker")
    result = subprocess.run([docker, "exec", "-i", common.CONTAINER_DB, "psql", "-h", "localhost", "-U", "supabase_admin",
                             "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-X"],
                            input=sql, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode != 0:
        if "legatto_role_missing" in result.stderr:
            fail(f"role {args.role} does not exist yet (legatto-app migrations not applied)", common.EXIT_PRECONDITION)
        fail(f"ALTER ROLE {args.role} failed (psql exit {result.returncode})")
    applied[args.role] = marker
    common.ensure_dir(state_file.parent, 0o700)
    common.write_json_atomic(state_file, applied, 0o600)
    common.emit({"ok": True, "role": args.role, "changed": True})
    return common.EXIT_OK


def cmd_status(_args: argparse.Namespace) -> int:
    status = common.read_json(path(common.P_STATUS) / "intake.json")
    if status is None:
        fail("intake.json does not exist yet", common.EXIT_PRECONDITION)
    common.emit(status)
    return common.EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=TOOL, description="Office intake of the public form queue (R9).")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="ack, pull, gate; then start the processor")
    fetch.add_argument("--actor")
    fetch.add_argument("--no-process", action="store_true", help="do not start legatto-intake-process.service")
    fetch.set_defaults(func=cmd_fetch)
    process = sub.add_parser("process", help="decrypt and store ready envelopes (no external network)")
    process.add_argument("--actor")
    process.set_defaults(func=cmd_process)
    selftest = sub.add_parser("selftest", help="signed end-to-end test through the Worker")
    selftest.add_argument("--mode", choices=("ping", "verify"), default="ping")
    selftest.add_argument("--marker")
    selftest.add_argument("--wait", type=int, default=0, metavar="SECONDS")
    selftest.set_defaults(func=cmd_selftest)
    keygen = sub.add_parser("keygen", help="create (or rotate) the office form key and the self-test key")
    keygen.add_argument("--rotate", action="store_true")
    keygen.add_argument("--actor")
    keygen.set_defaults(func=cmd_keygen)
    db_role = sub.add_parser("db-role", help="set the password of a legatto-app LOGIN role from the credstore")
    db_role.add_argument("--role", required=True, choices=sorted(DB_ROLES))
    db_role.add_argument("--force", action="store_true")
    db_role.set_defaults(func=cmd_db_role)
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return common.EXIT_USAGE if exc.code else common.EXIT_OK
    return common.main_wrapper(TOOL, lambda: args.func(args))
