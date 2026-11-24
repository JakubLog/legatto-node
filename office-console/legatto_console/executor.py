"""legatto-console-exec: root executor of office-console requests (CONTRACT §4.3, §4.6).

The panel runs unprivileged and can only drop request files into
requests/incoming/. This program (root, started by legatto-console-exec.path)
moves each file to processing/, validates it, checks the TOTP code of the
console user with anti-replay, runs the matching host tool, writes
results/<id>.json, appends `console.request` to the audit log and archives the
request without its `auth` field.

Subcommands: process [--once], prune, snapshot, setup-code [--json],
emergency-credentials --json. Exit codes: 0 OK, 1 unexpected error, 2 bad
arguments, 3 lock busy, 4 precondition (not root, wrong spool layout),
50 at least one request rejected.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import grp
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import contract, crypto, store, validate
from .validate import Invalid

EXIT_OK, EXIT_ERR, EXIT_ARGS, EXIT_LOCK, EXIT_PRECOND, EXIT_REJECTED = 0, 1, 2, 3, 4, 50

TOTP_FAIL_LIMIT = 5  # failed TOTP codes per user ...
TOTP_FAIL_WINDOW = 900  # ... within 15 minutes lock the user's requests until the window passes
SETUP_FAIL_LIMIT = 5  # wrong setup codes before the code is destroyed
TMP_GRACE_SECONDS = 5  # a `.json.tmp` older than this is abandoned (the panel renames within milliseconds)
LOCK_WAIT_SECONDS = 10
TOOL_TIMEOUT = 180
LONG_TOOL_TIMEOUT = 1800  # update rollback and recovery pack
TOOL_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8"}
ARCHIVE_REDACT = ("scrypt",)  # params never kept in the archive


class Rejected(Exception):
    """Ends processing of one request with status `rejected` (or `error`)."""

    def __init__(self, code: str, message: str, status: str = "rejected", data: dict | None = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.data = data or {}


class Fatal(Exception):
    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.code = code


@dataclass
class Outcome:
    status: str
    code: str
    message: str
    data: dict = field(default_factory=dict)
    sensitive: bool = False
    audit_event: str | None = None  # extra audit event besides console.request
    audit_params: dict = field(default_factory=dict)


@dataclass
class Context:
    rid: str
    rtype: str
    params: dict
    user: str
    ip: str
    node: str | None
    tags: list
    auth: dict

    @property
    def actor(self) -> dict:
        actor = {"kind": "office-admin", "id": self.user, "ip": self.ip}
        if self.node:
            actor["node"] = self.node
        return actor

    @property
    def actor_json(self) -> str:
        return json.dumps(self.actor, sort_keys=True, ensure_ascii=False)


def log(message: str) -> None:
    """Human-readable diagnostics for journald. Never pass secrets here."""
    print(f"legatto-console-exec: {message}", file=sys.stderr, flush=True)


# --- Spool layout (CONTRACT §4.3) ------------------------------------------------------
@dataclass(frozen=True)
class DirSpec:
    path: str
    mode: int
    group: str | None  # None = root


SPOOL_LAYOUT = (
    DirSpec(contract.REQUESTS, 0o750, contract.CONSOLE_GROUP),
    DirSpec(contract.REQUESTS_INCOMING, 0o730, contract.CONSOLE_GROUP),
    DirSpec(contract.REQUESTS_PROCESSING, 0o700, None),
    DirSpec(contract.REQUESTS_RESULTS, 0o750, contract.CONSOLE_GROUP),
    DirSpec(contract.REQUESTS_ARCHIVE, 0o700, None),
    DirSpec(contract.CONSOLE_STATE, 0o750, contract.CONSOLE_GROUP),
    DirSpec(contract.CONSOLE_AUTH, 0o700, None),
    DirSpec(contract.CONSOLE_TOTP_SEEDS, 0o700, None),
)


def layout_problems() -> list[str]:
    problems = []
    for spec in SPOOL_LAYOUT:
        location = contract.path(spec.path)
        try:
            st = os.lstat(location)
        except FileNotFoundError:
            problems.append(f"{spec.path}: missing")
            continue
        if not stat.S_ISDIR(st.st_mode):
            problems.append(f"{spec.path}: not a directory")
            continue
        expected_gid = 0 if spec.group is None else _gid(spec.group)
        if st.st_uid != 0 or st.st_gid != expected_gid or stat.S_IMODE(st.st_mode) != spec.mode:
            problems.append(f"{spec.path}: expected {spec.mode:04o} root:{spec.group or 'root'}, found "
                            f"{stat.S_IMODE(st.st_mode):04o} {st.st_uid}:{st.st_gid}")
    return problems


def _gid(group: str) -> int:
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise Fatal(f"group {group} does not exist", EXIT_PRECOND) from exc


def _uid(user: str) -> int:
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError as exc:
        raise Fatal(f"user {user} does not exist", EXIT_PRECOND) from exc


class FileLock:
    def __init__(self, location: str):
        self.location = location
        self.fd = -1

    def __enter__(self) -> "FileLock":
        os.makedirs(os.path.dirname(self.location), exist_ok=True)
        self.fd = os.open(self.location, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise Fatal("another legatto-console-exec holds the lock", EXIT_LOCK) from None
                time.sleep(0.2)

    def __exit__(self, *exc: object) -> None:
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


# --- Executor ----------------------------------------------------------------------------
class Executor:
    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock
        self.console_uid = _uid(contract.CONSOLE_USER)
        self.console_gid = _gid(contract.CONSOLE_GROUP)
        self.env = store.office_env()
        self.issuer = "Legatto " + (self.env.get("LEGATTO_SLUG") or "biuro")
        self.handlers: dict[str, Callable[[Context], Outcome]] = {
            "breakglass.enable": self.h_breakglass_enable,
            "breakglass.disable": self.h_breakglass_disable,
            "update.approve": self.h_update_approve,
            "update.reject": self.h_update_reject,
            "update.rollback": self.h_update_rollback,
            "update.autosecurity": self.h_update_autosecurity,
            "device.enroll": self.h_device_enroll,
            "device.revoke": self.h_device_revoke,
            "staff.set": self.h_staff_set,
            "features.set": self.h_features_set,
            "recovery.generate": self.h_recovery_generate,
            "console.user.add": self.h_user_add,
            "console.user.remove": self.h_user_remove,
            "console.user.reset_totp": self.h_user_reset_totp,
            "console.user.password": self.h_user_password,
            "console.login": self.h_login,
            "contacts.set": self.h_contacts_set,
            "console.setup": self.h_setup,
        }
        missing = set(contract.REQUEST_TYPES) ^ set(self.handlers)
        if missing:
            raise Fatal(f"handler table differs from the contract: {sorted(missing)}", EXIT_ERR)

    # --- helpers -----------------------------------------------------------------------
    def p(self, location: str) -> str:
        return contract.path(location)

    def now_utc(self) -> str:
        return validate.format_utc(self.clock())

    def local_time(self, utc_value: str | None) -> str:
        return validate.local_display(utc_value, self.env.get("LEGATTO_TZ") or contract.TIMEZONE)

    def write_console_file(self, location: str, obj: Any) -> None:
        store.atomic_write(location, store.dump_json(obj), mode=0o640, uid=0, gid=self.console_gid)

    def write_root_file(self, location: str, data: bytes, mode: int = 0o600) -> None:
        store.atomic_write(location, data, mode=mode, uid=0, gid=0)

    def run_tool(self, name: str, args: list[str], timeout: int = TOOL_TIMEOUT) -> tuple[int, Any, str]:
        """Run a host tool; returns (exit code, parsed JSON stdout or None, stderr tail)."""
        executable = name if name.startswith("/") else contract.tool(name)
        if not os.access(executable, os.X_OK):
            raise Rejected("tool_missing", f"Narzędzie {os.path.basename(executable)} nie jest zainstalowane na serwerze.",
                           status="error")
        try:
            proc = subprocess.run([executable, *args], capture_output=True, timeout=timeout, env=TOOL_ENV,
                                  stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            log(f"{os.path.basename(executable)} {args[:1]} timed out after {timeout}s")
            raise Rejected("timeout", "Operacja trwała zbyt długo i została przerwana. Sprawdź status za chwilę.",
                           status="error") from None
        stderr = proc.stderr.decode("utf-8", "replace")[-2000:]
        if stderr.strip():
            log(f"{os.path.basename(executable)} {args[:1]} rc={proc.returncode}: {stderr.strip()[-500:]}")
        parsed = None
        text = proc.stdout.decode("utf-8", "replace").strip()
        if text:
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
        return proc.returncode, parsed, stderr

    @staticmethod
    def tool_message(out: Any, default: str) -> str:
        if isinstance(out, dict) and isinstance(out.get("message"), str) and out["message"].strip():
            return out["message"].strip()[:500]
        return default

    def generic_failure(self, rc: int, out: Any, what: str) -> Outcome:
        if rc == 2:
            return Outcome("rejected", "bad_args", self.tool_message(out, f"{what}: narzędzie odrzuciło parametry."))
        if rc == 3:
            return Outcome("error", "busy", f"{what}: trwa inna operacja na serwerze. Spróbuj ponownie za minutę.")
        if rc == 4:
            return Outcome("error", "precondition",
                           self.tool_message(out, f"{what}: niespełniony warunek wstępny na serwerze. Zgłoś to dostawcy."))
        return Outcome("error", "tool_failed", self.tool_message(out, f"{what}: operacja nie powiodła się (kod {rc}). "
                                                                       "Zgłoś to dostawcy."))

    def audit(self, event: str, actor: dict, params: dict, node: str | None = None) -> int | None:
        args = ["append", "--cat", contract.AUDIT_CATEGORY, "--event", event,
                "--actor", json.dumps(actor, sort_keys=True, ensure_ascii=False),
                "--params", json.dumps(params, sort_keys=True, ensure_ascii=False)]
        if node:
            args += ["--node", node]
        for attempt in range(3):
            try:
                rc, out, _ = self.run_tool(contract.CLI_AUDIT, args, timeout=30)
            except Rejected as exc:
                log(f"audit {event} failed: {exc.code}")
                return None
            if rc == 0 and isinstance(out, dict) and isinstance(out.get("seq"), int):
                return out["seq"]
            if rc != 3:
                log(f"audit {event} failed with exit code {rc}")
                return None
            time.sleep(1 + attempt)
        log(f"audit {event} failed: lock busy")
        return None

    def whois(self, ip: str) -> tuple[str | None, list]:
        tailscale = self.p(contract.TAILSCALE)
        try:
            proc = subprocess.run([tailscale, "whois", "--json", ip], capture_output=True, timeout=10, env=TOOL_ENV,
                                  stdin=subprocess.DEVNULL, check=False)
            doc = json.loads(proc.stdout.decode("utf-8")) if proc.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError):
            doc = None
        node = doc.get("Node") if isinstance(doc, dict) else None
        if not isinstance(node, dict):
            return None, []
        name = node.get("ComputedName") or (node.get("Name") or "").rstrip(".")
        name = name if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,255}", name or "") else None
        tags = [t for t in node.get("Tags") or [] if isinstance(t, str)]
        return name, tags

    # --- users and TOTP ----------------------------------------------------------------
    def users_doc(self) -> dict:
        doc = store.read_json(self.p(contract.CONSOLE_USERS))
        if not isinstance(doc, dict) or not isinstance(doc.get("users"), dict):
            doc = {"v": 1, "users": {}}
        return doc

    def save_users(self, doc: dict) -> None:
        doc["v"] = 1
        doc["updated_at"] = self.now_utc()
        self.write_console_file(self.p(contract.CONSOLE_USERS), doc)

    def seed_path(self, login: str) -> str:
        return os.path.join(self.p(contract.CONSOLE_TOTP_SEEDS), login)

    def auth_path(self, login: str, suffix: str) -> str:
        return os.path.join(self.p(contract.CONSOLE_AUTH), f"{login}.{suffix}")

    def new_seed(self, login: str) -> str:
        secret = crypto.new_totp_secret()
        self.write_root_file(self.seed_path(login), (secret + "\n").encode("ascii"), mode=0o400)
        return secret

    def read_seed(self, login: str) -> bytes | None:
        try:
            with open(self.seed_path(login), encoding="ascii") as handle:
                return crypto.decode_totp_secret(handle.read())
        except (OSError, ValueError):
            return None

    def remove_user_files(self, login: str) -> None:
        for location in (self.seed_path(login), self.auth_path(login, "step"), self.auth_path(login, "fail")):
            try:
                os.unlink(location)
            except FileNotFoundError:
                pass

    def check_totp(self, login: str, code: str) -> None:
        """Verify `code` for `login` with anti-replay; raises Rejected."""
        now = self.clock()
        fail_path = self.auth_path(login, "fail")
        failures = store.read_json(fail_path)
        failures = [t for t in failures if isinstance(t, (int, float)) and now - t < TOTP_FAIL_WINDOW] \
            if isinstance(failures, list) else []
        if len(failures) >= TOTP_FAIL_LIMIT:
            raise Rejected("totp_locked", "Zbyt wiele błędnych kodów TOTP. Odczekaj 15 minut.")
        seed = self.read_seed(login)
        if seed is None:
            raise Rejected("no_totp_seed", "Konto nie ma skonfigurowanego TOTP. Poproś innego administratora o reset.")
        step = crypto.totp_match(seed, code, now)
        if step is None:
            failures.append(now)
            self.write_root_file(fail_path, json.dumps(failures).encode())
            raise Rejected("bad_totp", "Kod TOTP jest nieprawidłowy.")
        step_path = self.auth_path(login, "step")
        last = -1
        try:
            with open(step_path, encoding="ascii") as handle:
                last = int(handle.read().strip() or "-1")
        except (OSError, ValueError):
            last = -1
        if step <= last:
            raise Rejected("totp_replay", "Ten kod TOTP został już użyty. Poczekaj na następny kod (do 30 s).")
        self.write_root_file(step_path, f"{step}\n".encode("ascii"))
        if failures:
            try:
                os.unlink(fail_path)
            except FileNotFoundError:
                pass

    # --- processing --------------------------------------------------------------------------
    def process(self, once: bool = False) -> int:
        problems = layout_problems()
        if problems:
            raise Fatal("spool layout does not match the contract: " + "; ".join(problems), EXIT_PRECOND)
        rejected_any = False
        with FileLock(self.p(contract.EXEC_LOCK)):
            self.recover_interrupted()
            while True:
                names = self.ready_names()
                for name in names:
                    status = self.handle_file(name)
                    rejected_any = rejected_any or status != "ok"
                if once or not names:
                    break
        return EXIT_REJECTED if rejected_any else EXIT_OK

    def ready_names(self) -> list[str]:
        """Names in incoming/ to process now; waits briefly for in-flight `.json.tmp` files."""
        incoming = self.p(contract.REQUESTS_INCOMING)
        deadline = time.monotonic() + TMP_GRACE_SECONDS
        while True:
            names = sorted(os.listdir(incoming))
            pending_tmp = False
            ready = []
            for name in names:
                if name.endswith(".json.tmp"):
                    location = os.path.join(incoming, name)
                    try:
                        age = time.time() - os.lstat(location).st_mtime
                    except FileNotFoundError:
                        continue
                    if age > TMP_GRACE_SECONDS:
                        log(f"removing abandoned temporary file {name[:40]!r}")
                        self.unlink_quiet(location)
                    else:
                        pending_tmp = True
                else:
                    ready.append(name)
            if ready or not pending_tmp or time.monotonic() > deadline:
                return ready
            time.sleep(0.2)

    @staticmethod
    def unlink_quiet(location: str) -> None:
        try:
            os.unlink(location)
        except FileNotFoundError:
            pass
        except IsADirectoryError:
            shutil.rmtree(location, ignore_errors=True)

    def recover_interrupted(self) -> None:
        processing = self.p(contract.REQUESTS_PROCESSING)
        for name in sorted(os.listdir(processing)):
            stem = name[:-5] if name.endswith(".json") else ""
            log(f"request {stem or name[:40]!r} was interrupted by a previous run")
            if crypto.is_ulid(stem) and not self.seen(stem):
                self.write_result(stem, None, Outcome("error", "interrupted",
                                                      "Przetwarzanie przerwane (restart serwera). Złóż żądanie ponownie."), None)
            self.archive(stem if crypto.is_ulid(stem) else None, None, "error", "interrupted")
            self.unlink_quiet(os.path.join(processing, name))

    def seen(self, rid: str) -> bool:
        return (os.path.lexists(os.path.join(self.p(contract.REQUESTS_ARCHIVE), rid + ".json"))
                or os.path.lexists(os.path.join(self.p(contract.REQUESTS_RESULTS), rid + ".json")))

    def handle_file(self, name: str) -> str:
        incoming = self.p(contract.REQUESTS_INCOMING)
        processing = self.p(contract.REQUESTS_PROCESSING)
        stem = name[:-5] if name.endswith(".json") else ""
        file_id = stem if crypto.is_ulid(stem) else None
        work_name = (file_id or "invalid-" + crypto.new_ulid(self.clock())) + ".json"
        work = os.path.join(processing, work_name)
        try:
            os.rename(os.path.join(incoming, name), work)
        except FileNotFoundError:
            return "ok"
        except OSError as exc:
            if exc.errno in (errno.ENOTEMPTY, errno.EISDIR, errno.EEXIST):
                work = os.path.join(processing, "invalid-" + crypto.new_ulid(self.clock()))
                os.rename(os.path.join(incoming, name), work)
            else:
                raise
        request: dict | None = None
        ctx: Context | None = None
        duplicate = False
        try:
            if file_id is None:
                raise Rejected("bad_id", "Nazwa pliku żądania nie jest identyfikatorem ULID.")
            if self.seen(file_id):
                duplicate = True
                raise Rejected("duplicate_id", "Żądanie o tym identyfikatorze zostało już przetworzone.")
            raw = self.read_request_file(work)
            obj = validate.strict_json(raw)
            request = validate.envelope(obj)
            ctx = self.authenticate(request, file_id)
            if ctx.rtype != "console.setup":  # console.setup is authenticated by its one-time code
                self.authorize(ctx)
            outcome = self.handlers[ctx.rtype](ctx)
        except Rejected as exc:
            outcome = Outcome(exc.status, exc.code, str(exc), data=exc.data)
            if ctx is not None and ctx.rtype == "console.login" and exc.code != "unknown_user":
                outcome.audit_event = "console.login_failed"
        except Invalid as exc:
            outcome = Outcome("rejected", exc.code, str(exc))
        except Exception as exc:  # noqa: BLE001 - one bad request must not stop the queue
            log(f"unexpected error in request {file_id}: {type(exc).__name__}: {exc}")
            outcome = Outcome("error", "internal", "Błąd wewnętrzny wykonawcy. Zgłoś to dostawcy.")
        rtype = request.get("type") if isinstance(request, dict) and request.get("type") in self.handlers else None
        actor, node = self.audit_actor(request, ctx)
        audit_params = {"id": file_id or "-", "type": rtype or "-", "status": outcome.status, "code": outcome.code}
        audit_params.update(self.safe_params(rtype, ctx.params if ctx else None))
        audit_seq = self.audit("console.request", actor, audit_params, node)
        if outcome.audit_event:
            extra = {"id": file_id or "-"}
            extra.update(outcome.audit_params)
            seq = self.audit(outcome.audit_event, actor, extra, node)
            audit_seq = seq if seq is not None else audit_seq
        if file_id and not duplicate:
            self.write_result(file_id, rtype, outcome, audit_seq)
        if not duplicate:
            self.archive(file_id, request, outcome.status, outcome.code, ctx)
        self.unlink_quiet(work)
        log(f"request {file_id or name[:40]!r} type={rtype or '-'} -> {outcome.status}/{outcome.code}")
        return outcome.status

    def read_request_file(self, location: str) -> bytes:
        try:
            fd = os.open(location, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError as exc:
            raise Rejected("bad_file", "Plik żądania nie jest zwykłym plikiem.") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise Rejected("bad_file", "Plik żądania nie jest zwykłym plikiem.")
            if st.st_uid != self.console_uid:
                raise Rejected("bad_owner", "Plik żądania nie należy do konsoli.")
            if st.st_size > contract.REQUEST_MAX_BYTES:
                raise Rejected("too_large", f"Żądanie większe niż {contract.REQUEST_MAX_BYTES} B.")
            raw = os.read(fd, contract.REQUEST_MAX_BYTES + 1)
            if len(raw) > contract.REQUEST_MAX_BYTES:
                raise Rejected("too_large", f"Żądanie większe niż {contract.REQUEST_MAX_BYTES} B.")
            return raw
        finally:
            os.close(fd)

    def authenticate(self, request: dict, file_id: str) -> Context:
        """Checks in contract order: id, ts, type, params, actor, auth format; account and TOTP in authorize()."""
        rid = request["id"]
        if not crypto.is_ulid(rid) or rid != file_id:
            raise Rejected("bad_id", "Identyfikator żądania nie zgadza się z nazwą pliku.")
        ts = request["ts"]
        try:
            moment = validate.parse_utc(validate.utc(ts, "ts"))
        except Invalid as exc:
            raise Rejected("bad_ts", str(exc)) from exc
        if abs(self.clock() - moment) > contract.REQUEST_MAX_AGE_SECONDS:
            raise Rejected("stale", "Żądanie jest przeterminowane (zegar lub opóźnienie > 120 s). Spróbuj ponownie.")
        rtype = request["type"]
        if rtype not in self.handlers:
            raise Rejected("bad_type", "Nieznany typ żądania.")
        params = validate.params_for(rtype, request["params"])
        actor = validate.actor(request["actor"])
        auth = validate.auth(request["auth"], rtype)
        node, tags = self.whois(actor["ip"])
        return Context(rid, rtype, params, actor["user"], actor["ip"], node, tags, auth)

    def authorize(self, ctx: Context) -> None:
        """The account exists and is enabled, and the TOTP code is fresh (anti-replay)."""
        user = self.users_doc()["users"].get(ctx.user)
        if not isinstance(user, dict) or not user.get("enabled"):
            raise Rejected("unknown_user", "Konto nie istnieje albo jest wyłączone.")
        self.check_totp(ctx.user, ctx.auth["totp"])

    def audit_actor(self, request: Any, ctx: Context | None) -> tuple[dict, str | None]:
        """Audit as the console user only when that account exists; otherwise as the executor."""
        if ctx is not None and (ctx.rtype == "console.setup" or ctx.user in self.users_doc()["users"]):
            return ctx.actor, ctx.node
        actor = {"kind": "system", "id": contract.CLI_CONSOLE_EXEC}
        if ctx is not None:
            actor["ip"] = ctx.ip
        return actor, ctx.node if ctx is not None else None

    @staticmethod
    def safe_params(rtype: str | None, params: dict | None) -> dict:
        """Technical parameters only (CONTRACT §4.2): no keys, codes, hashes or personal contact data."""
        if not rtype or not params:
            return {}
        if rtype == "staff.set":
            return {"staff_count": len(params["staff"])}
        if rtype == "contacts.set":
            return {"sections": sorted(k for k in ("primary", "secondary", "iod") if params.get(k))}
        if rtype == "features.set":
            out = {"feature": params["feature"], "enabled": params["enabled"]}
            if "ics_hosts" in params:
                out["ics_hosts_count"] = len(params["ics_hosts"])
            return out
        allowed = ("hours", "release", "manifest_sha256", "not_before", "install_now", "to", "enabled", "kind",
                   "node_id", "login")
        out = {k: params[k] for k in allowed if k in params}
        if rtype.startswith("breakglass.") and params.get("reason"):
            out["reason"] = params["reason"]  # allowed by CONTRACT §4.2
        return out

    def write_result(self, rid: str, rtype: str | None, outcome: Outcome, audit_seq: int | None) -> None:
        result = {"v": 1, "id": rid, "type": rtype, "status": outcome.status, "code": outcome.code,
                  "message": outcome.message, "ts": self.now_utc(), "audit_seq": audit_seq,
                  "data": outcome.data, "sensitive": outcome.sensitive}
        self.write_console_file(os.path.join(self.p(contract.REQUESTS_RESULTS), rid + ".json"), result)

    def archive(self, rid: str | None, request: dict | None, status: str, code: str, ctx: Context | None = None) -> None:
        record: dict[str, Any]
        if isinstance(request, dict):
            record = {k: v for k, v in request.items() if k != "auth"}
            if isinstance(record.get("params"), dict):
                record["params"] = {k: ("<redacted>" if k in ARCHIVE_REDACT else v) for k, v in record["params"].items()}
        else:
            record = {"id": rid, "unparsed": True}
        record["executor"] = {"status": status, "code": code, "processed_at": self.now_utc(),
                              "node": ctx.node if ctx else None}
        name = (rid or "invalid-" + crypto.new_ulid(self.clock())) + ".json"
        self.write_root_file(os.path.join(self.p(contract.REQUESTS_ARCHIVE), name), store.dump_json(record))

    # --- handlers: break-glass ------------------------------------------------------------------
    def h_breakglass_enable(self, ctx: Context) -> Outcome:
        rc, out, _ = self.run_tool(contract.CLI_BREAKGLASS, [
            "enable", "--hours", str(ctx.params["hours"]), "--reason", ctx.params["reason"],
            "--actor", ctx.actor_json, "--json"])
        out = out if isinstance(out, dict) else {}
        if rc == 0:
            return Outcome("ok", "enabled", f"Dostęp serwisowy otwarty do {self.local_time(out.get('expires_at'))}.",
                           data={k: out.get(k) for k in ("window_id", "started_at", "expires_at", "policy_asserted")})
        if rc == 20:
            return Outcome("rejected", "already_active", "Dostęp serwisowy jest już otwarty.")
        if rc == 21:
            return Outcome("error", "policy_assert_failed",
                           "Okno otwarte, ale kontrola polityki tailnetu nie powiodła się — dostawca pozostaje odcięty "
                           "przez firewall. Zgłoś to dostawcy.")
        return self.generic_failure(rc, out, "Otwarcie dostępu serwisowego")

    def h_breakglass_disable(self, ctx: Context) -> Outcome:
        args = ["disable", "--actor", ctx.actor_json, "--json"]
        if ctx.params["reason"]:
            args[1:1] = ["--reason", ctx.params["reason"]]
        rc, out, _ = self.run_tool(contract.CLI_BREAKGLASS, args)
        out = out if isinstance(out, dict) else {}
        if rc == 0:
            return Outcome("ok", "disabled", "Dostęp serwisowy zamknięty. Podsumowanie okna jest na stronie "
                                             "„Dostęp serwisowy”.",
                           data={k: out.get(k) for k in ("window_id", "closed_at", "close_reason")})
        if rc == 20:
            return Outcome("rejected", "not_active", "Dostęp serwisowy nie jest otwarty.")
        return self.generic_failure(rc, out, "Zamknięcie dostępu serwisowego")

    # --- handlers: updates -------------------------------------------------------------------------
    def _update(self, ctx: Context, args: list[str], what: str, ok_code: str, ok_message: str,
                timeout: int = TOOL_TIMEOUT) -> Outcome:
        rc, out, _ = self.run_tool(contract.CLI_UPDATE, [*args, "--actor", ctx.actor_json, "--json"], timeout=timeout)
        data = out.get("data") if isinstance(out, dict) and isinstance(out.get("data"), dict) else {}
        code = out.get("code") if isinstance(out, dict) and isinstance(out.get("code"), str) else None
        if rc == 0:
            return Outcome("ok", code or ok_code, self.tool_message(out, ok_message), data=data)
        if rc == 10:
            return Outcome("rejected", code or "not_pending",
                           self.tool_message(out, "To wydanie nie czeka na decyzję albo jego skrót się zmienił. "
                                                  "Odśwież stronę wydań."))
        if rc == 13:
            return Outcome("error", code or "rollback_reverted",
                           self.tool_message(out, "Wycofanie nie przeszło kontroli zdrowia; przywrócono poprzednią "
                                                  "wersję."))
        if rc == 14:
            return Outcome("error", code or "rollback_failed",
                           self.tool_message(out, "Wycofanie nie powiodło się — stan krytyczny. Natychmiast zgłoś to "
                                                  "dostawcy."))
        if rc == 4 and args[0] == "autosecurity":
            return Outcome("rejected", code or "policy_forbids",
                           self.tool_message(out, "Polityka serwera nie pozwala na tę zmianę."))
        return self.generic_failure(rc, out, what)

    def h_update_approve(self, ctx: Context) -> Outcome:
        args = ["approve", "--release", ctx.params["release"], "--manifest-sha256", ctx.params["manifest_sha256"]]
        if "not_before" in ctx.params:
            args += ["--not-before", ctx.params["not_before"]]
        if ctx.params.get("install_now"):
            # Skips only the night install window; channel delays, promotion and egress gates still apply.
            # legatto-update starts its own run in the background; the result does not wait for the install.
            args.append("--install-now")
            message = (f"Wydanie {ctx.params['release']} zatwierdzone do instalacji teraz — bez czekania na okno "
                       "nocne, ale nie wcześniej niż po obowiązkowym opóźnieniu kanału.")
        else:
            message = f"Wydanie {ctx.params['release']} zatwierdzone; instalacja w najbliższym oknie."
        return self._update(ctx, args, "Zatwierdzenie wydania", "approved", message)

    def h_update_reject(self, ctx: Context) -> Outcome:
        args = ["reject", "--release", ctx.params["release"], "--manifest-sha256", ctx.params["manifest_sha256"]]
        if ctx.params["reason"]:
            args += ["--reason", ctx.params["reason"]]
        return self._update(ctx, args, "Odrzucenie wydania", "declined", f"Wydanie {ctx.params['release']} odrzucone.")

    def h_update_rollback(self, ctx: Context) -> Outcome:
        args = ["rollback"] + (["--to", ctx.params["to"]] if "to" in ctx.params else [])
        return self._update(ctx, args, "Wycofanie wydania", "rolled_back", "Przywrócono poprzednią wersję.",
                            timeout=LONG_TOOL_TIMEOUT)

    def h_update_autosecurity(self, ctx: Context) -> Outcome:
        enabled = ctx.params["enabled"]
        return self._update(ctx, ["autosecurity", "--enabled", "true" if enabled else "false"],
                            "Zmiana automatycznych poprawek bezpieczeństwa", "autosecurity_set",
                            "Automatyczne poprawki bezpieczeństwa " + ("włączone." if enabled else "wyłączone."))

    # --- handlers: tailnet devices -------------------------------------------------------------------
    def h_device_enroll(self, ctx: Context) -> Outcome:
        args = ["enroll", "--kind", ctx.params["kind"]]
        if ctx.params["kind"] == "staff":
            args += ["--login", ctx.params["login"]]
        rc, out, _ = self.run_tool(contract.CLI_TAILNET, [*args, "--actor", ctx.actor_json, "--json"])
        if rc == 0 and isinstance(out, dict) and isinstance(out.get("key"), str):
            data = {k: out.get(k) for k in ("kind", "user", "tags", "key", "expires_at", "login_server")}
            return Outcome("ok", "enrolled", "Klucz rejestracji urządzenia gotowy (jednorazowy, ważny 30 minut).",
                           data=data, sensitive=True)
        if rc == 24:
            return Outcome("rejected", "unknown_login", "Tego loginu nie ma na liście personelu. Dodaj go najpierw.")
        if rc == 0:
            return Outcome("error", "tool_output", "Narzędzie nie zwróciło klucza rejestracji. Zgłoś to dostawcy.")
        return self.generic_failure(rc, out, "Rejestracja urządzenia")

    def h_device_revoke(self, ctx: Context) -> Outcome:
        nodes = (store.read_json(self.p(contract.CONSOLE_SNAPSHOT)) or {}).get("nodes", {}).get("items") or []
        for node in nodes:
            if isinstance(node, dict) and str(node.get("id")) == ctx.params["node_id"] \
                    and contract.TAG_SERVER in (node.get("tags") or []):
                return Outcome("rejected", "server_node", "Nie można usunąć węzła serwera.")
        rc, out, _ = self.run_tool(contract.CLI_TAILNET, ["revoke", "--node-id", ctx.params["node_id"],
                                                          "--actor", ctx.actor_json, "--json"])
        if rc == 0:
            self.refresh_snapshot()
            name = out.get("name") if isinstance(out, dict) else None
            return Outcome("ok", "revoked", f"Urządzenie {name or ctx.params['node_id']} usunięte z tailnetu.",
                           data={"node_id": ctx.params["node_id"], "name": name})
        if rc == 24:
            return Outcome("rejected", "unknown_node", "Nie ma takiego urządzenia.")
        if rc == 2:
            return Outcome("rejected", "server_node", "Tego węzła nie można usunąć.")
        return self.generic_failure(rc, out, "Usunięcie urządzenia")

    def h_staff_set(self, ctx: Context) -> Outcome:
        with tempfile.TemporaryDirectory(prefix="legatto-staff-") as tmp:
            source = os.path.join(tmp, "staff.json")
            with open(source, "w", encoding="utf-8") as handle:
                json.dump({"v": 1, "staff": ctx.params["staff"]}, handle)
            rc, out, _ = self.run_tool(contract.CLI_TAILNET, ["staff-set", "--file", source,
                                                              "--actor", ctx.actor_json, "--json"])
        if rc == 0:
            self.refresh_snapshot()
            return Outcome("ok", "staff_set", f"Lista personelu zapisana ({len(ctx.params['staff'])} osób). "
                                              "Urządzenia osób usuniętych z listy zostały odłączone.")
        return self.generic_failure(rc, out, "Zapis listy personelu")

    # --- handlers: features and egress ----------------------------------------------------------------
    def h_features_set(self, ctx: Context) -> Outcome:
        location = self.p(contract.FEATURES)
        try:
            with open(location, "rb") as handle:
                previous = handle.read()
            doc = json.loads(previous)
        except (OSError, ValueError):
            return Outcome("error", "precondition", "Brak pliku funkcji biura na serwerze. Zgłoś to dostawcy.")
        if not isinstance(doc, dict) or not isinstance(doc.get("features"), dict):
            return Outcome("error", "precondition", "Plik funkcji biura jest uszkodzony. Zgłoś to dostawcy.")
        feature, enabled = ctx.params["feature"], ctx.params["enabled"]
        updated = {"v": 1, "updated_at": self.now_utc(),
                   "features": {name: bool(doc["features"].get(name, False)) for name in contract.FEATURE_NAMES},
                   "ics_hosts": [h for h in doc.get("ics_hosts") or [] if isinstance(h, str)]}
        updated["features"][feature] = enabled
        if "ics_hosts" in ctx.params:
            updated["ics_hosts"] = ctx.params["ics_hosts"]
        self.write_console_file(location, updated)
        rc, out, _ = self.run_tool(contract.CLI_EGRESS, ["apply", "--actor", ctx.actor_json, "--json"],
                                   timeout=LONG_TOOL_TIMEOUT)
        if rc == 0:
            state = "włączona" if enabled else "wyłączona"
            return Outcome("ok", "feature_set", f"Funkcja „{feature}” {state}; reguły ruchu wychodzącego zastosowane.",
                           data={"feature": feature, "enabled": enabled})
        store.atomic_write(location, previous, mode=0o640, uid=0, gid=self.console_gid)
        if rc == 42:
            return Outcome("rejected", "egress_invalid",
                           self.tool_message(out, "Reguły ruchu wychodzącego odrzucone (np. niepoprawny host). "
                                                  "Zmiana wycofana."))
        failure = self.generic_failure(rc, out, "Zmiana funkcji (zmiana wycofana)")
        return failure

    # --- handlers: recovery pack -----------------------------------------------------------------------
    def h_recovery_generate(self, ctx: Context) -> Outcome:
        rc, out, _ = self.run_tool(contract.CLI_RECOVERY_PACK, ["generate", "--json", "--actor", ctx.actor_json],
                                   timeout=LONG_TOOL_TIMEOUT)
        if rc != 0:
            return self.generic_failure(rc, out, "Generowanie pakietu odzyskiwania")
        if not isinstance(out, dict) or not isinstance(out.get("password"), str):
            return Outcome("error", "tool_output", "Narzędzie pakietu nie zwróciło hasła. Zgłoś to dostawcy.")
        recovery_dir = self.p(contract.RECOVERY_DIR)
        files = {}
        for key in ("file", "card"):
            value = out.get(key)
            if value is None:
                continue
            name = os.path.basename(value) if isinstance(value, str) else ""
            full = os.path.join(recovery_dir, name)
            if (not name or os.path.dirname(value) not in (contract.RECOVERY_DIR, recovery_dir)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name)
                    or os.path.islink(full) or not os.path.isfile(full)):
                return Outcome("error", "tool_output", "Pakiet zapisano poza katalogiem pakietów. Zgłoś to dostawcy.")
            files[key] = name
        if "file" not in files:
            return Outcome("error", "tool_output", "Narzędzie pakietu nie zwróciło pliku. Zgłoś to dostawcy.")
        data = {"password": out["password"], "sha256": out.get("sha256"), "bytes": out.get("bytes"),
                "items": out.get("items") or [], **files}
        return Outcome("ok", "generated", "Pakiet odzyskiwania gotowy. Pobierz pliki i zapisz hasło — znikną po 10 "
                                          "minutach.", data=data, sensitive=True)

    # --- handlers: console accounts --------------------------------------------------------------------
    def _new_account(self, login: str, display_name: str, password_hash: str, must_change: bool,
                     kind: str = "admin") -> str:
        doc = self.users_doc()
        secret = self.new_seed(login)
        self.unlink_quiet(self.auth_path(login, "fail"))
        now = self.now_utc()
        doc["users"][login] = {"display_name": display_name, "kind": kind, "enabled": True, "created_at": now,
                               "password": password_hash, "password_set_at": now, "must_change": must_change}
        self.save_users(doc)
        return secret

    def h_user_add(self, ctx: Context) -> Outcome:
        login = ctx.params["login"]
        if login in self.users_doc()["users"]:
            return Outcome("rejected", "exists", f"Konto {login} już istnieje.")
        initial = crypto.new_password()
        secret = self._new_account(login, ctx.params["display_name"], crypto.scrypt_hash(initial), True)
        return Outcome("ok", "added", f"Konto {login} utworzone. Przekaż hasło i kod QR tej osobie osobiście.",
                       data={"login": login, "display_name": ctx.params["display_name"], "initial_password": initial,
                             "totp_secret": secret, "otpauth_uri": crypto.otpauth_uri(secret, login, self.issuer)},
                       sensitive=True, audit_event="console.user.add", audit_params={"login": login})

    def h_user_remove(self, ctx: Context) -> Outcome:
        login = ctx.params["login"]
        doc = self.users_doc()
        if login not in doc["users"]:
            return Outcome("rejected", "unknown_login", f"Konto {login} nie istnieje.")
        if login == ctx.user:
            return Outcome("rejected", "self_remove", "Nie można usunąć własnego konta. Poproś innego administratora.")
        remaining = [u for u in store.regular_active_users(doc["users"]) if u != login]
        if not remaining:
            return Outcome("rejected", "last_active", "Nie można usunąć ostatniego aktywnego konta.")
        del doc["users"][login]
        self.save_users(doc)
        self.remove_user_files(login)
        return Outcome("ok", "removed", f"Konto {login} usunięte.", audit_event="console.user.remove",
                       audit_params={"login": login})

    def h_user_reset_totp(self, ctx: Context) -> Outcome:
        login = ctx.params["login"]
        if login not in self.users_doc()["users"]:
            return Outcome("rejected", "unknown_login", f"Konto {login} nie istnieje.")
        secret = self.new_seed(login)
        self.unlink_quiet(self.auth_path(login, "fail"))
        return Outcome("ok", "totp_reset", f"Nowy kod TOTP dla {login}. Stary kod przestał działać.",
                       data={"login": login, "totp_secret": secret,
                             "otpauth_uri": crypto.otpauth_uri(secret, login, self.issuer)},
                       sensitive=True, audit_event="console.user.reset_totp", audit_params={"login": login})

    def h_user_password(self, ctx: Context) -> Outcome:
        login = ctx.params["login"]
        doc = self.users_doc()
        user = doc["users"].get(login)
        if not isinstance(user, dict):
            return Outcome("rejected", "unknown_login", f"Konto {login} nie istnieje.")
        self_change = login == ctx.user
        user["password"] = ctx.params["scrypt"]
        user["password_set_at"] = self.now_utc()
        user["must_change"] = not self_change
        self.save_users(doc)
        message = "Hasło zmienione." if self_change else \
            f"Hasło konta {login} ustawione; przy pierwszym logowaniu trzeba będzie je zmienić."
        return Outcome("ok", "password_set", message, audit_event="console.user.password",
                       audit_params={"login": login, "self": self_change})

    def h_login(self, ctx: Context) -> Outcome:
        user = self.users_doc()["users"].get(ctx.user) or {}
        return Outcome("ok", "logged_in", "Zalogowano.",
                       data={"login": ctx.user, "display_name": user.get("display_name"),
                             "must_change": bool(user.get("must_change"))},
                       audit_event="console.login", audit_params={})

    def h_contacts_set(self, ctx: Context) -> Outcome:
        location = self.p(contract.INCIDENT_CONTACTS)
        if not os.path.isdir(os.path.dirname(location)):
            return Outcome("error", "precondition", "Brak katalogu danych biura na serwerze. Zgłoś to dostawcy.")
        doc = {"v": 1, "updated_at": self.now_utc(), **ctx.params}
        self.write_console_file(location, doc)
        return Outcome("ok", "contacts_set", "Kontakty do zgłaszania incydentów zapisane.",
                       audit_event="console.contacts.set", audit_params=self.safe_params("contacts.set", ctx.params))

    def h_setup(self, ctx: Context) -> Outcome:
        if contract.TAG_OFFICE_DEVICE not in ctx.tags:
            return Outcome("rejected", "not_office_device",
                           "Pierwsze konto można założyć tylko z urządzenia biura (tag:office-device).")
        if ctx.user != ctx.params["login"]:
            return Outcome("rejected", "bad_actor", "Login w żądaniu nie zgadza się z zakładanym kontem.")
        doc = self.users_doc()
        if store.regular_active_users(doc["users"]):
            return Outcome("rejected", "already_configured", "Panel ma już konto administratora. Zaloguj się.")
        if ctx.params["login"] in doc["users"]:
            return Outcome("rejected", "exists", "Konto o tym loginie już istnieje.")
        location = self.p(contract.SETUP_CODE_FILE)
        record = store.read_json(location)
        if not isinstance(record, dict) or not isinstance(record.get("scrypt"), str):
            return Outcome("rejected", "no_setup_code", "Brak ważnego kodu konfiguracji. Poproś dostawcę o nowy kod.")
        try:
            expired = validate.parse_utc(record.get("expires_at", "")) <= self.clock()
        except (TypeError, ValueError):
            expired = True
        if expired:
            self.unlink_quiet(location)
            return Outcome("rejected", "setup_code_expired", "Kod konfiguracji wygasł. Poproś dostawcę o nowy kod.")
        if not crypto.scrypt_verify(crypto.normalize_setup_code(ctx.auth["code"]), record["scrypt"]):
            failures = int(record.get("failures", 0)) + 1
            if failures >= SETUP_FAIL_LIMIT:
                self.unlink_quiet(location)
                return Outcome("rejected", "setup_code_destroyed",
                               "Zbyt wiele błędnych kodów — kod konfiguracji unieważniony. Poproś dostawcę o nowy.")
            record["failures"] = failures
            self.write_root_file(location, store.dump_json(record))
            return Outcome("rejected", "bad_setup_code", "Kod konfiguracji jest nieprawidłowy.")
        self.unlink_quiet(location)
        login = ctx.params["login"]
        secret = self._new_account(login, ctx.params["display_name"], ctx.params["scrypt"], False)
        return Outcome("ok", "setup_done", "Konto administratora utworzone. Zeskanuj kod QR w aplikacji "
                                           "uwierzytelniającej i zaloguj się.",
                       data={"login": login, "totp_secret": secret,
                             "otpauth_uri": crypto.otpauth_uri(secret, login, self.issuer)},
                       sensitive=True, audit_event="console.user.setup", audit_params={"login": login})

    # --- prune ------------------------------------------------------------------------------------------
    def prune(self) -> int:
        problems = layout_problems()
        if problems:
            raise Fatal("spool layout does not match the contract: " + "; ".join(problems), EXIT_PRECOND)
        now = self.clock()
        retention = contract.ARCHIVE_RETENTION_DAYS * 86400
        with FileLock(self.p(contract.EXEC_LOCK)):
            results = self.p(contract.REQUESTS_RESULTS)
            for name in sorted(os.listdir(results)):
                location = os.path.join(results, name)
                result = store.read_json(location) if name.endswith(".json") else None
                if not isinstance(result, dict):
                    try:
                        if now - os.lstat(location).st_mtime > contract.SENSITIVE_RESULT_TTL_SECONDS:
                            self.unlink_quiet(location)
                    except FileNotFoundError:
                        pass
                    continue
                try:
                    age = now - validate.parse_utc(result.get("ts", ""))
                except (TypeError, ValueError):
                    age = now - os.lstat(location).st_mtime
                if result.get("sensitive") and age >= contract.SENSITIVE_RESULT_TTL_SECONDS:
                    self.remove_recovery_files(result)
                    self.unlink_quiet(location)
                elif age >= retention:
                    self.unlink_quiet(location)
            for directory in (self.p(contract.REQUESTS_ARCHIVE),):
                for name in os.listdir(directory):
                    location = os.path.join(directory, name)
                    try:
                        if now - os.lstat(location).st_mtime >= retention:
                            self.unlink_quiet(location)
                    except FileNotFoundError:
                        pass
            incoming = self.p(contract.REQUESTS_INCOMING)
            for name in os.listdir(incoming):
                location = os.path.join(incoming, name)
                try:
                    if name.endswith(".json.tmp") and now - os.lstat(location).st_mtime > 600:
                        self.unlink_quiet(location)
                except FileNotFoundError:
                    pass
            self.prune_recovery_dir(now)
        return EXIT_OK

    def remove_recovery_files(self, result: dict) -> None:
        if result.get("type") != "recovery.generate" or not isinstance(result.get("data"), dict):
            return
        recovery_dir = self.p(contract.RECOVERY_DIR)
        for key in ("file", "card"):
            name = result["data"].get(key)
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,200}", name) and not name.startswith("."):
                self.unlink_quiet(os.path.join(recovery_dir, name))

    def prune_recovery_dir(self, now: float) -> None:
        """Packs never outlive the sensitive-result TTL, even if their result is gone."""
        recovery_dir = self.p(contract.RECOVERY_DIR)
        try:
            names = os.listdir(recovery_dir)
        except FileNotFoundError:
            return
        for name in names:
            location = os.path.join(recovery_dir, name)
            try:
                st = os.lstat(location)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(st.st_mode) and now - st.st_mtime > contract.SENSITIVE_RESULT_TTL_SECONDS + 300:
                self.unlink_quiet(location)

    # --- snapshot -------------------------------------------------------------------------------------
    def refresh_snapshot(self) -> dict:
        location = self.p(contract.CONSOLE_SNAPSHOT)
        previous = store.read_json(location)
        previous = previous if isinstance(previous, dict) else {}
        now = self.now_utc()
        snapshot: dict[str, Any] = {"v": 1, "ts": now}

        def section(key: str, loader: Callable[[], Any]) -> None:
            try:
                data = loader()
                snapshot[key] = {"ok": True, "ts": now, **data}
            except Rejected as exc:
                old = previous.get(key) if isinstance(previous.get(key), dict) else {}
                snapshot[key] = {**old, "ok": False, "error": exc.code, "checked_at": now}

        def nodes() -> dict:
            rc, out, _ = self.run_tool(contract.CLI_TAILNET, ["nodes", "--json"], timeout=60)
            if rc != 0 or not isinstance(out, dict) or not isinstance(out.get("nodes"), list):
                raise Rejected("nodes_failed", "nodes")
            keep = ("id", "name", "user", "tags", "ip4", "ip6", "online", "last_seen", "expiry")
            return {"items": [{k: n.get(k) for k in keep} for n in out["nodes"] if isinstance(n, dict)]}

        def staff() -> dict:
            doc = store.read_json(self.p(contract.STAFF_FILE))
            items = doc.get("staff") if isinstance(doc, dict) else doc if isinstance(doc, list) else None
            if doc is None:
                if os.path.exists(self.p(contract.STAFF_FILE)):
                    raise Rejected("staff_unreadable", "staff")
                items = []
            if not isinstance(items, list):
                raise Rejected("staff_unreadable", "staff")
            return {"items": sorted(x for x in items if isinstance(x, str))}

        section("nodes", nodes)
        section("staff", staff)
        self.write_console_file(location, snapshot)
        return snapshot

    def snapshot(self) -> int:
        problems = layout_problems()
        if problems:
            raise Fatal("spool layout does not match the contract: " + "; ".join(problems), EXIT_PRECOND)
        self.refresh_snapshot()
        return EXIT_OK

    # --- bootstrap: setup code and emergency account -----------------------------------------------------
    def setup_code(self, actor: dict) -> dict:
        if store.regular_active_users(self.users_doc()["users"]):
            raise Fatal("the console already has an administrator account; setup codes are only for the first "
                        "account", EXIT_PRECOND)
        code = crypto.new_setup_code()
        expires = validate.format_utc(self.clock() + contract.SETUP_CODE_TTL_HOURS * 3600)
        self.write_root_file(self.p(contract.SETUP_CODE_FILE),
                             store.dump_json({"scrypt": crypto.scrypt_hash(code), "expires_at": expires,
                                              "failures": 0, "created_at": self.now_utc()}))
        self.audit("console.user.setup_code", actor, {"expires_at": expires})
        return {"code": code, "expires_at": expires}

    def emergency_credentials(self, actor: dict) -> dict:
        login = contract.EMERGENCY_LOGIN
        password = crypto.new_password()
        secret = self._new_account(login, "Konto awaryjne (pakiet odzyskiwania)", crypto.scrypt_hash(password),
                                   False, kind="emergency")
        self.unlink_quiet(self.auth_path(login, "step"))
        self.audit("console.user.emergency_rotate", actor, {"login": login})
        return {"login": login, "password": password, "totp_secret": secret,
                "otpauth_uri": crypto.otpauth_uri(secret, login, self.issuer)}


# --- CLI ------------------------------------------------------------------------------------------
def _actor_arg(raw: str | None, default: dict) -> dict:
    if raw is None:
        return default
    try:
        actor = json.loads(raw)
    except ValueError as exc:
        raise Fatal("--actor is not JSON", EXIT_ARGS) from exc
    if not isinstance(actor, dict) or not isinstance(actor.get("kind"), str) or not isinstance(actor.get("id"), str):
        raise Fatal("--actor must be an object with kind and id", EXIT_ARGS)
    return actor


def _default_cli_actor() -> dict:
    sudo_user = os.environ.get("SUDO_USER", "")
    if re.fullmatch(r"v-[a-z][a-z0-9-]{1,20}", sudo_user):  # contract: legatto_vendor_login_regex
        return {"kind": "vendor", "id": sudo_user}
    return {"kind": "system", "id": contract.CLI_CONSOLE_EXEC}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=contract.CLI_CONSOLE_EXEC, description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_process = sub.add_parser("process", help="process requests in incoming/ (legatto-console-exec.service)")
    p_process.add_argument("--once", action="store_true", help="one pass over the files present now")
    sub.add_parser("prune", help="delete expired sensitive results, old archive entries and stale temp files")
    sub.add_parser("snapshot", help="refresh snapshot.json (tailnet nodes, staff list) for the panel")
    p_setup = sub.add_parser("setup-code", help="issue a one-time code for creating the first console account (P7)")
    p_setup.add_argument("--json", action="store_true")
    p_setup.add_argument("--actor", default=None)
    p_emergency = sub.add_parser("emergency-credentials",
                                 help="rotate the emergency account and print it for legatto-recovery-pack")
    p_emergency.add_argument("--json", action="store_true")
    p_emergency.add_argument("--actor", default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_ARGS if exc.code not in (0, None) else EXIT_OK
    try:
        if os.geteuid() != 0:
            raise Fatal("must run as root", EXIT_PRECOND)
        executor = Executor()
        if args.cmd == "process":
            return executor.process(once=args.once)
        if args.cmd == "prune":
            return executor.prune()
        if args.cmd == "snapshot":
            return executor.snapshot()
        if args.cmd == "setup-code":
            actor = _actor_arg(args.actor, _default_cli_actor())
            with FileLock(executor.p(contract.EXEC_LOCK)):
                result = executor.setup_code(actor)
            if args.json:
                print(json.dumps(result))
            else:
                print(f"Kod konfiguracji panelu: {result['code']} (ważny do {executor.local_time(result['expires_at'])}).")
                print("Biuro wpisuje go na stronie /console/ z urządzenia biura. Kod jest jednorazowy.")
            return EXIT_OK
        if args.cmd == "emergency-credentials":
            if not args.json:
                raise Fatal("emergency-credentials prints secrets only with --json (for legatto-recovery-pack)",
                            EXIT_ARGS)
            actor = _actor_arg(args.actor, {"kind": "system", "id": contract.CLI_RECOVERY_PACK})
            with FileLock(executor.p(contract.EXEC_LOCK)):
                print(json.dumps(executor.emergency_credentials(actor)))
            return EXIT_OK
    except Fatal as exc:
        log(str(exc))
        return exc.code
    except Exception as exc:  # noqa: BLE001
        log(f"unexpected error: {type(exc).__name__}: {exc}")
        return EXIT_ERR
    return EXIT_ARGS


if __name__ == "__main__":
    sys.exit(main())
