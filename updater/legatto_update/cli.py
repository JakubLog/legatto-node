"""legatto-update command line (docs/CONTRACT.md section 4.6)."""

import argparse
import errno
import fcntl
import json
import os
import re
import sys
import time
import traceback

from . import const
from .audit import AuditError
from .engine import Engine, Precondition, Result
from .host import Host
from .source import FetchError, SizeError

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ACTOR_KINDS = ("office-admin", "vendor", "system", "bootstrap")
LOCK_WAIT_SECONDS = 10


class Usage(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Usage(message)


def _semver(value):
    if not SEMVER_RE.match(value):
        raise argparse.ArgumentTypeError("not a version: %s" % value)
    return value


def _sha(value):
    if not SHA_RE.match(value):
        raise argparse.ArgumentTypeError("not a sha256: %s" % value)
    return value


def _ts(value):
    if not TS_RE.match(value):
        raise argparse.ArgumentTypeError("time must be YYYY-MM-DDTHH:MM:SSZ")
    return value


def _bool(value):
    if value not in ("true", "false"):
        raise argparse.ArgumentTypeError("expected true|false")
    return value == "true"


def _actor(value):
    try:
        actor = json.loads(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--actor is not JSON") from exc
    if (not isinstance(actor, dict) or actor.get("kind") not in ACTOR_KINDS
            or not isinstance(actor.get("id"), str) or not actor["id"] or len(value) > 1024):
        raise argparse.ArgumentTypeError("--actor must be {\"kind\": %s, \"id\": \"...\"}" % "|".join(ACTOR_KINDS))
    return actor


def build_parser():
    p = _Parser(prog=const.TOOL, description="Pull updates of the Legatto office server.")
    p.add_argument("--json", action="store_true", help="print one JSON object on stdout")
    # Section 4.6: --json is accepted before or after the subcommand. SUPPRESS keeps
    # a subcommand without the flag from resetting a global --json to False.
    common = _Parser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="print one JSON object on stdout")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    def cmd(name, **kw):
        return sub.add_parser(name, parents=[common], **kw)

    cmd("run", help="fetch, verify, gate and install when every gate is open")
    cmd("fetch", help="download documents and artifacts")
    s = cmd("verify", help="verify downloaded documents")
    s.add_argument("--release", type=_semver)
    cmd("status", help="print update.json")
    s = cmd("approve")
    s.add_argument("--release", type=_semver, required=True)
    s.add_argument("--manifest-sha256", type=_sha, required=True)
    when = s.add_mutually_exclusive_group()
    when.add_argument("--not-before", type=_ts)
    when.add_argument("--install-now", action="store_true",
                      help="install as soon as promotion and channel delay allow, outside the install window")
    s.add_argument("--actor", type=_actor, required=True)
    s = cmd("reject")
    s.add_argument("--release", type=_semver, required=True)
    s.add_argument("--manifest-sha256", type=_sha, required=True)
    s.add_argument("--reason", default="")
    s.add_argument("--actor", type=_actor, required=True)
    s = cmd("rollback")
    s.add_argument("--to", type=_semver)
    s.add_argument("--actor", type=_actor, required=True)
    s = cmd("autosecurity")
    s.add_argument("--enabled", type=_bool, required=True)
    s.add_argument("--actor", type=_actor, required=True)
    s = cmd("bootstrap", help="first installation from the update server (policy update_base_url)")
    s.add_argument("--bundle", help="local release mirror instead of the update server (env=test only)")
    s.add_argument("--actor", type=_actor, required=True)
    s = cmd("attest")
    s.add_argument("--release", type=_semver, required=True)
    s.add_argument("--report", required=True)
    return p


def _lock(host):
    path = host.p(const.LOCK)
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES) or time.monotonic() >= deadline:
                os.close(fd)
                return None
            time.sleep(0.5)


def _emit(args, result: Result) -> int:
    if args.json:
        print(json.dumps(result.as_json(), ensure_ascii=False, sort_keys=True))
    print(result.message, file=sys.stderr)
    return result.code


def dispatch(args, host) -> Result:
    eng = Engine(host, getattr(args, "actor", None))
    cmd = args.cmd
    if cmd == "run":
        return eng.cmd_run()
    if cmd == "fetch":
        return eng.cmd_fetch()
    if cmd == "verify":
        return eng.cmd_verify(args.release)
    if cmd == "approve":
        return eng.cmd_approve(args.release, args.manifest_sha256, args.not_before, args.install_now)
    if cmd == "reject":
        if len(args.reason) > 500:
            raise Usage("--reason longer than 500 characters")
        return eng.cmd_reject(args.release, args.manifest_sha256, args.reason)
    if cmd == "rollback":
        return eng.cmd_rollback(args.to)
    if cmd == "autosecurity":
        return eng.cmd_autosecurity(args.enabled)
    if cmd == "bootstrap":
        return eng.cmd_bootstrap(os.path.abspath(args.bundle) if args.bundle else None)
    if cmd == "attest":
        return eng.cmd_attest(args.release, os.path.abspath(args.report))
    raise Usage("unknown command %s" % cmd)


def main(argv=None) -> int:
    host = Host()
    try:
        args = build_parser().parse_args(argv)
    except Usage as exc:
        print("%s: %s" % (const.TOOL, exc), file=sys.stderr)
        return const.EXIT_USAGE
    if args.cmd == "status":
        try:
            doc = Engine(host).cmd_status()
        except Precondition as exc:
            print("%s: %s" % (const.TOOL, exc), file=sys.stderr)
            return const.EXIT_PRECONDITION
        if args.json:
            print(json.dumps(doc, ensure_ascii=False, sort_keys=True))
        else:
            inst = doc.get("installed") or {}
            print("version=%s channel=%s sig=%s upd=%s pending=%d" % (
                inst.get("version"), doc.get("channel"), doc.get("sig"), doc.get("upd"), len(doc.get("pending", []))))
        return const.EXIT_OK
    if not host.is_root():
        print("%s: must run as root" % const.TOOL, file=sys.stderr)
        return const.EXIT_PRECONDITION
    fd = _lock(host)
    if fd is None:
        return _emit(args, Result(const.EXIT_LOCKED, "locked", "Inna instancja legatto-update pracuje; spróbuj później."))
    try:
        return _emit(args, dispatch(args, host))
    except Usage as exc:
        print("%s: %s" % (const.TOOL, exc), file=sys.stderr)
        return const.EXIT_USAGE
    except Precondition as exc:
        return _emit(args, Result(const.EXIT_PRECONDITION, "precondition", "Warunek wstępny niespełniony: %s" % exc))
    except (FetchError, SizeError) as exc:
        return _emit(args, Result(const.EXIT_ERROR, "fetch_failed", "Nie udało się pobrać wydań: %s" % exc))
    except AuditError as exc:
        return _emit(args, Result(const.EXIT_ERROR, "audit_failed", "Zapis audytu nieudany: %s" % exc))
    except Exception as exc:  # noqa: BLE001 - last resort: report, never print secrets
        traceback.print_exc(file=sys.stderr)
        return _emit(args, Result(const.EXIT_ERROR, "error", "Nieoczekiwany błąd: %s" % type(exc).__name__))
    finally:
        os.close(fd)
