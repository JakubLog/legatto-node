"""Audit entries through the single writer `legatto-audit append` (section 4.2)."""

import json

from . import const
from .host import CommandError

SYSTEM_ACTOR = {"kind": "system", "id": const.TOOL}

EVENTS = ("fetched", "verified", "rejected", "pending", "approved", "declined", "installing", "installed",
          "rolled_back", "rollback_failed", "stale", "clock_jump", "autosecurity", "attested",
          "installed_yanked")


class AuditError(Exception):
    pass


class Audit:
    def __init__(self, host):
        self.host = host

    def append(self, event: str, params: dict, actor=None) -> int:
        if event not in EVENTS:
            raise ValueError("unknown audit event %s" % event)
        actor = dict(actor or SYSTEM_ACTOR)
        node = actor.pop("node", None)
        argv = [const.CLI_AUDIT, "append", "--cat", "update", "--event", "update." + event,
                "--actor", json.dumps(actor, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                "--params", json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)]
        if node:
            argv += ["--node", str(node)]
        try:
            _rc, out, _err = self.host.run(argv, timeout=30)
        except CommandError as exc:
            raise AuditError("legatto-audit append update.%s failed (exit %s)" % (event, exc.rc)) from exc
        try:
            return int(json.loads(out).get("seq"))
        except (ValueError, TypeError, AttributeError):
            return 0
