"""Local state of the updater (/var/lib/legatto/update).

state.json       installed release, history of kept releases, last index,
                 flags shown in update.json, trusted clock
first_seen.json  local first-seen of every verified document (delays, D7(b))
admin.json       office-admin decisions: approvals, rejections, auto-security opt-out
migrations.json  migrations applied through the updater (name -> sha256)
"""

import os

from . import const
from .host import fmt_ts, read_json

STATE_VERSION = 1


def _empty_state():
    return {
        "v": STATE_VERSION,
        "installed": None,
        "history": [],
        "index": None,
        "last_check": {"ts": None, "ok": False, "ok_ts": None, "index_sequence": None, "index_expires": None},
        "sig": "none",
        "flags": {"rb": None, "failed": None, "stale": False, "rej": False, "vuln": None,
                  "worker_pending": None, "installing": None},
        "failed_releases": {},
        "clock": None,
        "audited": {},
        "candidates": [],
    }


class Store:
    def __init__(self, host):
        self.host = host
        self.dir = host.state()
        self.state = _empty_state()
        self.first_seen = {}
        self.admin = {"approvals": {}, "rejections": {}, "auto_security_optout": False}
        self.migrations = {"applied": {}}

    def load(self):
        st = read_json(os.path.join(self.dir, const.STATE_FILE))
        if st:
            base = _empty_state()
            base.update(st)
            base["flags"] = dict(_empty_state()["flags"], **(st.get("flags") or {}))
            self.state = base
        self.first_seen = read_json(os.path.join(self.dir, const.FIRST_SEEN_FILE), {}) or {}
        admin = read_json(os.path.join(self.dir, const.ADMIN_FILE)) or {}
        self.admin = {"approvals": admin.get("approvals", {}), "rejections": admin.get("rejections", {}),
                      "auto_security_optout": bool(admin.get("auto_security_optout", False))}
        self.migrations = read_json(os.path.join(self.dir, const.MIGRATIONS_FILE), {"applied": {}}) or {"applied": {}}
        return self

    def save(self):
        os.makedirs(self.dir, exist_ok=True)
        self.host.write_json(os.path.join(self.dir, const.STATE_FILE), self.state, mode=0o600)
        self.host.write_json(os.path.join(self.dir, const.FIRST_SEEN_FILE), self.first_seen, mode=0o600)
        self.host.write_json(os.path.join(self.dir, const.ADMIN_FILE), self.admin, mode=0o600)
        self.host.write_json(os.path.join(self.dir, const.MIGRATIONS_FILE), self.migrations, mode=0o600)

    # --- first seen -------------------------------------------------------------------
    def seen(self, sha256: str, trusted: float, wall: float, kind: str, version: str) -> dict:
        entry = self.first_seen.get(sha256)
        if entry is None:
            entry = {"trusted": trusted, "wall": fmt_ts(wall), "kind": kind, "version": version}
            self.first_seen[sha256] = entry
        return entry

    # --- audit de-duplication ------------------------------------------------------------
    def once(self, key: str, wall: float) -> bool:
        """True the first time `key` is seen (one audit entry per event and document)."""
        if key in self.state["audited"]:
            return False
        self.state["audited"][key] = fmt_ts(wall)
        if len(self.state["audited"]) > 2000:
            for old in sorted(self.state["audited"], key=self.state["audited"].get)[:500]:
                del self.state["audited"][old]
        return True


class TrustedClock:
    """Elapsed time that wall-clock jumps cannot accelerate (rule 5).

    Within one boot the elapsed time is CLOCK_MONOTONIC; a wall-clock delta
    that differs from it by more than clock_jump_block_minutes is a jump.
    Across reboots only the wall delta exists: a backwards step or a time
    earlier than the latest wall time seen is a jump and adds nothing.
    """

    def __init__(self, host, store, block_minutes: int):
        self.host = host
        self.store = store
        self.block = block_minutes * 60
        self.jumped = False
        self.jump_detail = None

    def tick(self) -> float:
        wall, mono, boot = self.host.now(), self.host.mono(), self.host.boot_id()
        clock = self.store.state.get("clock")
        if not clock:
            clock = {"boot_id": boot, "mono": mono, "wall": wall, "max_wall": wall, "trusted": wall,
                     "jump_until": None}
        else:
            wall_d = wall - clock["wall"]
            if clock["boot_id"] == boot and mono >= clock["mono"]:
                mono_d = mono - clock["mono"]
                if abs(wall_d - mono_d) > self.block:
                    self._jump(wall_d - mono_d)
                clock["trusted"] += mono_d
            else:
                if wall_d < -self.block:
                    self._jump(wall_d)
                clock["trusted"] += max(0.0, wall_d)
            if wall < clock.get("max_wall", wall) - self.block:
                self._jump(wall - clock["max_wall"])
            clock["boot_id"], clock["mono"], clock["wall"] = boot, mono, wall
            clock["max_wall"] = max(clock.get("max_wall", wall), wall)
            if self.jumped:
                clock["jump_until"] = clock["trusted"] + self.block
        self.store.state["clock"] = clock
        return clock["trusted"]

    def _jump(self, delta: float):
        self.jumped = True
        self.jump_detail = int(delta)

    def blocked(self) -> bool:
        clock = self.store.state.get("clock") or {}
        until = clock.get("jump_until")
        return until is not None and clock.get("trusted", 0) < until
