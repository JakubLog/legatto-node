"""status/update.json (section 4.4) and pending/<version>.json for the console."""

import os

from . import const
from .host import fmt_ts, semver_gt

UPD_ORDER = ("failed", "rb", "rej", "stale", "vuln", "blocked-baseline", "installing", "optout", "pending",
             "waiting", "ok")
DOWN = ("failed", "rb", "rej", "vuln", "stale")
PENDING_KEYS = ("version", "sequence", "type", "channel", "manifest_sha256", "state", "first_seen_at",
                "promotion_first_seen_at", "earliest_install_at", "released_at", "expires", "min_installed",
                "min_contract_version", "changelog_url", "notes_md", "advisories", "signers",
                "canary_attestation", "egress", "approval", "rejection", "verify", "needs_approval")


def compute_upd(store) -> str:
    st = store.state
    flags = st["flags"]
    inst = st.get("installed")
    cands = st.get("candidates") or []
    found = set()
    if flags.get("failed"):
        found.add("failed")
    if flags.get("rb"):
        found.add("rb")
    if flags.get("rej") or st.get("sig") == "bad":
        found.add("rej")
    if flags.get("stale"):
        found.add("stale")
    if flags.get("vuln") and inst and semver_gt(flags["vuln"], inst["version"]):
        found.add("vuln")
    if flags.get("installing"):
        found.add("installing")
    for c in cands:
        if c["state"] == "blocked-baseline":
            found.add("blocked-baseline")
        elif c["state"] == "waiting-approval":
            if c["type"] == "security" and store.admin["auto_security_optout"]:
                found.add("optout")
            else:
                found.add("pending")
        elif c["state"] in ("waiting-promotion", "waiting-delay", "waiting-window", "ready"):
            found.add("waiting")
    for upd in UPD_ORDER:
        if upd in found:
            return upd
    return "ok"


def summary_candidates(ev_candidates: list) -> list:
    out = []
    for c in ev_candidates:
        out.append({k: c.get(k) for k in PENDING_KEYS})
    return out


def write_status(host, store, policy, now: float) -> dict:
    st = store.state
    inst = st.get("installed")
    upd = compute_upd(store)
    sig = st.get("sig", "none")
    doc = {
        "v": 1,
        "component": "update",
        "ts": fmt_ts(now),
        "ok": sig != "bad" and upd not in DOWN,
        "installed": ({k: inst.get(k) for k in ("version", "sequence", "manifest_sha256", "installed_at")}
                      if inst else {"version": None, "sequence": None, "manifest_sha256": None,
                                    "installed_at": None}),
        "channel": policy["channel"] if policy else None,
        "sig": sig,
        "upd": upd,
        "auto_security": {"policy": bool(policy and policy["auto_security"]),
                          "admin_optout": bool(store.admin["auto_security_optout"])},
        "last_check": st["last_check"],
        "pending": [{
            "version": c["version"], "sequence": c["sequence"], "type": c["type"],
            "manifest_sha256": c["manifest_sha256"], "state": c["state"],
            "earliest_install_at": c.get("earliest_install_at"),
            "egress_widening": bool(c.get("egress") and c["egress"].get("widening")),
            "changelog_url": c.get("changelog_url"),
        } for c in st.get("candidates") or []],
    }
    host.write_json(os.path.join(host.p(const.STATUS_DIR), "update.json"), doc, mode=0o640,
                    group=const.GROUP_STATUS)
    pending_dir = host.p(const.UPDATE_PENDING)
    os.makedirs(pending_dir, exist_ok=True)
    keep = set()
    for c in st.get("candidates") or []:
        name = "%s.json" % c["version"]
        keep.add(name)
        body = {"v": 1, "updated_at": fmt_ts(now)}
        body.update({k: c.get(k) for k in PENDING_KEYS})
        host.write_json(os.path.join(pending_dir, name), body, mode=0o640, group=const.GROUP_CONSOLE)
    for name in os.listdir(pending_dir):
        if name.endswith(".json") and name not in keep:
            os.unlink(os.path.join(pending_dir, name))
    return doc
