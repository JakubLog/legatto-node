"""Read-only views of server state for the panel (status files, pending releases, audit, snapshot)."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from . import contract, crypto, store, validate

AUDIT_TAIL_BYTES = 4 * 1024 * 1024
WINDOW_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def status(name: str) -> dict | None:
    if name not in contract.STATUS_FILES:
        return None
    doc = store.read_json(os.path.join(contract.path(contract.STATUS_DIR), name + ".json"))
    return doc if isinstance(doc, dict) else None


def all_status() -> dict[str, dict | None]:
    return {name: status(name) for name in contract.STATUS_FILES}


def pending_release(version: Any) -> dict | None:
    if not isinstance(version, str) or not validate.SEMVER_RE.fullmatch(version) or len(version) > 64:
        return None
    doc = store.read_json(os.path.join(contract.path(contract.UPDATE_PENDING), version + ".json"))
    return doc if isinstance(doc, dict) else None


def snapshot() -> dict:
    doc = store.read_json(contract.path(contract.CONSOLE_SNAPSHOT))
    return doc if isinstance(doc, dict) else {}


def features() -> dict | None:
    doc = store.read_json(contract.path(contract.FEATURES))
    return doc if isinstance(doc, dict) and isinstance(doc.get("features"), dict) else None


def contacts() -> dict | None:
    doc = store.read_json(contract.path(contract.INCIDENT_CONTACTS))
    return doc if isinstance(doc, dict) else None


def audit_tail(categories: tuple[str, ...], limit: int = 50) -> list[dict]:
    """Newest-first audit entries of the given categories from the end of audit.log."""
    location = contract.path(contract.AUDIT_LOG)
    try:
        with open(location, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - AUDIT_TAIL_BYTES)
            handle.seek(start)
            chunk = handle.read()
    except OSError:
        return []
    lines = chunk.split(b"\n")
    if start > 0:
        lines = lines[1:]  # first line is probably cut
    result = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(entry, dict) and entry.get("cat") in categories:
            result.append(entry)
            if len(result) >= limit:
                break
    return result


def breakglass_summaries(limit: int = 30) -> list[dict]:
    directory = contract.path(contract.BREAKGLASS_SUMMARIES)
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    items = []
    for name in names:
        if not name.endswith(".json") or not WINDOW_ID_RE.fullmatch(name[:-5]):
            continue
        doc = store.read_json(os.path.join(directory, name))
        if isinstance(doc, dict):
            doc.setdefault("window_id", name[:-5])
            items.append(doc)
    items.sort(key=lambda d: str(d.get("started_at") or ""), reverse=True)
    return items[:limit]


def breakglass_summary(window_id: str) -> dict | None:
    if not WINDOW_ID_RE.fullmatch(window_id or ""):
        return None
    doc = store.read_json(os.path.join(contract.path(contract.BREAKGLASS_SUMMARIES), window_id + ".json"))
    return doc if isinstance(doc, dict) else None


def result(rid: str) -> dict | None:
    if not crypto.is_ulid(rid):
        return None
    doc = store.read_json(os.path.join(contract.path(contract.REQUESTS_RESULTS), rid + ".json"), max_bytes=1024 * 1024)
    if not isinstance(doc, dict) or doc.get("id") != rid:
        return None
    return doc
