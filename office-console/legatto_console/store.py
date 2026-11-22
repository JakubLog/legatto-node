"""Files shared by panel and executor: atomic writes, JSON reads, office.env, users."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from . import contract


def atomic_write(target: str, data: bytes, mode: int = 0o640, uid: int | None = None, gid: int | None = None) -> None:
    """Write `data` to `target` via a temporary file in the same directory, fsync and rename."""
    directory = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(tmp, target)
        tmp = ""
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def dump_json(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def read_json(location: str, max_bytes: int = 4 * 1024 * 1024) -> Any:
    """Parse a JSON file; None when it is missing, unreadable, too large or invalid."""
    try:
        with open(location, "rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def office_env() -> dict[str, str]:
    """`/etc/legatto/office.env` (CONTRACT §4.1): KEY=value lines, no quoting, no expansion."""
    result: dict[str, str] = {}
    try:
        with open(contract.path(contract.OFFICE_ENV), encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.startswith("LEGATTO_"):
                    result[key] = value
    except OSError:
        pass
    return result


def load_users() -> dict[str, dict[str, Any]]:
    """Console accounts from users.json (written only by the executor)."""
    doc = read_json(contract.path(contract.CONSOLE_USERS))
    if not isinstance(doc, dict) or not isinstance(doc.get("users"), dict):
        return {}
    return {k: v for k, v in doc["users"].items() if isinstance(v, dict)}


def regular_active_users(users: dict[str, dict[str, Any]]) -> list[str]:
    """Enabled accounts other than the emergency account."""
    return sorted(login for login, user in users.items()
                  if user.get("enabled") and user.get("kind") != "emergency" and login != contract.EMERGENCY_LOGIN)
