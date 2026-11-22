"""Validation of spool requests (CONTRACT §4.3), shared by panel and executor.

The panel validates before writing a request so the admin sees mistakes at
once; the executor validates again because it trusts nothing the
unprivileged panel wrote.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import unicodedata
from typing import Any

from . import contract, crypto

SEMVER_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
LOGIN_RE = re.compile(r"[a-z][a-z0-9.-]{1,40}")  # staff and console logins (CONTRACT §4.3 staff.set)
NODE_ID_RE = re.compile(r"[1-9][0-9]{0,9}")
HOSTNAME_RE = re.compile(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
EMAIL_RE = re.compile(r"[^@\s<>\"']{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?[0-9][0-9 ()-]{5,28}[0-9]")
TOTP_RE = re.compile(r"[0-9]{6}")

DISPLAY_NAME_MAX = 80
CONTACT_FIELD_MAX = 200  # integrator condition for contacts.set
STAFF_MAX = 200
ICS_HOSTS_MAX = 50  # egress lane limit
SETUP_CODE_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}")

_TAILNET_NETS = (ipaddress.ip_network(contract.TAILNET_PREFIX_V4), ipaddress.ip_network(contract.TAILNET_PREFIX_V6))


class Invalid(ValueError):
    """A request or field failed validation; `code` is machine readable, str() is Polish."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --- Strict JSON ---------------------------------------------------------------------
def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("bad_json", "Powtórzony klucz w JSON.")
        result[key] = value
    return result


def _no_constants(name: str) -> Any:
    raise Invalid("bad_json", f"Niedozwolona wartość {name} w JSON.")


def strict_json(raw: bytes) -> Any:
    """Parse UTF-8 JSON rejecting duplicate keys and NaN/Infinity."""
    try:
        text = raw.decode("utf-8")
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except Invalid:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise Invalid("bad_json", "Żądanie nie jest poprawnym JSON.") from exc


# --- Field helpers ---------------------------------------------------------------------
def plain_text(value: Any, field: str, min_len: int, max_len: int) -> str:
    """Single-line plain text: no control, format or private-use characters."""
    if not isinstance(value, str):
        raise Invalid("bad_params", f"Pole {field} musi być tekstem.")
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise Invalid("bad_params", f"Pole {field} zawiera niedozwolone znaki sterujące.")
    if value != value.strip():
        raise Invalid("bad_params", f"Pole {field} nie może zaczynać się ani kończyć spacją.")
    if not min_len <= len(value) <= max_len:
        raise Invalid("bad_params", f"Pole {field} musi mieć od {min_len} do {max_len} znaków.")
    return value


def int_range(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Invalid("bad_params", f"Pole {field} musi być liczbą całkowitą od {low} do {high}.")
    return value


def boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise Invalid("bad_params", f"Pole {field} musi mieć wartość tak/nie.")
    return value


def login(value: Any, field: str = "login") -> str:
    if not isinstance(value, str) or not LOGIN_RE.fullmatch(value):
        raise Invalid("bad_params", f"Pole {field}: login z małych liter, cyfr, kropek i myślników (2–41 znaków).")
    return value


def console_login(value: Any) -> str:
    """Login of a regular console account; the emergency login is reserved."""
    value = login(value)
    if value == contract.EMERGENCY_LOGIN:
        raise Invalid("reserved_login", f"Login {contract.EMERGENCY_LOGIN} jest zarezerwowany dla konta awaryjnego.")
    return value


def utc(value: Any, field: str) -> str:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise Invalid("bad_params", f"Pole {field} musi być czasem UTC w formacie RRRR-MM-DDTGG:MM:SSZ.")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise Invalid("bad_params", f"Pole {field} nie jest poprawną datą.") from exc
    return value


def semver(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or not SEMVER_RE.fullmatch(value):
        raise Invalid("bad_params", f"Pole {field} musi być numerem wersji (np. 1.5.0).")
    return value


def sha256_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise Invalid("bad_params", f"Pole {field} musi być skrótem SHA-256 (64 znaki hex).")
    return value


def scrypt_string(value: Any) -> str:
    try:
        crypto.parse_scrypt(value)
    except crypto.WeakHash as exc:
        raise Invalid("weak_hash", "Hash hasła jest słabszy niż wymagany (scrypt n≥2^15, r=8, p=1).") from exc
    except ValueError as exc:
        raise Invalid("bad_params", "Niepoprawny format hasha hasła.") from exc
    return value


def hostname(value: Any) -> str:
    if not isinstance(value, str) or not HOSTNAME_RE.fullmatch(value):
        raise Invalid("bad_params", f"Niepoprawna nazwa hosta: {str(value)[:80]!r} (małe litery, bez portu i adresu IP).")
    return value


def _exact_keys(params: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:
    keys = set(params)
    missing = required - keys
    extra = keys - required - set(optional)
    if missing:
        raise Invalid("bad_params", "Brak pól: " + ", ".join(sorted(missing)) + ".")
    if extra:
        raise Invalid("bad_params", "Nieznane pola: " + ", ".join(sorted(extra)) + ".")


def _person(value: Any, field: str, required: bool) -> dict[str, str] | None:
    if value is None:
        if required:
            raise Invalid("bad_params", f"Pole {field} jest wymagane.")
        return None
    if not isinstance(value, dict):
        raise Invalid("bad_params", f"Pole {field} musi być obiektem.")
    _exact_keys(value, {"name", "email", "phone"})
    name = plain_text(value["name"], f"{field}.name", 2, CONTACT_FIELD_MAX)
    email = plain_text(value["email"], f"{field}.email", 0, CONTACT_FIELD_MAX)
    phone = plain_text(value["phone"], f"{field}.phone", 0, CONTACT_FIELD_MAX)
    if email and not EMAIL_RE.fullmatch(email):
        raise Invalid("bad_params", f"Pole {field}.email nie jest adresem e-mail.")
    if phone and not PHONE_RE.fullmatch(phone):
        raise Invalid("bad_params", f"Pole {field}.phone nie jest numerem telefonu.")
    if not email and not phone:
        raise Invalid("bad_params", f"Pole {field}: podaj e-mail lub telefon.")
    return {"name": name, "email": email, "phone": phone}


# --- Per-type params -----------------------------------------------------------------
def params_for(rtype: str, params: Any) -> dict[str, Any]:
    """Validate and normalise `params` of a request of type `rtype`."""
    if not isinstance(params, dict):
        raise Invalid("bad_params", "Pole params musi być obiektem.")
    p = params
    if rtype == "breakglass.enable":
        _exact_keys(p, {"hours", "reason"})
        return {
            "hours": int_range(p["hours"], "hours", contract.BREAKGLASS_HOURS_MIN, contract.BREAKGLASS_HOURS_MAX),
            "reason": plain_text(p["reason"], "reason", contract.BREAKGLASS_REASON_MIN, contract.BREAKGLASS_REASON_MAX),
        }
    if rtype == "breakglass.disable":
        _exact_keys(p, set(), {"reason"})
        return {"reason": plain_text(p.get("reason", ""), "reason", 0, contract.BREAKGLASS_REASON_MAX)}
    if rtype == "update.approve":
        _exact_keys(p, {"release", "manifest_sha256"}, {"not_before"})
        out = {"release": semver(p["release"], "release"), "manifest_sha256": sha256_hex(p["manifest_sha256"], "manifest_sha256")}
        if "not_before" in p:
            out["not_before"] = utc(p["not_before"], "not_before")
        return out
    if rtype == "update.reject":
        _exact_keys(p, {"release", "manifest_sha256"}, {"reason"})
        return {
            "release": semver(p["release"], "release"),
            "manifest_sha256": sha256_hex(p["manifest_sha256"], "manifest_sha256"),
            "reason": plain_text(p.get("reason", ""), "reason", 0, 500),
        }
    if rtype == "update.rollback":
        _exact_keys(p, set(), {"to"})
        return {"to": semver(p["to"], "to")} if "to" in p else {}
    if rtype == "update.autosecurity":
        _exact_keys(p, {"enabled"})
        return {"enabled": boolean(p["enabled"], "enabled")}
    if rtype == "studio.enable":
        _exact_keys(p, {"hours"})
        return {"hours": int_range(p["hours"], "hours", 1, 8)}
    if rtype in ("studio.disable", "recovery.generate", "console.login"):
        _exact_keys(p, set())
        return {}
    if rtype == "device.enroll":
        kind = p.get("kind")
        if kind == "staff":
            _exact_keys(p, {"kind", "login"})
            return {"kind": "staff", "login": login(p["login"])}
        if kind == "office-device":
            _exact_keys(p, {"kind"})
            return {"kind": "office-device"}
        raise Invalid("bad_params", "Pole kind musi mieć wartość staff albo office-device.")
    if rtype == "device.revoke":
        _exact_keys(p, {"node_id"})
        node_id = p["node_id"]
        if not isinstance(node_id, str) or not NODE_ID_RE.fullmatch(node_id):
            raise Invalid("bad_params", "Pole node_id musi być identyfikatorem węzła (liczba).")
        return {"node_id": node_id}
    if rtype == "staff.set":
        _exact_keys(p, {"staff"})
        staff = p["staff"]
        if not isinstance(staff, list) or len(staff) > STAFF_MAX:
            raise Invalid("bad_params", f"Pole staff musi być listą do {STAFF_MAX} loginów.")
        logins = [login(item, "staff") for item in staff]
        if len(set(logins)) != len(logins):
            raise Invalid("bad_params", "Lista personelu zawiera powtórzone loginy.")
        return {"staff": sorted(logins)}
    if rtype == "features.set":
        feature = p.get("feature")
        if feature not in contract.FEATURE_NAMES:
            raise Invalid("bad_params", "Nieznana funkcja.")
        if feature == "ics":
            _exact_keys(p, {"feature", "enabled"}, {"ics_hosts"})
        else:
            _exact_keys(p, {"feature", "enabled"})
        out: dict[str, Any] = {"feature": feature, "enabled": boolean(p["enabled"], "enabled")}
        if feature == "ics":
            hosts = p.get("ics_hosts", [])
            if not isinstance(hosts, list) or len(hosts) > ICS_HOSTS_MAX:
                raise Invalid("bad_params", f"Pole ics_hosts musi być listą do {ICS_HOSTS_MAX} nazw hostów.")
            names = [hostname(h) for h in hosts]
            if len(set(names)) != len(names):
                raise Invalid("bad_params", "Lista hostów kalendarza zawiera powtórzenia.")
            if out["enabled"] and not names:
                raise Invalid("bad_params", "Włączenie kalendarzy ICS wymaga co najmniej jednego hosta.")
            out["ics_hosts"] = sorted(names)
        return out
    if rtype == "console.user.add":
        _exact_keys(p, {"login", "display_name"})
        return {"login": console_login(p["login"]),
                "display_name": plain_text(p["display_name"], "display_name", 2, DISPLAY_NAME_MAX)}
    if rtype in ("console.user.remove", "console.user.reset_totp"):
        _exact_keys(p, {"login"})
        return {"login": console_login(p["login"])}
    if rtype == "console.user.password":
        _exact_keys(p, {"login", "scrypt"})
        return {"login": console_login(p["login"]), "scrypt": scrypt_string(p["scrypt"])}
    if rtype == "console.setup":
        _exact_keys(p, {"login", "display_name", "scrypt"})
        return {"login": console_login(p["login"]),
                "display_name": plain_text(p["display_name"], "display_name", 2, DISPLAY_NAME_MAX),
                "scrypt": scrypt_string(p["scrypt"])}
    if rtype == "contacts.set":
        _exact_keys(p, {"primary"}, {"secondary", "iod", "notes"})
        return {
            "primary": _person(p["primary"], "primary", True),
            "secondary": _person(p.get("secondary"), "secondary", False),
            "iod": _person(p.get("iod"), "iod", False),
            "notes": plain_text(p.get("notes", ""), "notes", 0, CONTACT_FIELD_MAX),
        }
    raise Invalid("bad_type", "Nieznany typ żądania.")


# --- Envelope -----------------------------------------------------------------------------
def tailnet_ip(value: Any) -> str:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError) as exc:
        raise Invalid("bad_actor", "Niepoprawny adres IP klienta.") from exc
    if not any(address.version == net.version and address in net for net in _TAILNET_NETS):
        raise Invalid("bad_actor", "Adres klienta spoza tailnetu.")
    return address.compressed


def envelope(obj: Any) -> dict[str, Any]:
    """Structural checks of a request object except id/ts/params (checked by the caller in contract order)."""
    if not isinstance(obj, dict):
        raise Invalid("bad_json", "Żądanie musi być obiektem JSON.")
    _exact_keys_env(obj)
    if obj["v"] != contract.REQUEST_VERSION or isinstance(obj["v"], bool):
        raise Invalid("bad_version", "Nieobsługiwana wersja żądania.")
    return obj


def _exact_keys_env(obj: dict[str, Any]) -> None:
    expected = {"v", "id", "type", "ts", "actor", "auth", "params"}
    if set(obj) != expected:
        raise Invalid("bad_json", "Żądanie ma niepoprawny zestaw pól.")


def actor(obj: Any) -> dict[str, str]:
    if not isinstance(obj, dict) or set(obj) != {"user", "ip"}:
        raise Invalid("bad_actor", "Pole actor musi zawierać dokładnie user i ip.")
    user = login(obj["user"], "actor.user")
    return {"user": user, "ip": tailnet_ip(obj["ip"])}


def auth(obj: Any, rtype: str) -> dict[str, str]:
    if not isinstance(obj, dict):
        raise Invalid("bad_auth", "Brak danych uwierzytelnienia.")
    if rtype == "console.setup":
        if set(obj) != {"method", "code"} or obj["method"] != "setup-code" or not isinstance(obj["code"], str):
            raise Invalid("bad_auth", "Konfiguracja wymaga kodu jednorazowego.")
        if not SETUP_CODE_RE.fullmatch(obj["code"]):
            raise Invalid("bad_setup_code", "Kod jednorazowy ma niepoprawny format.")
        return {"method": "setup-code", "code": obj["code"]}
    if set(obj) != {"method", "totp"} or obj["method"] != "local-totp" or not isinstance(obj["totp"], str):
        raise Invalid("bad_auth", "Żądanie wymaga kodu TOTP.")
    if not TOTP_RE.fullmatch(obj["totp"]):
        raise Invalid("bad_totp", "Kod TOTP musi mieć 6 cyfr.")
    return {"method": "local-totp", "totp": obj["totp"]}


def parse_utc(value: str) -> float:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


def format_utc(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_display(utc_value: Any, tzname: str = contract.TIMEZONE, with_seconds: bool = False) -> str:
    """`YYYY-MM-DDTHH:MM:SSZ` shown as office local time (`DD.MM.YYYY HH:MM`)."""
    if not isinstance(utc_value, str) or not UTC_RE.fullmatch(utc_value):
        return "—" if not utc_value else str(utc_value)[:40]
    try:
        from zoneinfo import ZoneInfo

        zone: dt.tzinfo = ZoneInfo(tzname)
    except Exception:  # noqa: BLE001 - missing tzdata: fall back to UTC
        zone = dt.timezone.utc
    try:
        moment = dt.datetime.fromtimestamp(parse_utc(utc_value), zone)
    except ValueError:
        return utc_value
    return moment.strftime("%d.%m.%Y %H:%M:%S" if with_seconds else "%d.%m.%Y %H:%M")
