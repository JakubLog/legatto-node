"""office-console: the office admin panel on admin.app.<domain>/console/ (CONTRACT §4.3).

Runs as the unprivileged user legatto-console behind Caddy on the unix socket
/run/legatto/office-console.sock (socket activation, legatto-console.socket).
It reads status files and writes request files; it cannot change anything by
itself. Login: scrypt password checked here, TOTP checked by the root
executor (console.login). Every state change is a spool request carrying a
fresh TOTP code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import stat
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from . import contract, crypto, data, pages, store, validate
from .validate import Invalid

BASE = pages.BASE
SESSION_COOKIE = "__Host-lgc"
PRE_COOKIE = "__Host-lgc_pre"
SESSION_IDLE_SECONDS = 15 * 60
SESSION_MAX_SECONDS = 8 * 3600
SESSION_LIMIT = 200
LOGIN_FAIL_LIMIT = 5
LOGIN_FAIL_WINDOW = 15 * 60
MAX_BODY = 64 * 1024
PASSWORD_MIN = 12
PASSWORD_MAX = 256
OWNED_REQUEST_TTL = 30 * 60
SECURITY_HEADERS = (
    ("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    ("Strict-Transport-Security", "max-age=31536000"),
)


def log(message: str) -> None:
    print(f"office-console: {message}", file=sys.stderr, flush=True)


# --- HTTP plumbing -----------------------------------------------------------------------------
@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes = b""
    ip: str = ""

    @property
    def cookies(self) -> dict[str, str]:
        result = {}
        for part in self.headers.get("cookie", "").split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                result.setdefault(key, value)
        return result

    def form(self) -> dict[str, str]:
        if not self.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            raise Invalid("bad_form", "Nieobsługiwany format formularza.")
        try:
            parsed = urllib.parse.parse_qs(self.body.decode("utf-8"), keep_blank_values=True, max_num_fields=200)
        except (UnicodeDecodeError, ValueError) as exc:
            raise Invalid("bad_form", "Niepoprawny formularz.") from exc
        return {k: v[0] for k, v in parsed.items()}


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def redirect(cls, location: str, status: int = 303) -> "Response":
        return cls(status, b"", "text/plain; charset=utf-8", [("Location", location)])


# --- sessions --------------------------------------------------------------------------------------
@dataclass
class Session:
    login: str
    display_name: str
    ip: str
    csrf: str
    created: float
    last_seen: float
    must_change: bool = False
    requests: dict[str, tuple[str, float]] = field(default_factory=dict)  # id -> (type, submitted_at)
    secrets: dict[str, dict] = field(default_factory=dict)  # id -> values shown once (temporary passwords)
    flash: list[tuple[str, str]] = field(default_factory=list)


class Sessions:
    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.lock = threading.Lock()
        self.items: dict[str, Session] = {}

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, login: str, display_name: str, ip: str, must_change: bool) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = self.clock()
        session = Session(login, display_name, ip, secrets.token_urlsafe(32), now, now, must_change)
        with self.lock:
            self._purge(now)
            if len(self.items) >= SESSION_LIMIT:
                oldest = min(self.items, key=lambda k: self.items[k].last_seen)
                del self.items[oldest]
            self.items[self._key(token)] = session
        return token, session

    def get(self, token: str | None, ip: str) -> Session | None:
        if not token or len(token) > 100:
            return None
        now = self.clock()
        with self.lock:
            self._purge(now)
            session = self.items.get(self._key(token))
            if session is None:
                return None
            if session.ip != ip:  # tailnet addresses are stable per device; a new address means a new login
                del self.items[self._key(token)]
                return None
            session.last_seen = now
            return session

    def destroy(self, token: str | None) -> None:
        if token:
            with self.lock:
                self.items.pop(self._key(token), None)

    def destroy_user(self, login: str) -> None:
        with self.lock:
            for key in [k for k, s in self.items.items() if s.login == login]:
                del self.items[key]

    def _purge(self, now: float) -> None:
        for key in [k for k, s in self.items.items()
                    if now - s.last_seen > SESSION_IDLE_SECONDS or now - s.created > SESSION_MAX_SECONDS]:
            del self.items[key]


class Throttle:
    """Failed logins per key (login name, client address) in a sliding window."""

    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.lock = threading.Lock()
        self.failures: dict[str, list[float]] = {}

    def blocked(self, *keys: str) -> bool:
        now = self.clock()
        with self.lock:
            for key in keys:
                recent = [t for t in self.failures.get(key, []) if now - t < LOGIN_FAIL_WINDOW]
                self.failures[key] = recent
                if len(recent) >= LOGIN_FAIL_LIMIT:
                    return True
        return False

    def fail(self, *keys: str) -> None:
        now = self.clock()
        with self.lock:
            for key in keys:
                self.failures.setdefault(key, []).append(now)
            if len(self.failures) > 10000:
                self.failures.clear()


# --- the application -------------------------------------------------------------------------------
@dataclass
class Config:
    host: str
    title: str
    tz: str
    submit_wait: float = 15.0
    setup_wait: float = 60.0
    require_surface: bool = True

    @classmethod
    def from_office_env(cls) -> "Config":
        env = store.office_env()
        host = env.get("LEGATTO_HOST_ADMIN", "")
        if not host:
            raise SystemExit("office-console: LEGATTO_HOST_ADMIN missing in office.env")
        return cls(host=host.lower(), title=env.get("LEGATTO_OFFICE_TITLE") or env.get("LEGATTO_SLUG") or "Legatto",
                   tz=env.get("LEGATTO_TZ") or contract.TIMEZONE)


class App:
    def __init__(self, config: Config, clock: Callable[[], float] = time.time):
        self.config = config
        self.clock = clock
        self.sessions = Sessions(clock)
        self.throttle = Throttle(clock)
        self.get_routes: dict[str, Callable[[Request, Session], Response]] = {
            "/": self.page_status,
            "/wydania": self.page_releases,
            "/dostep": self.page_access,
            "/funkcje": self.page_features,
            "/urzadzenia": self.page_devices,
            "/odzyskiwanie": self.page_recovery,
            "/kontakty": self.page_contacts,
            "/konta": self.page_accounts,
            "/haslo": self.page_password,
        }
        self.actions: dict[str, tuple[Callable[[dict, Session], tuple[str, dict, dict]], str]] = {
            "/wydania/autosecurity": (self.act_autosecurity, "wydania"),
            "/wydania/zatwierdz": (self.act_approve, "wydania"),
            "/wydania/odrzuc": (self.act_reject, "wydania"),
            "/wydania/wycofaj": (self.act_rollback, "wydania"),
            "/dostep/otworz": (self.act_bg_enable, "dostep"),
            "/dostep/zamknij": (self.act_bg_disable, "dostep"),
            "/funkcje": (self.act_feature, "funkcje"),
            "/urzadzenia/dodaj": (self.act_enroll, "urzadzenia"),
            "/urzadzenia/usun": (self.act_revoke, "urzadzenia"),
            "/urzadzenia/personel": (self.act_staff, "urzadzenia"),
            "/odzyskiwanie": (self.act_recovery, "odzyskiwanie"),
            "/kontakty": (self.act_contacts, "kontakty"),
            "/konta/dodaj": (self.act_user_add, "konta"),
            "/konta/usun": (self.act_user_remove, "konta"),
            "/konta/reset-totp": (self.act_user_reset_totp, "konta"),
            "/konta/haslo-tymczasowe": (self.act_user_temp_password, "konta"),
            "/haslo": (self.act_password, "haslo"),
        }

    # --- entry point ---------------------------------------------------------------------------------
    def handle(self, req: Request) -> Response:
        try:
            response = self._handle(req)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the browser
            log(f"internal error on {req.method} {req.path.split('?')[0][:80]}: {type(exc).__name__}: {exc}")
            response = Response(500, self.view().error("Błąd", "Błąd wewnętrzny panelu.").encode())
        response.headers.extend(SECURITY_HEADERS)
        return response

    def _handle(self, req: Request) -> Response:
        host = req.headers.get("host", "").split(":")[0].lower()
        forwarded_host = req.headers.get("x-forwarded-host", host).split(":")[0].lower()
        if host != self.config.host or forwarded_host != self.config.host:
            return Response(421, b"Misdirected request", "text/plain; charset=utf-8")
        if self.config.require_surface and req.headers.get("x-legatto-surface") != "admin":
            return Response(403, b"Forbidden", "text/plain; charset=utf-8")
        forwarded = req.headers.get("x-forwarded-for", "")
        try:
            req.ip = validate.tailnet_ip(forwarded.split(",")[-1].strip())
        except Invalid:
            return Response(403, "Panel jest dostępny tylko z urządzeń w tailnecie.".encode(),
                            "text/plain; charset=utf-8")
        path = urllib.parse.urlsplit(req.path).path
        if path == BASE:
            return Response.redirect(BASE + "/", 308)
        if not path.startswith(BASE + "/"):
            return Response(404, b"Not found", "text/plain; charset=utf-8")
        route = path[len(BASE):]
        if req.method in ("GET", "HEAD"):
            return self.get(req, route)
        if req.method == "POST":
            return self.post(req, route)
        return Response(405, b"Method not allowed", "text/plain; charset=utf-8", [("Allow", "GET, HEAD, POST")])

    def view(self, session: Session | None = None) -> pages.View:
        flash = []
        if session is not None:
            flash, session.flash = session.flash, []
        return pages.View(self.config.tz, self.config.title, session.login if session else None,
                          session.display_name if session else None, session.csrf if session else None, flash)

    def html(self, body: str, status: int = 200, headers: list | None = None) -> Response:
        return Response(status, body.encode("utf-8"), headers=headers or [])

    def session(self, req: Request) -> Session | None:
        session = self.sessions.get(req.cookies.get(SESSION_COOKIE), req.ip)
        if session is None:
            return None
        user = store.load_users().get(session.login)
        if not isinstance(user, dict) or not user.get("enabled"):
            self.sessions.destroy_user(session.login)  # account removed or disabled meanwhile
            return None
        return session

    # --- GET -------------------------------------------------------------------------------------------
    def get(self, req: Request, route: str) -> Response:
        if route == "/static/app.css":
            return Response(200, pages.CSS.encode(), "text/css; charset=utf-8",
                            [("Cache-Control", "no-store")])
        if route == "/logowanie":
            return self.page_login(req)
        if route == "/konfiguracja":
            return self.page_setup(req)
        session = self.session(req)
        if session is None:
            return Response.redirect(BASE + "/logowanie")
        match = re.fullmatch(r"/zadania/([0-9A-Z]{26})", route)
        if match:
            return self.page_result(session, match.group(1))
        match = re.fullmatch(r"/zadania/([0-9A-Z]{26})/plik/(file|card)", route)
        if match:
            return self.download(session, match.group(1), match.group(2))
        if session.must_change and route != "/haslo":
            return Response.redirect(BASE + "/haslo")
        match = re.fullmatch(r"/dostep/okno/([A-Za-z0-9._-]{1,64})", route)
        if match:
            summary = data.breakglass_summary(match.group(1))
            if summary is None:
                return self.html(self.view(session).error("Nie znaleziono", "Nie ma takiego okna."), 404)
            return self.html(self.view(session).access_window(summary))
        handler = self.get_routes.get(route)
        if handler is None:
            return self.html(self.view(session).error("Nie znaleziono", "Nie ma takiej strony."), 404)
        return handler(req, session)

    def page_login(self, req: Request, error: str | None = None, login_value: str = "",
                   status: int = 200) -> Response:
        if error is None and self.session(req) is not None:
            return Response.redirect(BASE + "/")
        pre = req.cookies.get(PRE_COOKIE)
        headers = []
        if not pre or not re.fullmatch(r"[A-Za-z0-9_-]{43}", pre):
            pre = secrets.token_urlsafe(32)
            headers.append(("Set-Cookie", f"{PRE_COOKIE}={pre}; Path=/; Secure; HttpOnly; SameSite=Strict"))
        view = self.view()
        if error:
            view.flash.append(("error", error))
        setup_available = not store.regular_active_users(store.load_users())
        return self.html(view.login(pre, login_value, setup_available), status, headers)

    def page_setup(self, req: Request, error: str | None = None, status: int = 200) -> Response:
        if store.regular_active_users(store.load_users()):
            return Response.redirect(BASE + "/logowanie")
        pre = req.cookies.get(PRE_COOKIE)
        headers = []
        if not pre or not re.fullmatch(r"[A-Za-z0-9_-]{43}", pre):
            pre = secrets.token_urlsafe(32)
            headers.append(("Set-Cookie", f"{PRE_COOKIE}={pre}; Path=/; Secure; HttpOnly; SameSite=Strict"))
        view = self.view()
        if error:
            view.flash.append(("error", error))
        return self.html(view.setup(pre), status, headers)

    def page_status(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).status(data.all_status(), self.clock()))

    def pending_items(self) -> tuple[dict | None, list[dict]]:
        update = data.status("update")
        items = []
        for entry in (update or {}).get("pending") or []:
            if isinstance(entry, dict):
                item = dict(entry)
                item["_detail"] = data.pending_release(entry.get("version")) or {}
                items.append(item)
        return update, items

    def page_releases(self, req: Request, session: Session) -> Response:
        update, items = self.pending_items()
        return self.html(self.view(session).releases(update, items, data.audit_tail(("update",), 40)))

    def page_access(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).access(data.status("breakglass"), data.breakglass_summaries(),
                                                   data.audit_tail(("breakglass",), 40)))

    def page_features(self, req: Request, session: Session) -> Response:
        _, items = self.pending_items()
        widening = [i for i in items if i.get("egress_widening") or (i["_detail"].get("egress") or {}).get("widening")]
        return self.html(self.view(session).features(data.features(), data.status("egress"), widening))

    def page_devices(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).devices(data.snapshot()))

    def page_recovery(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).recovery())

    def page_contacts(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).contacts(data.contacts()))

    def page_accounts(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).accounts(store.load_users()))

    def page_password(self, req: Request, session: Session) -> Response:
        return self.html(self.view(session).password(session.must_change))

    def page_result(self, session: Session, rid: str) -> Response:
        owned = session.requests.get(rid)
        if owned is None:
            return self.html(self.view(session).expired_result(rid), 404)
        result = data.result(rid)
        if result is None:
            if self.clock() - owned[1] < OWNED_REQUEST_TTL:
                return self.html(self.view(session).pending_result(rid, owned[0]))
            return self.html(self.view(session).expired_result(rid), 404)
        self.apply_result(session, result)
        extra = session.secrets.get(rid) if result.get("status") == "ok" else None
        back = "haslo" if session.must_change else self.back_for(owned[0])
        return self.html(self.view(session).result(result, extra, back))

    @staticmethod
    def back_for(rtype: str) -> str:
        return {"breakglass": "dostep", "update": "wydania", "device": "urzadzenia",
                "staff": "urzadzenia", "features": "funkcje", "recovery": "odzyskiwanie", "contacts": "kontakty",
                "console": "konta"}.get(rtype.split(".")[0], "")

    def apply_result(self, session: Session, result: dict) -> None:
        """Session side effects of finished requests (password change clears the must-change flag)."""
        rid = result.get("id")
        if result.get("type") == "console.user.password" and result.get("status") == "ok" \
                and isinstance(rid, str) and session.secrets.get(rid, {}).get("_self"):
            session.must_change = False

    def download(self, session: Session, rid: str, which: str) -> Response:
        result = data.result(rid)
        if rid not in session.requests or result is None or result.get("type") != "recovery.generate" \
                or result.get("status") != "ok" or not isinstance(result.get("data"), dict):
            return self.html(self.view(session).expired_result(rid), 404)
        name = result["data"].get(which)
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name):
            return self.html(self.view(session).expired_result(rid), 404)
        location = os.path.join(contract.path(contract.RECOVERY_DIR), name)
        try:
            fd = os.open(location, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return self.html(self.view(session).expired_result(rid), 404)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return self.html(self.view(session).expired_result(rid), 404)
            content = handle.read(256 * 1024 * 1024)
        return Response(200, content, "application/octet-stream",
                        [("Content-Disposition", f'attachment; filename="{name}"')])

    # --- POST ------------------------------------------------------------------------------------------------
    def same_origin(self, req: Request) -> bool:
        origin = req.headers.get("origin")
        if origin is not None and origin != f"https://{self.config.host}":
            return False
        fetch_site = req.headers.get("sec-fetch-site")
        return fetch_site in (None, "same-origin")

    def post(self, req: Request, route: str) -> Response:
        if not self.same_origin(req):
            return self.html(self.view().error("Odmowa", "Żądanie spoza panelu (Origin)."), 403)
        try:
            form = req.form()
        except Invalid as exc:
            return self.html(self.view().error("Odmowa", str(exc)), 400)
        if route == "/logowanie":
            return self.login(req, form)
        if route == "/konfiguracja":
            return self.setup(req, form)
        session = self.session(req)
        if session is None:
            return Response.redirect(BASE + "/logowanie")
        if not hmac.compare_digest(form.get("csrf", "").encode(), session.csrf.encode()):
            return self.html(self.view(session).error("Odmowa", "Nieprawidłowy token formularza (CSRF). Odśwież "
                                                                "stronę i spróbuj ponownie."), 403)
        if route == "/wyloguj":
            self.sessions.destroy(req.cookies.get(SESSION_COOKIE))
            return Response(303, b"", "text/plain; charset=utf-8",
                            [("Location", BASE + "/logowanie"),
                             ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")])
        action = self.actions.get(route)
        if action is None:
            return self.html(self.view(session).error("Nie znaleziono", "Nie ma takiej operacji."), 404)
        if session.must_change and route != "/haslo":
            return Response.redirect(BASE + "/haslo")
        builder, back = action
        try:
            totp = form.get("totp", "").strip()
            if not validate.TOTP_RE.fullmatch(totp):
                raise Invalid("bad_totp", "Podaj 6-cyfrowy kod TOTP.")
            rtype, params, extra = builder(form, session)
            params = validate.params_for(rtype, params)
            rid = self.submit(rtype, params, session.login, req.ip, {"method": "local-totp", "totp": totp})
        except Invalid as exc:
            session.flash.append(("error", str(exc)))
            return Response.redirect(f"{BASE}/{back}")
        session.requests[rid] = (rtype, self.clock())
        if extra:
            session.secrets[rid] = extra
        self.prune_session(session)
        result = self.wait_result(rid, self.config.submit_wait)
        if result is not None:
            self.apply_result(session, result)
        return Response.redirect(f"{BASE}/zadania/{rid}")

    @staticmethod
    def prune_session(session: Session) -> None:
        now = time.time()
        for rid in [r for r, (_, ts) in session.requests.items() if now - ts > OWNED_REQUEST_TTL]:
            session.requests.pop(rid, None)
            session.secrets.pop(rid, None)

    # --- spool ------------------------------------------------------------------------------------------------
    def submit(self, rtype: str, params: dict, user: str, ip: str, auth: dict) -> str:
        rid = crypto.new_ulid(self.clock())
        request = {"v": contract.REQUEST_VERSION, "id": rid, "type": rtype, "ts": validate.format_utc(self.clock()),
                   "actor": {"user": user, "ip": ip}, "auth": auth, "params": params}
        raw = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > contract.REQUEST_MAX_BYTES:
            raise Invalid("too_large", "Dane formularza są zbyt duże.")
        incoming = contract.path(contract.REQUESTS_INCOMING)
        tmp = os.path.join(incoming, rid + ".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, os.path.join(incoming, rid + ".json"))
        return rid

    def wait_result(self, rid: str, timeout: float) -> dict | None:
        deadline = time.monotonic() + timeout
        while True:
            result = data.result(rid)
            if result is not None or time.monotonic() >= deadline:
                return result
            time.sleep(0.15)

    # --- login, setup, logout ----------------------------------------------------------------------------------
    def login(self, req: Request, form: dict) -> Response:
        pre = req.cookies.get(PRE_COOKIE, "")
        if not pre or not hmac.compare_digest(form.get("csrf", "").encode(), pre.encode()):
            return self.page_login(req, "Sesja formularza wygasła. Spróbuj ponownie.", status=403)
        login = form.get("login", "").strip().lower()
        password = form.get("password", "")
        totp = form.get("totp", "").strip()
        generic = "Nieprawidłowy login, hasło lub kod TOTP."
        if self.throttle.blocked("login:" + login, "ip:" + req.ip):
            return self.page_login(req, "Zbyt wiele nieudanych prób. Odczekaj 15 minut.", login, 429)
        user = store.load_users().get(login) if validate.LOGIN_RE.fullmatch(login) else None
        stored = user.get("password") if isinstance(user, dict) and user.get("enabled") else None
        password_ok = crypto.scrypt_verify(password[:PASSWORD_MAX], stored if isinstance(stored, str)
                                           else crypto.dummy_hash())
        if not (password_ok and isinstance(stored, str)) or not validate.TOTP_RE.fullmatch(totp):
            self.throttle.fail("login:" + login, "ip:" + req.ip)
            log(f"login failed (password) from {req.ip}")
            return self.page_login(req, generic, login, 401)
        rid = self.submit("console.login", {}, login, req.ip, {"method": "local-totp", "totp": totp})
        result = self.wait_result(rid, self.config.submit_wait)
        if result is None:
            return self.page_login(req, "Serwer nie potwierdził kodu TOTP w czasie. Spróbuj ponownie za chwilę.",
                                   login, 503)
        if result.get("status") != "ok":
            self.throttle.fail("login:" + login, "ip:" + req.ip)
            message = result.get("message") if result.get("code") in ("totp_replay", "totp_locked") else generic
            return self.page_login(req, str(message), login, 401)
        result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
        must_change = bool(result_data.get("must_change", user.get("must_change")))
        token, _ = self.sessions.create(login, str(result_data.get("display_name") or user.get("display_name") or login),
                                        req.ip, must_change)
        log(f"login {login} from {req.ip}")
        return Response(303, b"", "text/plain; charset=utf-8",
                        [("Location", BASE + ("/haslo" if must_change else "/")),
                         ("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict"),
                         ("Set-Cookie", f"{PRE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")])

    def setup(self, req: Request, form: dict) -> Response:
        pre = req.cookies.get(PRE_COOKIE, "")
        if not pre or not hmac.compare_digest(form.get("csrf", "").encode(), pre.encode()):
            return self.page_setup(req, "Sesja formularza wygasła. Spróbuj ponownie.", 403)
        if self.throttle.blocked("setup:" + req.ip):
            return self.page_setup(req, "Zbyt wiele nieudanych prób. Odczekaj 15 minut.", 429)
        try:
            login = validate.console_login(form.get("login", "").strip().lower())
            display_name = validate.plain_text(" ".join(form.get("display_name", "").split()), "display_name", 2,
                                               validate.DISPLAY_NAME_MAX)
            code = crypto.normalize_setup_code(form.get("code", ""))
            if not validate.SETUP_CODE_RE.fullmatch(code):
                raise Invalid("bad_setup_code", "Kod konfiguracji ma postać XXXX-XXXX-XXXX-XXXX.")
            self.check_new_password(form.get("password", ""), form.get("password2", ""), login)
            params = validate.params_for("console.setup", {"login": login, "display_name": display_name,
                                                           "scrypt": crypto.scrypt_hash(form["password"])})
        except Invalid as exc:
            return self.page_setup(req, str(exc), 400)
        rid = self.submit("console.setup", params, login, req.ip, {"method": "setup-code", "code": code})
        result = self.wait_result(rid, self.config.setup_wait)
        if result is None:
            return self.page_setup(req, "Serwer nie odpowiedział. Jeśli konto powstało, poproś dostawcę o reset "
                                        "TOTP; w przeciwnym razie spróbuj ponownie.", 503)
        if result.get("status") != "ok":
            self.throttle.fail("setup:" + req.ip)
        return self.html(self.view().result(result, None, "logowanie"), 200 if result.get("status") == "ok" else 400)

    def check_new_password(self, new: str, repeat: str, login: str) -> None:
        if new != repeat:
            raise Invalid("password_mismatch", "Hasła nie są takie same.")
        if not PASSWORD_MIN <= len(new) <= PASSWORD_MAX:
            raise Invalid("weak_password", f"Hasło musi mieć od {PASSWORD_MIN} do {PASSWORD_MAX} znaków.")
        if new.strip().lower() == login or len(set(new)) < 5:
            raise Invalid("weak_password", "Hasło jest zbyt proste.")

    # --- action builders: (form, session) -> (type, params, extra shown once) -------------------------------------
    @staticmethod
    def _int(value: str, field_name: str) -> int:
        if not re.fullmatch(r"[0-9]{1,3}", value or ""):
            raise Invalid("bad_params", f"Pole {field_name} musi być liczbą.")
        return int(value)

    @staticmethod
    def _text(value: str) -> str:
        return " ".join((value or "").split())

    @staticmethod
    def _lines(value: str) -> list[str]:
        return [line.strip().lower() for line in (value or "").splitlines() if line.strip()]

    @staticmethod
    def _bool(value: str) -> bool:
        if value not in ("true", "false"):
            raise Invalid("bad_params", "Niepoprawna wartość przełącznika.")
        return value == "true"

    def act_autosecurity(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "update.autosecurity", {"enabled": self._bool(form.get("enabled", ""))}, {}

    def act_approve(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        params: dict[str, Any] = {"release": form.get("release", ""), "manifest_sha256": form.get("manifest_sha256", "")}
        not_before = form.get("not_before", "").strip()
        if not_before:
            params["not_before"] = self.local_to_utc(not_before)
        if "install_now" in form:
            params["install_now"] = self._bool(form["install_now"])
        return "update.approve", params, {}

    def local_to_utc(self, value: str) -> str:
        try:
            moment = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M")
            from zoneinfo import ZoneInfo

            local = moment.replace(tzinfo=ZoneInfo(self.config.tz))
        except Exception as exc:  # noqa: BLE001
            raise Invalid("bad_params", "Niepoprawna data „nie wcześniej niż”.") from exc
        return local.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def act_reject(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "update.reject", {"release": form.get("release", ""), "manifest_sha256": form.get("manifest_sha256", ""),
                                 "reason": self._text(form.get("reason", ""))}, {}

    def act_rollback(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        target = form.get("to", "").strip()
        return "update.rollback", ({"to": target} if target else {}), {}

    def act_bg_enable(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "breakglass.enable", {"hours": self._int(form.get("hours", ""), "hours"),
                                     "reason": self._text(form.get("reason", ""))}, {}

    def act_bg_disable(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "breakglass.disable", {"reason": self._text(form.get("reason", ""))}, {}

    def act_feature(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        params: dict[str, Any] = {"feature": form.get("feature", ""), "enabled": self._bool(form.get("enabled", ""))}
        if params["feature"] == "ics" and "ics_hosts" in form:
            params["ics_hosts"] = self._lines(form["ics_hosts"])
        return "features.set", params, {}

    def act_enroll(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        kind = form.get("kind", "")
        params: dict[str, Any] = {"kind": kind}
        if kind == "staff":
            if not form.get("login"):
                raise Invalid("bad_params", "Wybierz pracownika z listy personelu.")
            params["login"] = form["login"]
        return "device.enroll", params, {}

    def act_revoke(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "device.revoke", {"node_id": form.get("node_id", "")}, {}

    def act_staff(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        staff = self._lines(form.get("staff", ""))
        return "staff.set", {"staff": sorted(set(staff))}, {}

    def act_recovery(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "recovery.generate", {}, {}

    def act_contacts(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        params: dict[str, Any] = {"notes": self._text(form.get("notes", ""))}
        for key in ("primary", "secondary", "iod"):
            person = {f: self._text(form.get(f"{key}_{f}", "")) for f in ("name", "email", "phone")}
            if key == "primary" or any(person.values()):
                params[key] = person
        return "contacts.set", params, {}

    def act_user_add(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "console.user.add", {"login": form.get("login", "").strip().lower(),
                                    "display_name": self._text(form.get("display_name", ""))}, {}

    def act_user_remove(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "console.user.remove", {"login": form.get("login", "")}, {}

    def act_user_reset_totp(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        return "console.user.reset_totp", {"login": form.get("login", "")}, {}

    def act_user_temp_password(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        login = validate.console_login(form.get("login", ""))
        if login == session.login:
            raise Invalid("bad_params", "Własne hasło zmieniasz na stronie „Zmień własne hasło”.")
        temporary = crypto.new_password()
        return "console.user.password", {"login": login, "scrypt": crypto.scrypt_hash(temporary)}, \
            {"temporary_password": temporary}

    def act_password(self, form: dict, session: Session) -> tuple[str, dict, dict]:
        user = store.load_users().get(session.login) or {}
        stored = user.get("password") if isinstance(user.get("password"), str) else crypto.dummy_hash()
        if not crypto.scrypt_verify(form.get("current", "")[:PASSWORD_MAX], stored):
            raise Invalid("bad_password", "Obecne hasło jest nieprawidłowe.")
        new = form.get("new", "")
        self.check_new_password(new, form.get("new2", ""), session.login)
        if new == form.get("current", ""):
            raise Invalid("weak_password", "Nowe hasło musi różnić się od obecnego.")
        return "console.user.password", {"login": session.login, "scrypt": crypto.scrypt_hash(new)}, {"_self": True}


# --- server -------------------------------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "legatto-console"
    sys_version = ""
    timeout = 30
    app: App

    def address_string(self) -> str:
        return "caddy"

    def log_message(self, fmt: str, *args: Any) -> None:  # requests are logged in _serve without query strings
        pass

    def _serve(self) -> None:
        slots: threading.BoundedSemaphore = self.server.slots  # type: ignore[attr-defined]
        if not slots.acquire(blocking=False):
            self.send_error(503)
            return
        try:
            length = self.headers.get("Content-Length")
            body = b""
            if length:
                if not re.fullmatch(r"[0-9]{1,7}", length) or int(length) > MAX_BODY:
                    self.send_error(413)
                    return
                body = self.rfile.read(int(length))
            headers = {k.lower(): v for k, v in self.headers.items()}
            response = self.app.handle(Request(self.command, self.path, headers, body))
            self.send_response(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            for key, value in response.headers:
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)
            if response.status >= 400:
                log(f"{self.command} {self.path.split('?')[0][:80]} -> {response.status}")
        finally:
            slots.release()

    do_GET = do_HEAD = do_POST = _serve

    def do_PUT(self) -> None:  # noqa: N802
        self.send_error(405)

    do_DELETE = do_PATCH = do_OPTIONS = do_PUT


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address: str | None, app: App, fd: int | None = None):
        handler = type("BoundHandler", (Handler,), {"app": app})
        self.slots = threading.BoundedSemaphore(32)
        if fd is None:
            assert address is not None
            if os.path.exists(address) and stat.S_ISSOCK(os.lstat(address).st_mode):
                os.unlink(address)
            super().__init__(address, handler)
            os.chmod(address, 0o660)
        else:
            super().__init__("", handler, bind_and_activate=False)
            self.socket.close()
            self.socket = socket.socket(fileno=fd)
            if self.socket.family != socket.AF_UNIX:
                raise SystemExit("office-console: the activation socket must be AF_UNIX")


def activation_fd() -> int | None:
    """File descriptor passed by legatto-console.socket (sd_listen_fds protocol)."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if os.environ.get("LISTEN_FDS") != "1":
        raise SystemExit("office-console: expected exactly one activation socket")
    for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(key, None)
    return 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="legatto-console", description="Office admin panel (admin.app/console/).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="serve on the systemd activation socket (or --listen)")
    serve.add_argument("--listen", default=None, help="unix socket path when not socket-activated")
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        fd = activation_fd()
        if fd is None and not args.listen:
            raise SystemExit("office-console: no activation socket; use legatto-console.socket or --listen")
        app = App(Config.from_office_env())
        server = Server(args.listen, app, fd)
        log("serving" + (f" on {args.listen}" if args.listen else " on the activation socket"))
        try:
            server.serve_forever(poll_interval=1.0)
        except KeyboardInterrupt:
            pass
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
