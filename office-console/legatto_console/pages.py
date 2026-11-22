"""HTML of the office console (Polish UI, no JavaScript, everything escaped)."""

from __future__ import annotations

import html
from typing import Any, Iterable

from . import contract, qr, validate

BASE = "/console"


def h(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


NAV = (
    ("", "Status"),
    ("wydania", "Wydania"),
    ("dostep", "Dostęp serwisowy"),
    ("funkcje", "Funkcje"),
    ("urzadzenia", "Urządzenia"),
    ("studio", "Studio"),
    ("odzyskiwanie", "Pakiet odzyskiwania"),
    ("kontakty", "Kontakty incydentów"),
    ("konta", "Konta panelu"),
)

CSS = """
:root{--fg:#1d2330;--muted:#5b6472;--line:#d8dce3;--bg:#f6f7f9;--ok:#1f7a3d;--warn:#9a6a00;--bad:#b3261e;--acc:#234e9e}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg)}
header{background:#fff;border-bottom:1px solid var(--line);padding:.6rem 1.2rem;display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;align-items:center}
header .brand{font-weight:700;margin-right:1rem}header nav{display:flex;flex-wrap:wrap;gap:.2rem .9rem;flex:1}
header nav a{color:var(--fg);text-decoration:none;padding:.15rem 0;border-bottom:2px solid transparent}
header nav a.active{border-color:var(--acc);color:var(--acc)}header .user{color:var(--muted);font-size:.9rem}
main{max-width:1100px;margin:0 auto;padding:1.2rem}h1{font-size:1.45rem;margin:.2rem 0 1rem}h2{font-size:1.15rem;margin:1.6rem 0 .6rem}
.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:1rem 1.2rem;margin:0 0 1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:1rem}.grid .card{margin:0}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.muted{color:var(--muted)}
.badge{display:inline-block;padding:.05rem .5rem;border-radius:99px;font-size:.82rem;font-weight:600;border:1px solid currentColor}
table{width:100%;border-collapse:collapse;background:#fff}th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.85rem;color:var(--muted);font-weight:600}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;word-break:break-all}
form.inline{display:inline}label{display:block;margin:.5rem 0 .2rem;font-weight:600}
input[type=text],input[type=password],input[type=email],input[type=tel],input[type=number],input[type=datetime-local],select,textarea{width:100%;max-width:32rem;padding:.4rem .5rem;border:1px solid #b9c0cb;border-radius:6px;font:inherit}
input.totp{max-width:8rem;letter-spacing:.2em}textarea{min-height:5rem}
button{font:inherit;padding:.45rem .9rem;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;cursor:pointer;margin-top:.6rem}
button.secondary{background:#fff;color:var(--acc)}button.danger{background:var(--bad);border-color:var(--bad)}
.flash{padding:.7rem 1rem;border-radius:6px;margin:0 0 1rem;border:1px solid}.flash.error{color:var(--bad);background:#fdecea}
.flash.info{color:var(--acc);background:#eef3fc}.flash.ok{color:var(--ok);background:#e9f6ee}
.secret{font-family:ui-monospace,Menlo,monospace;font-size:1.25rem;background:#fffbe6;border:1px dashed var(--warn);padding:.6rem .8rem;border-radius:6px;word-break:break-all}
.qr{display:inline-block;margin:.5rem 1.5rem .5rem 0;text-align:center}.qr svg{max-width:100%;height:auto}
pre{white-space:pre-wrap;background:#fbfbfc;border:1px solid var(--line);padding:.8rem;border-radius:6px;max-height:30rem;overflow:auto}
.hint{color:var(--muted);font-size:.9rem}dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:0}dl.kv dt{color:var(--muted)}dl.kv dd{margin:0}
"""

FEATURE_INFO = {
    "ai": ("Asystent AI", "Treść zapytań trafia do zewnętrznego dostawcy modelu AI (możliwy transfer poza UE). "
                          "Włączaj tylko po decyzji administratora danych."),
    "mcp": ("Serwer MCP", "Narzędzia AI na urządzeniach biura (Claude Code, Cursor, VS Code) łączą się z CRM w tailnecie. "
                          "Działa tylko przy włączonym asystencie AI."),
    "email": ("Powiadomienia e-mail", "Wysyłka e-maili z domeny biura przez dostawcę poczty."),
    "getresponse": ("GetResponse", "Synchronizacja odbiorców newslettera z kontem GetResponse."),
    "push": ("Powiadomienia push", "Powiadomienia w przeglądarce przez usługi push producentów przeglądarek."),
    "ics": ("Kalendarze ICS", "Pobieranie zewnętrznych kalendarzy wyłącznie z hostów podanych niżej."),
    "hibp": ("Sprawdzanie haseł (HIBP)", "Sprawdza, czy hasło konta CRM wyciekło; wysyłany jest tylko fragment skrótu."),
}

PENDING_STATE = {
    "waiting-promotion": ("czeka na promocję kanału", "muted"),
    "waiting-delay": ("czeka (minimalne opóźnienie bezpieczeństwa)", "muted"),
    "waiting-approval": ("czeka na Twoją decyzję", "warn"),
    "waiting-window": ("zatwierdzone — czeka na okno instalacji", "ok"),
    "blocked-baseline": ("zablokowane — wymaga prac serwisowych", "bad"),
    "ready": ("gotowe do instalacji", "ok"),
    "rejected": ("odrzucone", "bad"),
    "expired": ("wygasło", "muted"),
}
UPD_STATE = {
    "ok": ("aktualne", "ok"), "pending": ("oczekuje wydanie", "warn"), "waiting": ("czeka na bramkę", "warn"),
    "installing": ("trwa instalacja", "warn"), "failed": ("instalacja nieudana", "bad"),
    "rb": ("wycofano wydanie", "bad"), "rej": ("wydanie odrzucone przez weryfikację", "bad"),
    "vuln": ("działa wersja ze znaną podatnością", "bad"), "stale": ("brak świeżego indeksu wydań", "bad"),
    "blocked-baseline": ("zablokowane — wymaga prac serwisowych", "bad"),
    "optout": ("automatyczne poprawki wyłączone", "warn"),
}
SIG_STATE = {"ok": ("podpis poprawny", "ok"), "bad": ("PODPIS NIEPOPRAWNY", "bad"), "none": ("brak podpisu", "warn")}
REQUEST_LABELS = {
    "breakglass.enable": "Otwarcie dostępu serwisowego", "breakglass.disable": "Zamknięcie dostępu serwisowego",
    "update.approve": "Zatwierdzenie wydania", "update.reject": "Odrzucenie wydania",
    "update.rollback": "Wycofanie wydania", "update.autosecurity": "Automatyczne poprawki bezpieczeństwa",
    "studio.enable": "Włączenie Studio", "studio.disable": "Wyłączenie Studio",
    "device.enroll": "Rejestracja urządzenia", "device.revoke": "Usunięcie urządzenia",
    "staff.set": "Lista personelu", "features.set": "Zmiana funkcji", "recovery.generate": "Pakiet odzyskiwania",
    "console.user.add": "Nowe konto panelu", "console.user.remove": "Usunięcie konta panelu",
    "console.user.reset_totp": "Nowy kod TOTP", "console.user.password": "Zmiana hasła",
    "console.login": "Logowanie", "contacts.set": "Kontakty incydentów", "console.setup": "Pierwsze konto panelu",
}


class View:
    """Per-request rendering context."""

    def __init__(self, tz: str, title: str, user: str | None = None, display_name: str | None = None,
                 csrf: str | None = None, flash: Iterable[tuple[str, str]] = ()):
        self.tz = tz
        self.title = title
        self.user = user
        self.display_name = display_name
        self.csrf = csrf
        self.flash = list(flash)
        self._seq = 0

    def uid(self, base: str) -> str:
        """Element id unique within the page (several forms share field names)."""
        self._seq += 1
        return f"{base}-{self._seq}"

    # --- helpers ------------------------------------------------------------------------------
    def t(self, utc_value: Any, seconds: bool = False) -> str:
        return h(validate.local_display(utc_value, self.tz, seconds))

    def page(self, title: str, body: str, active: str | None = None) -> str:
        nav = ""
        if self.user:
            links = "".join(
                f'<a href="{BASE}/{slug}" class="{"active" if slug == active else ""}">{h(label)}</a>'
                for slug, label in NAV)
            nav = (f"<nav>{links}</nav><span class=\"user\">{h(self.display_name or self.user)} "
                   f"({h(self.user)})</span>"
                   f'<form class="inline" method="post" action="{BASE}/wyloguj">{self.csrf_field()}'
                   f'<button class="secondary" type="submit">Wyloguj</button></form>')
        flashes = "".join(f'<div class="flash {h(kind)}">{h(text)}</div>' for kind, text in self.flash)
        return ("<!doctype html><html lang=\"pl\"><head><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                f"<title>{h(title)} — {h(self.title)}</title>"
                f'<link rel="stylesheet" href="{BASE}/static/app.css"></head><body>'
                f'<header><span class="brand">Panel biura · {h(self.title)}</span>{nav}</header>'
                f"<main>{flashes}<h1>{h(title)}</h1>{body}</main></body></html>")

    def csrf_field(self) -> str:
        return f'<input type="hidden" name="csrf" value="{h(self.csrf)}">' if self.csrf else ""

    def form(self, action: str, inner: str, button: str, *, totp: bool = True, style: str = "",
             inline: bool = False) -> str:
        code = ('<label for="{a}">Kod z aplikacji uwierzytelniającej (TOTP)</label>'
                '<input class="totp" id="{a}" name="totp" type="text" inputmode="numeric" pattern="[0-9]{{6}}" '
                'maxlength="6" autocomplete="one-time-code" required>').format(a=self.uid("totp"))
        cls = f' class="{style}"' if style else ""
        form_cls = ' class="inline"' if inline else ""
        return (f'<form method="post" action="{BASE}/{action}"{form_cls}>'
                f'{self.csrf_field()}{inner}{code if totp else ""}'
                f'<button type="submit"{cls}>{h(button)}</button></form>')

    @staticmethod
    def badge(text: str, cls: str) -> str:
        return f'<span class="badge {h(cls)}">{h(text)}</span>'

    @staticmethod
    def qr_block(data: str, caption: str) -> str:
        try:
            svg = qr.svg(data, "M", title=caption)
        except qr.DataTooLong:
            return f"<p class=\"bad\">Dane zbyt długie na kod QR: {h(caption)}</p>"
        return f'<figure class="qr">{svg}<figcaption>{h(caption)}</figcaption></figure>'

    # --- login and setup ------------------------------------------------------------------------------
    def login(self, pre_csrf: str, login_value: str = "", setup_available: bool = False) -> str:
        setup = (f'<p class="hint">Panel nie ma jeszcze konta administratora. '
                 f'<a href="{BASE}/konfiguracja">Załóż pierwsze konto</a> kodem jednorazowym od dostawcy.</p>'
                 if setup_available else "")
        body = (f'<div class="card"><form method="post" action="{BASE}/logowanie">'
                f'<input type="hidden" name="csrf" value="{h(pre_csrf)}">'
                f'<label for="login">Login</label><input id="login" name="login" type="text" autocomplete="username" '
                f'value="{h(login_value)}" required maxlength="41">'
                '<label for="password">Hasło</label><input id="password" name="password" type="password" '
                'autocomplete="current-password" required maxlength="256">'
                '<label for="totp">Kod TOTP</label><input class="totp" id="totp" name="totp" type="text" '
                'inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>'
                '<button type="submit">Zaloguj</button></form>'
                '<p class="hint">Każda operacja w panelu wymaga nowego kodu TOTP. Kod użyty raz nie zadziała '
                'ponownie — po zalogowaniu poczekaj na następny (do 30 s).</p></div>' + setup)
        return self.page("Logowanie", body)

    def setup(self, pre_csrf: str) -> str:
        body = (
            '<div class="card"><p>Pierwsze konto administratora zakładasz kodem jednorazowym, który podaje dostawca '
            'przy instalacji (ważny 24 godziny). Strona działa tylko z urządzenia biura. Hasło wybierasz sam — '
            'dostawca go nie zna.</p>'
            f'<form method="post" action="{BASE}/konfiguracja"><input type="hidden" name="csrf" value="{h(pre_csrf)}">'
            '<label for="code">Kod konfiguracji</label><input id="code" name="code" type="text" required '
            'maxlength="24" autocomplete="off" placeholder="XXXX-XXXX-XXXX-XXXX">'
            '<label for="login">Login (małe litery, np. jan.kowalski)</label>'
            '<input id="login" name="login" type="text" required maxlength="41" autocomplete="username">'
            '<label for="display_name">Imię i nazwisko</label>'
            '<input id="display_name" name="display_name" type="text" required maxlength="80">'
            '<label for="password">Hasło (co najmniej 12 znaków)</label>'
            '<input id="password" name="password" type="password" required minlength="12" maxlength="256" '
            'autocomplete="new-password">'
            '<label for="password2">Powtórz hasło</label>'
            '<input id="password2" name="password2" type="password" required minlength="12" maxlength="256" '
            'autocomplete="new-password">'
            '<button type="submit">Załóż konto</button></form></div>')
        return self.page("Pierwsze konto panelu", body)

    def password(self, forced: bool) -> str:
        intro = ("<div class=\"flash info\">Hasło ustawił inny administrator. Ustaw własne hasło, aby korzystać "
                 "z panelu.</div>" if forced else "")
        inner = ('<label for="current">Obecne hasło</label><input id="current" name="current" type="password" '
                 'required maxlength="256" autocomplete="current-password">'
                 '<label for="new">Nowe hasło (co najmniej 12 znaków)</label><input id="new" name="new" '
                 'type="password" required minlength="12" maxlength="256" autocomplete="new-password">'
                 '<label for="new2">Powtórz nowe hasło</label><input id="new2" name="new2" type="password" required '
                 'minlength="12" maxlength="256" autocomplete="new-password">')
        return self.page("Zmiana hasła", intro + '<div class="card">' + self.form("haslo", inner, "Zmień hasło") + "</div>",
                         active="konta")

    # --- status -------------------------------------------------------------------------------------
    def status(self, statuses: dict[str, dict | None], now: float) -> str:
        cards = []
        labels = {"update": "Aktualizacje", "breakglass": "Dostęp serwisowy", "backup": "Kopia bazy (pg_dump)",
                  "restore-test": "Test odtworzenia", "intake": "Formularz strony", "publish": "Publikacja strony",
                  "worker": "Worker strony", "egress": "Ruch wychodzący", "audit": "Dziennik audytu",
                  "tls": "Certyfikat TLS", "health": "Monitoring"}
        for name in contract.STATUS_FILES:
            doc = statuses.get(name)
            title = labels.get(name, name)
            if doc is None:
                cards.append(f'<div class="card"><h2>{h(title)}</h2><p class="muted">brak danych</p></div>')
                continue
            ok = doc.get("ok") is True
            age = ""
            try:
                seconds = int(now - validate.parse_utc(doc.get("ts", "")))
                age = f"aktualizacja {self.t(doc.get('ts'))}" + (" — <span class=\"warn\">dane starsze niż doba</span>"
                                                                 if seconds > 86400 else "")
            except (TypeError, ValueError):
                age = "brak znacznika czasu"
            details = self.status_details(name, doc)
            cards.append(f'<div class="card"><h2>{h(title)} '
                         f'{self.badge("OK" if ok else "UWAGA", "ok" if ok else "bad")}</h2>'
                         f'<dl class="kv">{details}</dl><p class="hint">{age}</p></div>')
        return self.page("Status serwera", '<div class="grid">' + "".join(cards) + "</div>", active="")

    def status_details(self, name: str, d: dict) -> str:
        rows: list[tuple[str, str]] = []

        def add(label: str, value: Any) -> None:
            rows.append((label, h(value) if not isinstance(value, Markup) else str(value)))

        if name == "update":
            installed = d.get("installed") or {}
            add("Wersja", installed.get("version", "—"))
            add("Kanał", d.get("channel", "—"))
            sig = SIG_STATE.get(d.get("sig"), (d.get("sig", "—"), "muted"))
            add("Podpis", Markup(self.badge(*sig)))
            upd = UPD_STATE.get(d.get("upd"), (d.get("upd", "—"), "muted"))
            add("Stan", Markup(self.badge(*upd)))
            add("Oczekujące", len(d.get("pending") or []))
        elif name == "breakglass":
            add("Okno", "OTWARTE do " + validate.local_display(d.get("expires_at"), self.tz) if d.get("active")
                else "zamknięte")
        elif name == "backup":
            pg = d.get("pgdump") or {}
            add("pg_dump", pg.get("state", "—"))
            add("Ostatni udany", validate.local_display(pg.get("last_ok_at"), self.tz))
            add("Okno Hetzner (UTC)", d.get("hetzner_window", "—"))
        elif name == "restore-test":
            add("Wynik", d.get("state", "—"))
            add("Ostatni test", validate.local_display(d.get("last_run_at"), self.tz))
        elif name == "intake":
            add("Ostatnie pobranie", validate.local_display(d.get("last_ok_at"), self.tz))
            add("Zaległe / błędy / kwarantanna", f"{d.get('backlog', '—')} / {d.get('failed', '—')} / "
                                                  f"{d.get('quarantined', '—')}")
        elif name in ("publish", "worker"):
            add("Stan", d.get("state", "—"))
            add("Ostatnio", validate.local_display(d.get("last_ok_at") or d.get("deployed_at"), self.tz))
        elif name == "egress":
            add("Tryb", {"observe": "obserwacja", "enforce": "egzekwowanie"}.get(d.get("mode"), d.get("mode", "—")))
            add("Odrzucone (5 min)", d.get("denied_5m", "—"))
        elif name == "audit":
            add("Wpisów", d.get("seq", "—"))
            add("Łańcuch", "spójny" if d.get("chain_ok") else "USZKODZONY")
            add("Sprawdzono", validate.local_display(d.get("verified_at"), self.tz))
        elif name == "tls":
            add("Ważny do", validate.local_display(d.get("not_after"), self.tz))
            add("Dni", d.get("days_left", "—"))
        elif name == "health":
            add("Monitoring", {"up": "działa", "down": "AWARIA"}.get(d.get("status"), d.get("status", "—")))
        return "".join(f"<dt>{h(label)}</dt><dd>{value}</dd>" for label, value in rows)

    # --- releases ----------------------------------------------------------------------------------------
    def releases(self, update: dict | None, pending: list[dict], history: list[dict]) -> str:
        if update is None:
            return self.page("Wydania", '<div class="card"><p class="muted">Brak danych aktualizatora.</p></div>',
                             active="wydania")
        installed = update.get("installed") or {}
        auto = update.get("auto_security") or {}
        last = update.get("last_check") or {}
        sig = SIG_STATE.get(update.get("sig"), (update.get("sig", "—"), "muted"))
        upd = UPD_STATE.get(update.get("upd"), (update.get("upd", "—"), "muted"))
        top = (f'<div class="card"><dl class="kv"><dt>Zainstalowana wersja</dt><dd>{h(installed.get("version", "—"))} '
               f'(sekwencja {h(installed.get("sequence", "—"))}, od {self.t(installed.get("installed_at"))})</dd>'
               f'<dt>Skrót manifestu</dt><dd><code>{h(installed.get("manifest_sha256", "—"))}</code></dd>'
               f'<dt>Kanał</dt><dd>{h(update.get("channel", "—"))}</dd>'
               f'<dt>Weryfikacja podpisu</dt><dd>{self.badge(*sig)}</dd>'
               f'<dt>Stan</dt><dd>{self.badge(*upd)}</dd>'
               f'<dt>Ostatnie sprawdzenie</dt><dd>{self.t(last.get("ts"))} '
               f'{self.badge("OK", "ok") if last.get("ok") else self.badge("błąd", "bad")}</dd></dl></div>')
        policy_allows = auto.get("policy") is not False
        optout = bool(auto.get("admin_optout"))
        if not policy_allows:
            auto_html = "<p>Polityka serwera wyłącza automatyczne poprawki bezpieczeństwa.</p>"
        else:
            state = "wyłączone przez biuro" if optout else "włączone"
            auto_html = (f"<p>Poprawki bezpieczeństwa instalują się same w nocnym oknie instalacji. Obecnie: "
                         f"<strong>{h(state)}</strong>. Wyłączenie widzi dostawca w monitoringu.</p>"
                         + self.form("wydania/autosecurity",
                                     f'<input type="hidden" name="enabled" value="{"true" if optout else "false"}">',
                                     "Włącz automatyczne poprawki" if optout else "Wyłącz automatyczne poprawki",
                                     style="" if optout else "danger"))
        body = [top, f'<h2>Automatyczne poprawki bezpieczeństwa</h2><div class="card">{auto_html}</div>',
                "<h2>Oczekujące wydania</h2>"]
        if not pending:
            body.append('<div class="card"><p class="muted">Brak oczekujących wydań.</p></div>')
        for item in pending:
            body.append(self.pending_card(item))
        body.append('<h2>Wycofanie</h2><div class="card"><p>Przywraca poprzednią wersję obrazów, konfiguracji i '
                    'programów. Baza danych zostaje bez zmian. Wycofanie poniżej poprawki bezpieczeństwa oznacza '
                    'pracę na wersji ze znaną podatnością.</p>'
                    + self.form("wydania/wycofaj", '<label for="to">Wersja docelowa (puste = poprzednia)</label>'
                                                  '<input id="to" name="to" type="text" maxlength="64" '
                                                  'placeholder="np. 1.4.2">', "Wycofaj wydanie", style="danger")
                    + "</div>")
        body.append("<h2>Historia</h2>" + self.audit_table(history, ("version", "from_version", "type", "code")))
        return self.page("Wydania", "".join(body), active="wydania")

    def pending_card(self, item: dict) -> str:
        detail = item.get("_detail") or {}
        version = item.get("version", "?")
        state = PENDING_STATE.get(item.get("state"), (item.get("state", "?"), "muted"))
        kind = {"security": "poprawka bezpieczeństwa", "feature": "zmiana funkcjonalna"}.get(item.get("type"),
                                                                                             item.get("type", "?"))
        rows = [f'<dt>Typ</dt><dd>{h(kind)}</dd>', f'<dt>Stan</dt><dd>{self.badge(*state)}</dd>',
                f'<dt>Skrót manifestu</dt><dd><code>{h(item.get("manifest_sha256", "—"))}</code></dd>',
                f'<dt>Najwcześniejsza instalacja</dt><dd>{self.t(item.get("earliest_install_at"))}</dd>']
        verify = detail.get("verify") if isinstance(detail.get("verify"), dict) else None
        if verify is not None:
            rows.append(f'<dt>Weryfikacja</dt><dd>{self.badge("poprawna", "ok") if verify.get("ok") else self.badge("NIEUDANA", "bad")} '
                        f'<span class="hint">{h(verify.get("detail") or verify.get("code") or "")}</span></dd>')
        signers = detail.get("signers") if isinstance(detail.get("signers"), dict) else {}
        if signers:
            text = "; ".join(f"{k}: {', '.join(map(str, v))}" for k, v in signers.items() if isinstance(v, list) and v)
            rows.append(f"<dt>Podpisy</dt><dd>{h(text)}</dd>")
        attestation = detail.get("canary_attestation")
        if isinstance(attestation, dict):
            rows.append(f'<dt>Test canary</dt><dd>{h(attestation.get("result"))}</dd>')
        url = item.get("changelog_url") or detail.get("changelog_url")
        if isinstance(url, str) and url.startswith("https://"):
            rows.append(f'<dt>Lista zmian</dt><dd><a href="{h(url)}" rel="noopener noreferrer">{h(url)}</a></dd>')
        parts = [f'<div class="card"><h2>Wydanie {h(version)}</h2><dl class="kv">{"".join(rows)}</dl>']
        advisories = detail.get("advisories") if isinstance(detail.get("advisories"), list) else []
        if advisories:
            parts.append("<h3>Poprawki bezpieczeństwa</h3><ul>" + "".join(
                f"<li><strong>{h(a.get('id'))}</strong> ({h(a.get('severity'))}): {h(a.get('summary'))}</li>"
                for a in advisories if isinstance(a, dict)) + "</ul>")
        notes = detail.get("notes_md")
        if isinstance(notes, str) and notes.strip():
            parts.append(f"<h3>Opis zmian</h3><pre>{h(notes[:65536])}</pre>")
        egress = detail.get("egress") if isinstance(detail.get("egress"), dict) else None
        widening = item.get("egress_widening") or (egress or {}).get("widening")
        if widening:
            added = (egress or {}).get("added") or []
            parts.append('<h3 class="warn">Poszerzenie ruchu wychodzącego — wymaga Twojej zgody</h3>'
                         '<table><tr><th>Rola</th><th>Host</th><th>Port</th></tr>' + "".join(
                             f"<tr><td>{h(a.get('role'))}</td><td><code>{h(a.get('host'))}</code></td>"
                             f"<td>{h(a.get('port'))}</td></tr>" for a in added if isinstance(a, dict)) + "</table>")
        approval = detail.get("approval")
        rejection = detail.get("rejection")
        if isinstance(approval, dict):
            parts.append(f'<p class="ok">Zatwierdzone {self.t(approval.get("ts"))}'
                         f'{" (nie wcześniej niż " + self.t(approval.get("not_before")) + ")" if approval.get("not_before") else ""}.</p>')
        if isinstance(rejection, dict):
            parts.append(f'<p class="bad">Odrzucone {self.t(rejection.get("ts"))}: {h(rejection.get("reason"))}</p>')
        if item.get("state") not in ("expired",) and isinstance(item.get("manifest_sha256"), str):
            hidden = (f'<input type="hidden" name="release" value="{h(version)}">'
                      f'<input type="hidden" name="manifest_sha256" value="{h(item.get("manifest_sha256"))}">')
            if not isinstance(approval, dict):
                nb = self.uid("nb")
                parts.append(self.form("wydania/zatwierdz", hidden +
                                       f'<label for="{nb}">Nie wcześniej niż (czas lokalny, opcjonalnie)</label>'
                                       f'<input id="{nb}" name="not_before" type="datetime-local">',
                                       "Zatwierdź wydanie"))
            if not isinstance(rejection, dict):
                rr = self.uid("rr")
                parts.append(self.form("wydania/odrzuc", hidden +
                                       f'<label for="{rr}">Powód odrzucenia (opcjonalnie)</label>'
                                       f'<input id="{rr}" name="reason" type="text" maxlength="500">',
                                       "Odrzuć wydanie", style="danger"))
        parts.append("</div>")
        return "".join(parts)

    def audit_table(self, entries: list[dict], keys: tuple[str, ...]) -> str:
        if not entries:
            return '<div class="card"><p class="muted">Brak wpisów.</p></div>'
        rows = []
        for e in entries:
            params = e.get("params") if isinstance(e.get("params"), dict) else {}
            actor = e.get("actor") if isinstance(e.get("actor"), dict) else {}
            shown = ", ".join(f"{k}={params[k]}" for k in keys if k in params)
            rows.append(f"<tr><td>{self.t(e.get('ts'), True)}</td><td><code>{h(e.get('event'))}</code></td>"
                        f"<td>{h(actor.get('kind'))}:{h(actor.get('id'))}{(' @ ' + h(e.get('node'))) if e.get('node') else ''}</td>"
                        f"<td>{h(shown)}</td><td class=\"muted\">#{h(e.get('seq'))}</td></tr>")
        return ("<table><tr><th>Czas</th><th>Zdarzenie</th><th>Kto</th><th>Szczegóły</th><th>Wpis</th></tr>"
                + "".join(rows) + "</table>")

    # --- break-glass ------------------------------------------------------------------------------------------
    def access(self, bg: dict | None, summaries: list[dict], history: list[dict]) -> str:
        parts = []
        if bg and bg.get("active"):
            actor = bg.get("actor") if isinstance(bg.get("actor"), dict) else {}
            parts.append(f'<div class="card"><p>{self.badge("OTWARTY", "warn")} do <strong>{self.t(bg.get("expires_at"))}'
                         f'</strong> (od {self.t(bg.get("started_at"))}, otworzył {h(actor.get("id"))}).</p>'
                         f'<p>Powód: {h(bg.get("reason"))}</p>'
                         + self.form("dostep/zamknij", '<label for="dr">Uwagi przy zamknięciu (opcjonalnie)</label>'
                                                      '<input id="dr" name="reason" type="text" maxlength="500">',
                                     "Zamknij dostęp teraz", style="danger") + "</div>")
        else:
            hours = "".join(f'<option value="{n}"{" selected" if n == 2 else ""}>{n} h</option>'
                            for n in range(contract.BREAKGLASS_HOURS_MIN, contract.BREAKGLASS_HOURS_MAX + 1))
            parts.append(
                '<div class="card"><p>Dostęp serwisowy jest <strong>zamknięty</strong>: dostawca nie ma SSH ani dostępu '
                'do tego panelu. Otwórz go tylko na prośbę dostawcy, na tyle godzin, ile potrzeba. Okno zamknie się '
                'samo; wszystkie logowania i polecenia trafią do dziennika audytu.</p>'
                + self.form("dostep/otworz",
                            f'<label for="hours">Czas trwania</label><select id="hours" name="hours">{hours}</select>'
                            f'<label for="reason">Powód (widoczny w dzienniku, {contract.BREAKGLASS_REASON_MIN}–'
                            f'{contract.BREAKGLASS_REASON_MAX} znaków)</label>'
                            f'<textarea id="reason" name="reason" required minlength="{contract.BREAKGLASS_REASON_MIN}" '
                            f'maxlength="{contract.BREAKGLASS_REASON_MAX}"></textarea>',
                            "Otwórz dostęp serwisowy") + "</div>")
        parts.append("<h2>Okna dostępu i podsumowania</h2>")
        if not summaries:
            parts.append('<div class="card"><p class="muted">Brak zakończonych okien.</p></div>')
        else:
            rows = []
            for s in summaries:
                ssh = s.get("ssh") if isinstance(s.get("ssh"), dict) else {}
                sudo = s.get("sudo") if isinstance(s.get("sudo"), dict) else {}
                audit = s.get("audit") if isinstance(s.get("audit"), dict) else {}
                rows.append(
                    f"<tr><td><a href=\"{BASE}/dostep/okno/{h(s.get('window_id'))}\">{self.t(s.get('started_at'))}</a></td>"
                    f"<td>{self.t(s.get('closed_at'))} ({h(s.get('close_reason'))})</td>"
                    f"<td>{h(s.get('reason'))}</td><td>{len(ssh.get('logins') or [])}</td>"
                    f"<td>{h(sudo.get('count', 0))}</td>"
                    f"<td>{'spójny' if audit.get('chain_ok') else '<span class=bad>USZKODZONY</span>'}</td></tr>")
            parts.append("<table><tr><th>Otwarte</th><th>Zamknięte</th><th>Powód</th><th>Logowania SSH</th>"
                         "<th>Polecenia sudo</th><th>Dziennik</th></tr>" + "".join(rows) + "</table>")
        parts.append("<h2>Dziennik dostępu</h2>" + self.audit_table(history, ("window_id", "hours", "reason", "user")))
        return self.page("Dostęp serwisowy", "".join(parts), active="dostep")

    def access_window(self, s: dict) -> str:
        ssh = s.get("ssh") if isinstance(s.get("ssh"), dict) else {}
        sudo = s.get("sudo") if isinstance(s.get("sudo"), dict) else {}
        admin = s.get("admin_http") if isinstance(s.get("admin_http"), dict) else {}
        audit = s.get("audit") if isinstance(s.get("audit"), dict) else {}
        actor = s.get("actor") if isinstance(s.get("actor"), dict) else {}
        parts = [f'<div class="card"><dl class="kv"><dt>Otworzył</dt><dd>{h(actor.get("id"))}</dd>'
                 f'<dt>Powód</dt><dd>{h(s.get("reason"))}</dd>'
                 f'<dt>Od – do</dt><dd>{self.t(s.get("started_at"))} – {self.t(s.get("closed_at"))} '
                 f'({h(s.get("close_reason"))})</dd>'
                 f'<dt>Dziennik audytu</dt><dd>wpisy {h(audit.get("from_seq"))}–{h(audit.get("to_seq"))}, '
                 f'{"łańcuch spójny" if audit.get("chain_ok") else "<span class=bad>ŁAŃCUCH USZKODZONY</span>"}, '
                 f'kotwica <code>{h(str(audit.get("head") or "")[:16])}</code></dd>'
                 f'<dt>Żądania do panelu</dt><dd>{h(admin.get("requests", 0))}</dd></dl></div>']
        logins = [x for x in ssh.get("logins") or [] if isinstance(x, dict)]
        parts.append(f"<h2>Logowania SSH ({len(logins)}, nieudane: {h(ssh.get('fails', 0))})</h2>")
        parts.append("<table><tr><th>Czas</th><th>Konto</th><th>Węzeł</th><th>Klucz</th></tr>" + "".join(
            f"<tr><td>{self.t(x.get('ts'), True)}</td><td>{h(x.get('user'))}</td><td>{h(x.get('node'))}</td>"
            f"<td><code>{h(x.get('key_fp'))}</code></td></tr>" for x in logins) + "</table>")
        commands = [x for x in sudo.get("commands") or [] if isinstance(x, dict)]
        parts.append(f"<h2>Polecenia sudo ({h(sudo.get('count', len(commands)))}"
                     f"{', lista skrócona' if sudo.get('truncated') else ''})</h2>")
        parts.append("<table><tr><th>Czas</th><th>Konto</th><th>Polecenie</th></tr>" + "".join(
            f"<tr><td>{self.t(x.get('ts'), True)}</td><td>{h(x.get('user'))}</td><td><code>{h(x.get('command'))}</code>"
            f"</td></tr>" for x in commands) + "</table>")
        runs = [x for x in s.get("ansible") or [] if isinstance(x, dict)]
        parts.append("<h2>Uruchomienia Ansible</h2><table><tr><th>Czas</th><th>Zdarzenie</th><th>Commit</th>"
                     "<th>Plan</th><th>Wynik</th></tr>" + "".join(
                         f"<tr><td>{self.t(x.get('ts'), True)}</td><td>{h(x.get('event'))}</td>"
                         f"<td><code>{h(str(x.get('commit') or '')[:12])}</code></td>"
                         f"<td><code>{h(str(x.get('plan_sha256') or '')[:16])}</code></td><td>{h(x.get('result'))}</td></tr>"
                         for x in runs) + "</table>")
        return self.page(f"Okno dostępu {s.get('window_id', '')}", "".join(parts), active="dostep")

    # --- features ---------------------------------------------------------------------------------------------
    def features(self, doc: dict | None, egress: dict | None, widening: list[dict]) -> str:
        parts = []
        if egress:
            mode = {"observe": "obserwacja (ruch spoza listy jest logowany, nie blokowany)",
                    "enforce": "egzekwowanie (ruch spoza listy jest blokowany)"}.get(egress.get("mode"), egress.get("mode"))
            parts.append(f'<div class="card"><dl class="kv"><dt>Ruch wychodzący</dt><dd>{h(mode)}</dd>'
                         f'<dt>Odrzucone połączenia (5 min)</dt><dd>{h(egress.get("denied_5m", "—"))}</dd>'
                         f'<dt>Ostatnie zastosowanie reguł</dt><dd>{self.t(egress.get("last_apply_at"))}</dd></dl></div>')
        if widening:
            parts.append('<div class="flash info">Oczekujące wydania poszerzają listę dozwolonych połączeń: '
                         + ", ".join(h(w.get("version")) for w in widening)
                         + f'. Zgodę wyrażasz na stronie <a href="{BASE}/wydania">Wydania</a>.</div>')
        parts.append('<p class="hint">Każda funkcja korzystająca z usług zewnętrznych otwiera nowe połączenia '
                     'wychodzące. Włączenie funkcji tutaj jest zgodą biura na ten ruch.</p>')
        if doc is None:
            parts.append('<div class="card"><p class="bad">Brak pliku funkcji na serwerze.</p></div>')
            return self.page("Funkcje i ruch wychodzący", "".join(parts), active="funkcje")
        flags = doc.get("features") or {}
        for name in contract.FEATURE_NAMES:
            label, description = FEATURE_INFO[name]
            enabled = bool(flags.get(name))
            inner = (f'<input type="hidden" name="feature" value="{h(name)}">'
                     f'<input type="hidden" name="enabled" value="{"false" if enabled else "true"}">')
            extra = ""
            if name == "ics":
                hosts = "\n".join(h(x) for x in doc.get("ics_hosts") or [] if isinstance(x, str))
                textarea = ('<label for="ics_hosts">Hosty kalendarzy (jeden w wierszu, bez https:// i portu)</label>'
                            f'<textarea id="ics_hosts" name="ics_hosts">{hosts}</textarea>')
                if enabled:
                    extra = self.form("funkcje", '<input type="hidden" name="feature" value="ics">'
                                                 '<input type="hidden" name="enabled" value="true">' + textarea,
                                      "Zapisz listę hostów")
                else:
                    inner += textarea
            button = "Wyłącz" if enabled else "Włącz"
            parts.append(f'<div class="card"><h2>{h(label)} {self.badge("włączone" if enabled else "wyłączone", "ok" if enabled else "muted")}</h2>'
                         f"<p>{h(description)}</p>{extra}"
                         + self.form("funkcje", inner, button, style="danger" if enabled else "") + "</div>")
        return self.page("Funkcje i ruch wychodzący", "".join(parts), active="funkcje")

    # --- devices ------------------------------------------------------------------------------------------------
    def devices(self, snap: dict) -> str:
        staff_section = snap.get("staff") if isinstance(snap.get("staff"), dict) else {}
        staff = [x for x in staff_section.get("items") or [] if isinstance(x, str)]
        nodes_section = snap.get("nodes") if isinstance(snap.get("nodes"), dict) else {}
        nodes = [n for n in nodes_section.get("items") or [] if isinstance(n, dict)]
        parts = []
        if nodes_section and not nodes_section.get("ok", True):
            parts.append('<div class="flash error">Nie udało się odświeżyć listy urządzeń; pokazuję ostatnią znaną.</div>')
        options = "".join(f'<option value="{h(x)}">{h(x)}</option>' for x in staff)
        parts.append(
            '<h2>Dodaj urządzenie</h2><div class="card"><p>Klucz rejestracji jest jednorazowy i ważny 30 minut. '
            'Urządzenie osoby z personelu dostaje dostęp do CRM; urządzenie biura dodatkowo do tego panelu.</p>'
            + self.form("urzadzenia/dodaj",
                        '<label for="kind">Rodzaj</label><select id="kind" name="kind">'
                        '<option value="staff">urządzenie pracownika (dostęp do CRM)</option>'
                        '<option value="office-device">urządzenie biura (CRM i panel admina)</option></select>'
                        f'<label for="enroll-login">Pracownik (tylko dla urządzenia pracownika)</label>'
                        f'<select id="enroll-login" name="login"><option value="">—</option>{options}</select>',
                        "Utwórz klucz rejestracji") + "</div>")
        rows = []
        for n in nodes:
            tags = [t for t in n.get("tags") or [] if isinstance(t, str)]
            is_server = contract.TAG_SERVER in tags
            revoke = "" if is_server else self.form(
                "urzadzenia/usun", f'<input type="hidden" name="node_id" value="{h(n.get("id"))}">',
                "Usuń", style="danger")
            online = self.badge("online", "ok") if n.get("online") else self.badge("offline", "muted")
            rows.append(f"<tr><td>{h(n.get('name'))}</td><td>{h(n.get('user'))}</td><td>{h(', '.join(tags))}</td>"
                        f"<td><code>{h(n.get('ip4'))}</code><br><code>{h(n.get('ip6'))}</code></td>"
                        f"<td>{online}<br><span class=\"hint\">{self.t(n.get('last_seen'))}</span></td>"
                        f"<td>{self.t(n.get('expiry'))}</td><td>{revoke}</td></tr>")
        parts.append(f"<h2>Urządzenia w tailnecie</h2><p class=\"hint\">Stan z {self.t(nodes_section.get('ts'))}.</p>")
        parts.append("<table><tr><th>Nazwa</th><th>Użytkownik</th><th>Rola</th><th>Adresy</th><th>Ostatnio</th>"
                     "<th>Wygasa</th><th></th></tr>" + "".join(rows) + "</table>" if rows
                     else '<div class="card"><p class="muted">Brak danych o urządzeniach.</p></div>')
        parts.append(
            '<h2>Personel</h2><div class="card"><p>Lista loginów osób z dostępem do CRM (jeden w wierszu, małe litery, '
            'np. <code>anna.nowak</code>). Usunięcie osoby z listy odłącza jej urządzenia.</p>'
            + self.form("urzadzenia/personel", '<label for="staff">Loginy</label>'
                        f'<textarea id="staff" name="staff">{h(chr(10).join(staff))}</textarea>', "Zapisz listę")
            + "</div>")
        return self.page("Urządzenia", "".join(parts), active="urzadzenia")

    # --- studio --------------------------------------------------------------------------------------------------
    def studio(self, snap: dict) -> str:
        section = snap.get("studio") if isinstance(snap.get("studio"), dict) else {}
        data = section.get("data") if isinstance(section.get("data"), dict) else {}
        parts = ['<div class="card"><p>Supabase Studio to narzędzie administracyjne bazy danych. Jest domyślnie '
                 'wyłączone; włączaj je tylko na czas prac (wyłączy się samo).</p>']
        if data.get("enabled"):
            url = data.get("url")
            link = (f'<a href="{h(url)}" rel="noopener noreferrer">{h(url)}</a>'
                    if isinstance(url, str) and url.startswith("https://") else "")
            parts.append(f"<p>{self.badge('włączone', 'warn')} do {self.t(data.get('expires_at'))} {link}</p>"
                         + self.form("studio/wylacz", "", "Wyłącz Studio", style="danger"))
        else:
            hours = "".join(f'<option value="{n}">{n} h</option>' for n in range(1, 9))
            parts.append(f"<p>{self.badge('wyłączone', 'muted')}</p>"
                         + self.form("studio/wlacz", f'<label for="sh">Na ile godzin</label>'
                                                     f'<select id="sh" name="hours">{hours}</select>', "Włącz Studio"))
        if section and not section.get("ok", True):
            parts.append('<p class="bad">Nie udało się odczytać stanu Studio.</p>')
        parts.append(f'<p class="hint">Stan z {self.t(section.get("ts"))}.</p></div>')
        return self.page("Studio na żądanie", "".join(parts), active="studio")

    # --- recovery ---------------------------------------------------------------------------------------------------
    def recovery(self) -> str:
        body = ('<div class="card"><p>Pakiet odzyskiwania pozwala odzyskać dostęp do serwera, gdy biuro straci '
                'urządzenia i konta panelu. Zawiera zaszyfrowane poświadczenia awaryjne (konto awaryjne panelu, '
                'konto <code>recovery</code> konsoli VPS) i klucze danych.</p><ul>'
                '<li>Pakiet powstaje na serwerze; hasło pokazujemy <strong>tylko raz</strong>.</li>'
                '<li>Zapisz plik na dwóch nośnikach, wydrukuj kartę, a hasło przechowuj osobno, u innej osoby.</li>'
                '<li>Wygenerowanie nowego pakietu unieważnia konto awaryjne z poprzedniego pakietu.</li>'
                '<li>Pliki i hasło znikają z serwera po 10 minutach.</li></ul>'
                + self.form("odzyskiwanie", "", "Wygeneruj nowy pakiet") + "</div>")
        return self.page("Pakiet odzyskiwania", body, active="odzyskiwanie")

    # --- contacts ---------------------------------------------------------------------------------------------------
    def contacts(self, doc: dict | None) -> str:
        doc = doc or {}

        def person(key: str, title: str, required: bool) -> str:
            p = doc.get(key) if isinstance(doc.get(key), dict) else {}
            req = " required" if required else ""
            return (f"<h2>{h(title)}</h2>"
                    f'<label for="{key}-name">Imię i nazwisko</label><input id="{key}-name" name="{key}_name" '
                    f'type="text" maxlength="200" value="{h(p.get("name"))}"{req}>'
                    f'<label for="{key}-email">E-mail</label><input id="{key}-email" name="{key}_email" type="email" '
                    f'maxlength="200" value="{h(p.get("email"))}">'
                    f'<label for="{key}-phone">Telefon</label><input id="{key}-phone" name="{key}_phone" type="tel" '
                    f'maxlength="200" value="{h(p.get("phone"))}">')

        inner = (person("primary", "Osoba zgłaszająca naruszenie do UODO", True)
                 + person("secondary", "Zastępca (opcjonalnie)", False)
                 + person("iod", "Inspektor Ochrony Danych (jeśli wyznaczony)", False)
                 + '<label for="notes">Uwagi (opcjonalnie)</label>'
                   f'<input id="notes" name="notes" type="text" maxlength="200" value="{h(doc.get("notes"))}">')
        updated = f'<p class="hint">Ostatnia zmiana: {self.t(doc.get("updated_at"))}.</p>' if doc.get("updated_at") else ""
        body = ('<div class="card"><p>Naruszenie ochrony danych osobowych zgłasza do UODO biuro (RODO art. 33, '
                'w ciągu 72 godzin). Dostawca zgłasza incydenty bezpieczeństwa produktu (CRA art. 14) i powiadomi '
                'te osoby. Dane trafiają też do pakietu odzyskiwania; nie trafiają do monitoringu dostawcy.</p>'
                + updated + self.form("kontakty", inner, "Zapisz kontakty") + "</div>")
        return self.page("Kontakty incydentów", body, active="kontakty")

    # --- accounts ----------------------------------------------------------------------------------------------------
    def accounts(self, users: dict[str, dict]) -> str:
        rows = []
        for login in sorted(users):
            u = users[login]
            if u.get("kind") == "emergency" or login == contract.EMERGENCY_LOGIN:
                actions = '<span class="hint">zarządzane przez pakiet odzyskiwania</span>'
            else:
                hidden = f'<input type="hidden" name="login" value="{h(login)}">'
                actions = (self.form("konta/reset-totp", hidden, "Nowy kod TOTP", style="secondary")
                           + self.form("konta/haslo-tymczasowe", hidden, "Hasło tymczasowe", style="secondary")
                           + ("" if login == self.user else self.form("konta/usun", hidden, "Usuń", style="danger")))
            flags = []
            if u.get("must_change"):
                flags.append("musi zmienić hasło")
            if not u.get("enabled"):
                flags.append("wyłączone")
            rows.append(f"<tr><td><code>{h(login)}</code></td><td>{h(u.get('display_name'))}</td>"
                        f"<td>{self.t(u.get('created_at'))}</td><td>{h(', '.join(flags))}</td><td>{actions}</td></tr>")
        add = self.form("konta/dodaj",
                        '<label for="nl">Login (małe litery, np. anna.nowak)</label>'
                        '<input id="nl" name="login" type="text" required maxlength="41">'
                        '<label for="nd">Imię i nazwisko</label>'
                        '<input id="nd" name="display_name" type="text" required maxlength="80">', "Dodaj konto")
        body = (f'<p><a href="{BASE}/haslo">Zmień własne hasło</a></p>'
                "<table><tr><th>Login</th><th>Osoba</th><th>Utworzone</th><th>Uwagi</th><th></th></tr>"
                + "".join(rows) + "</table>"
                '<h2>Nowe konto</h2><div class="card"><p>Nowa osoba dostanie hasło startowe (zmieni je przy pierwszym '
                'logowaniu) i kod QR do aplikacji uwierzytelniającej. Przekaż je osobiście.</p>' + add + "</div>")
        return self.page("Konta panelu", body, active="konta")

    # --- request results -----------------------------------------------------------------------------------------------
    def pending_result(self, rid: str, rtype: str) -> str:
        body = (f'<div class="card"><p>Żądanie „{h(REQUEST_LABELS.get(rtype, rtype))}” czeka na wykonanie na serwerze. '
                f'Strona odświeży się sama.</p><p class="hint">Identyfikator: <code>{h(rid)}</code></p></div>')
        return self.page("Żądanie w toku", body).replace(
            "<head>", f'<head><meta http-equiv="refresh" content="2;url={BASE}/zadania/{h(rid)}">', 1)

    def expired_result(self, rid: str) -> str:
        return self.page("Wynik niedostępny", '<div class="card"><p>Wynik tego żądania wygasł albo nie istnieje. '
                                              'Dane wrażliwe (klucze, kody, hasła) są usuwane po 10 minutach.</p>'
                                              f'<p class="hint"><code>{h(rid)}</code></p></div>')

    def result(self, res: dict, extra: dict | None = None, back: str = "") -> str:
        status = res.get("status")
        cls = {"ok": "ok", "rejected": "error", "error": "error"}.get(status, "info")
        label = {"ok": "Wykonano", "rejected": "Odrzucono", "error": "Błąd"}.get(status, status)
        rtype = res.get("type") or ""
        parts = [f'<div class="flash {cls}"><strong>{h(label)}:</strong> {h(res.get("message"))}</div>']
        data = res.get("data") if isinstance(res.get("data"), dict) else {}
        if status == "ok":
            if rtype == "device.enroll":
                parts.append(self.enroll_result(data))
            elif rtype in ("console.user.add", "console.user.reset_totp", "console.setup"):
                parts.append(self.totp_result(data))
            elif rtype == "recovery.generate":
                parts.append(self.recovery_result(res["id"], data))
        if extra and extra.get("temporary_password"):
            parts.append(f'<div class="card"><h2>Hasło tymczasowe</h2><p class="secret">{h(extra["temporary_password"])}'
                         "</p><p>Przekaż je osobiście. Przy pierwszym logowaniu trzeba je zmienić.</p></div>")
        meta = (f'<p class="hint">Żądanie <code>{h(res.get("id"))}</code>, {self.t(res.get("ts"), True)}'
                f'{", wpis audytu #" + h(res.get("audit_seq")) if res.get("audit_seq") is not None else ""}.</p>')
        link = f'<p><a href="{BASE}/{h(back)}">Wróć</a></p>' if back is not None else ""
        return self.page(REQUEST_LABELS.get(rtype, "Wynik żądania"), "".join(parts) + meta + link)

    def enroll_result(self, d: dict) -> str:
        server = d.get("login_server") if isinstance(d.get("login_server"), str) else ""
        key = d.get("key") if isinstance(d.get("key"), str) else ""
        command = f"tailscale up --login-server={server} --auth-key={key}"
        office = d.get("kind") == "office-device"
        return (
            f'<div class="card"><p>Klucz ważny do <strong>{self.t(d.get("expires_at"))}</strong>, jednorazowy'
            f'{" — urządzenie biura (CRM i panel admina)" if office else ", dla " + h(d.get("user"))}.</p>'
            f'{self.qr_block(server, "1. Adres serwera koordynacji")}{self.qr_block(key, "2. Klucz rejestracji")}'
            '<h2>Telefon (Android, iOS)</h2><ol><li>Zainstaluj aplikację Tailscale.</li>'
            '<li>W ustawieniach wybierz „Use a custom coordination server” / „Use alternate server” i zeskanuj kod 1.</li>'
            '<li>Wybierz logowanie kluczem („Use an auth key”) i zeskanuj kod 2.</li></ol>'
            '<h2>Komputer (Windows, macOS, Linux)</h2><p>Zainstaluj Tailscale i w terminalu administratora wpisz:</p>'
            f'<p class="secret">{h(command)}</p>'
            f'<p class="hint">Adres serwera: <code>{h(server)}</code></p></div>')

    def totp_result(self, d: dict) -> str:
        uri = d.get("otpauth_uri") if isinstance(d.get("otpauth_uri"), str) else ""
        secret = d.get("totp_secret") if isinstance(d.get("totp_secret"), str) else ""
        grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
        parts = ['<div class="card"><h2>Aplikacja uwierzytelniająca</h2>'
                 '<p>Zeskanuj kod w aplikacji (np. Aegis, FreeOTP, Google Authenticator, 1Password).</p>',
                 self.qr_block(uri, f"TOTP: {d.get('login', '')}"),
                 f'<p>Albo wpisz klucz ręcznie:</p><p class="secret">{h(grouped)}</p>']
        if d.get("initial_password"):
            parts.append(f'<h2>Hasło startowe</h2><p class="secret">{h(d["initial_password"])}</p>'
                         '<p>Przy pierwszym logowaniu trzeba ustawić własne hasło.</p>')
        parts.append("<p class=\"hint\">Te dane znikną z serwera po 10 minutach i nie da się ich odtworzyć.</p></div>")
        return "".join(parts)

    def recovery_result(self, rid: str, d: dict) -> str:
        links = []
        if d.get("file"):
            links.append(f'<li><a href="{BASE}/zadania/{h(rid)}/plik/file">Pakiet: {h(d.get("file"))}</a> '
                         f'({h(d.get("bytes"))} B, SHA-256 <code>{h(d.get("sha256"))}</code>)</li>')
        if d.get("card"):
            links.append(f'<li><a href="{BASE}/zadania/{h(rid)}/plik/card">Karta do wydruku: {h(d.get("card"))}</a></li>')
        return (f'<div class="card"><h2>Hasło pakietu</h2><p class="secret">{h(d.get("password"))}</p>'
                '<p>Zapisz hasło na papierze i przechowuj oddzielnie od pakietu. Nie wysyłaj go e-mailem ani SMS-em.</p>'
                f'<h2>Pliki</h2><ul>{"".join(links)}</ul></div>')

    def error(self, title: str, message: str) -> str:
        return self.page(title, f'<div class="flash error">{h(message)}</div>')


class Markup(str):
    """Pre-escaped HTML fragment."""
