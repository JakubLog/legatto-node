# Kontrakt serwera biura

Nazwy, ścieżki, formaty i interfejsy wspólne dla narzędzi działających na serwerze biura. Wartości (nazwy, adresy, porty, ścieżki, użytkownicy, jednostki) są w `contract/contract.yml`, przypięte wersje w `contract/versions.yml` — tu jest ich znaczenie i formaty wymiany danych. Kontrakt v1 (`legatto_contract_version: 1`). Numeracja sekcji jest stała, bo odwołuje się do niej kod (`CONTRACT §4.x`).

## 1. Zasady

1. **Jedno źródło nazw.** Kod nie wpisuje na sztywno nazwy sieci, adresu, portu, ścieżki, użytkownika ani jednostki. Kod na serwerze (Python, szablony w paczce) dostaje je przez `/etc/legatto/office.env`, pliki konfiguracyjne instalowane przy wdrożeniu albo stałe w kodzie z komentarzem `# contract: legatto_paths.status` (testy sprawdzają zgodność ze `contract.yml`).
2. **Zmiany kontraktu.** Zmiana niekompatybilna podbija `legatto_contract_version`, a manifest wydania wymagający nowego kontraktu ustawia `min_contract_version`.
5. **Narzędzia hosta** (updater, office-console, executor, break-glass, audyt, polityka ACL, egress, monitoring, pakiet odzyskiwania): Python 3.12, tylko biblioteka standardowa Ubuntu 24.04. Hasła: `hashlib.scrypt`. TOTP: RFC 6238 na `hmac` (SHA-1, 6 cyfr, krok 30 s, okno ±1 krok). Wyjątki:
   - `legatto-policy` renderuje `headscale/acl.hujson.j2` przez `python3-jinja2` z Ubuntu main, wyłącznie w `jinja2.sandbox.SandboxedEnvironment` z `StrictUndefined`; żadne inne narzędzie nie importuje jinja2;
   - `legatto-recovery-pack` woła binaria z APT noble universe: `age` (`age -p`, szyfrowanie pakietu) i `qrencode` (kody QR karty). Działają tylko lokalnie na danych serwera, bez wejścia z sieci; universe nie ma gwarantowanych poprawek bezpieczeństwa bez Ubuntu Pro — ryzyko zaakceptowane z tego powodu.
6. **Bez sekretów w repo i w logach.** CLI nigdy nie drukuje sekretu na stdout/stderr (wyjątki są wymienione przy poleceniach w §4.6).
7. **Bez zaślepek.** Każdy plik w repozytorium działa.

## 3. Stałe wspólne (skrót)

Pełne wartości: `contract.yml`. Najważniejsze rozstrzygnięcia:

- **Nazwy hostów:** `vpn.<domena>` — Headscale, jedyny publiczny rekord serwera; `app.<domena>` — CRM; `admin.app.<domena>` — panel i funkcje wrażliwe; `<domena>` — strona posła (Pages, konto CF biura). `app` i `admin.app` istnieją tylko w Headscale `extra_records`. MagicDNS: `tn.<domena>`. Certyfikat DNS-01 (lego, token Cloudflare ograniczony do strefy biura): `app.<domena>` + `*.app.<domena>`. CAA: `vpn.` tylko `tls-alpn-01`, `app.` tylko `dns-01`.
- **Tailnet:** prefiksy `100.64.0.0/10` i `fd7a:115c:a1e0::/48`, przydział sekwencyjny. CRM słucha na `legatto_ts_ip4:443`, admin na `[legatto_ts_ip6]:443`, SSH na `legatto_ts_ip4:22`. Adresy serwera zawsze z `tailscale ip -4/-6`.
- **Porty publiczne:** tylko `443/tcp` (Headscale), `3478/udp` (STUN), `41641/udp` (WireGuard).
- **Proxy egress:** host — Smokescreen na `127.0.0.1:4750`, dostęp tylko dla `legatto_egress_host_proxy_clients`; kontenery — Smokescreen per rola (`app`, `auth`, `functions`, `intake`, `publish`) na porcie 4750 pod nazwą usługi `egress-<rola>` (`legatto_egress_container_proxies`).
- **Sieci Dockera:** `legatto-host` (`br-legatto`, `172.30.0.0/24`, db `.2`, app `.10`, api-gw `.11`, czarna dziura DNS `.53`), `legatto-int` (`internal`), `legatto-egress-ext` (`172.30.255.0/24`, tylko proxy), `legatto-egress-<rola>` (`internal`). Projekt compose: `legatto`.
- **Użytkownicy:** `v-<imię>` w `legatto-ops`; `recovery` (tylko konsola VPS); `legatto-console`, `legatto-mon`, `legatto-acme`, `smokescreen`, `caddy`; grupy `legatto-status` i `legatto-audit` do odczytu statusów i audytu. Rola `base` (net, pierwsza w bootstrapie) tworzy grupy `legatto-ops`, `legatto-console`, `legatto-status`, `legatto-audit` oraz konta `recovery` i `v-*`. Konta usług tworzy rola właściciela z grupami wg `legatto_users`: `legatto-console` — `office_console`, `legatto-mon` — `monitoring`, `legatto-acme` i `caddy` — `proxy`, `smokescreen` — `egress`.
- **Ścieżki:** `/opt/legatto` (kod, wydania, binaria), `/etc/legatto` (konfiguracja tylko z Ansible, `secrets/` 0700), `/var/lib/legatto` (stan), `/var/log/legatto/audit.log`, `/run/legatto` (tmpfs: env, klucz PII, gniazdo konsoli), `/var/backups/legatto/pg` (lokalny `pg_dump`). Katalogi bazowe tworzy wyłącznie rola `base` i inne role nie zmieniają ich trybu: `/opt/legatto` i `/opt/legatto/sbin` 0755, `/etc/legatto` 0755, `/etc/legatto/secrets` 0700, `/var/lib/legatto` 0755, `/var/lib/legatto/status` 0750 `root:legatto-status`, `/var/log/legatto` 0750 `root:legatto-audit`, `/run/legatto` 0755 (tmpfiles.d). Podkatalogi tworzą role ich właścicieli.
- **Kanały:** `canary|early|stable`. **Typy wydań:** `security|feature`.

## 4. Interfejsy

### 4.1 `/etc/legatto/office.env`

Pisze: rola `base` (net) w oknie break-glass. Czytają: updater (renderowanie szablonów paczki), `legatto-secrets`, `legatto-policy`, narzędzia hosta.

Format: `KLUCZ=wartość`, jedna para na linię, bez cudzysłowów, bez rozwijania zmiennych, bez sekretów, 0644 root. Klucze: `legatto_office_env` w `contract.yml` (`LEGATTO_CONTRACT_VERSION`, `LEGATTO_SLUG`, `LEGATTO_ENV`, `LEGATTO_OFFICE_TITLE`, `LEGATTO_OFFICE_DOMAIN`, `LEGATTO_HOST_{SITE,VPN,CRM,ADMIN}`, `LEGATTO_TS_IP4`, `LEGATTO_TS_IP6`, `LEGATTO_PUBLIC_IPV4`, `LEGATTO_TZ`). Szablony w paczce używają wyłącznie placeholderów `${LEGATTO_*}`; updater odrzuca szablon z placeholderem spoza tej listy.

### 4.2 Log audytu (JSONL, łańcuch hashy)

Plik `/var/log/legatto/audit.log`, `0640 root:legatto-audit`, `chattr +a`. **Jedyny zapisujący:** `legatto-audit append` (net), który trzyma `flock` na `audit.log.lock`. Nikt inny nie otwiera pliku do zapisu. `legatto-audit` oraz jednostki `legatto-audit-ssh` i `legatto-audit-verify` instaluje rola `base`, więc audyt działa od pierwszej roli bootstrapu; inne role mogą go wołać od razu.

Wpis (jedna linia JSON, UTF-8):

```json
{"seq":1042,"ts":"2026-11-21T10:02:11Z","host":"<slug>","cat":"update","event":"update.installed",
 "actor":{"kind":"system","id":"legatto-update"},"node":null,
 "params":{"version":"1.5.0","manifest_sha256":"…"},"prev":"<hash wpisu 1041>","hash":"<sha256 hex>"}
```

- `seq` rośnie o 1 od 1; `prev` pierwszego wpisu = 64 zera (`legatto_audit.genesis_prev`).
- `hash = sha256(canonical(wpis bez pola "hash"))`, gdzie `canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. `prev` jest wewnątrz haszowanego obiektu.
- `actor.kind`: `office-admin` (login konsoli, `node` = nazwa węzła z `tailscale whois`), `vendor` (konto `v-*`), `system` (`id` = nazwa narzędzia), `bootstrap`.
- `params`: tylko dane techniczne. Bez treści spraw, nazwisk wyborców, e-maili, haseł, kodów TOTP i kluczy pre-auth. `reason` okna break-glass jest dozwolony (tekst wpisany przez admina biura).
- Kategorie (`cat` = prefiks `event` do pierwszej kropki): `legatto_audit.categories`. Zdarzenia obowiązkowe:
  - net: `breakglass.enable|disable|shorten|expire|error|drift`, `ssh.login|logout|fail`, `sudo.command`, `admin.http`, `fw.apply|confirm|rollback`, `device.enroll|revoke`, `ansible.check|apply` (wpisy wywołuje playbook przez `legatto-audit append`);
  - updater: `update.fetched|verified|rejected|pending|approved|declined|installing|installed|rolled_back|rollback_failed|stale|clock_jump|autosecurity|attested|installed_yanked` (`installed_yanked` raz na zmianę stanu: zainstalowane wydanie zostało wycofane w indeksie);
  - console (pisze executor; konsola nie pisze audytu): `console.request`, `console.login`, `console.login_failed`, `console.contacts.set` (typ żądania w spoolu to `contacts.set`), `console.user.{add,remove,reset_totp,password,setup,setup_code,emergency_rotate}`;
  - egress: `egress.applied|widening_held|denied` (`denied` zbiorczo, liczniki — bez nazw hostów spoza allowlisty);
  - ops: `backup.pgdump`, `backup.restore_test`, `backup.recovery_pack`;
  - publicsite: `intake.quarantine`, `publish.deployed|failed`, `publish.worker_deployed|worker_failed|drift`.
- `legatto-audit-verify.timer` (co 5 min) uruchamia `legatto-audit verify` i odświeża `status/audit.json`. Kursory journald czytników (`legatto-audit-ssh`, `admin.http`): `/var/lib/legatto/audit/` (0700 root).
- Hasło konta `recovery` powstaje na serwerze przy instalacji do `/etc/legatto/secrets/recovery-password` (0400 root); czyta je tylko `legatto-recovery-pack`.
- `legatto-audit` CLI:
  - `append --cat C --event E --actor JSON [--node N] --params JSON` → stdout `{"seq":…,"hash":"…"}`;
  - `verify [--from SEQ] [--json]` → sprawdza cały łańcuch;
  - `head [--json]` → `{"seq":…,"hash":"…"}`; to samo trafia do `status/audit.json`.
  - Kody wyjścia: 0 OK, 2 błędne argumenty, 3 blokada zajęta po 10 s, 30 łańcuch uszkodzony (`verify`), 1 inny błąd.

### 4.3 Spool: office-console → executor

Panel działa jako `legatto-console` bez uprawnień, na gnieździe `/run/legatto/office-console.sock` tworzonym przez `legatto-console.socket` (root, `0660 root:caddy`). Każda akcja zmieniająca stan to plik żądania wykonywany przez `legatto-console-exec` (root, tor console), uruchamiany jednostką `legatto-console-exec.path` (`DirectoryNotEmpty=` na `incoming/`) → `legatto-console-exec.service`. `legatto-console-exec-maint.timer` co minutę wykonuje `prune` i `snapshot`.

Stan konsoli (pisze tylko executor, konsola czyta): `/var/lib/legatto/console/users.json` (rejestr użytkowników i hashe `hashlib.scrypt`, `0640 root:legatto-console`), `/var/lib/legatto/console/snapshot.json` (węzły tailnetu z `legatto-tailnet nodes --json` i lista personelu), `/var/lib/legatto/office/contacts.json` (kontakty incydentów: UODO, IOD; czyta też `legatto-recovery-pack`).

Katalogi (`legatto_paths.requests_*`):

| Katalog | Prawa | Kto |
|---|---|---|
| `incoming/` | `0730 root:legatto-console` | konsola zapisuje `<id>.json.tmp`, potem `rename` na `<id>.json` |
| `processing/` | `0700 root:root` | executor przenosi tu plik przed walidacją |
| `results/` | `0750 root:legatto-console`, pliki `0640` | executor zapisuje wynik; konsola tylko czyta |
| `archive/` | `0700 root:root` | żądanie po przetworzeniu, bez pola `auth` (retencja 30 dni) |

Żądanie (`legatto_requests.version: 1`, maks. 8192 B):

```json
{"v":1,"id":"01JDQ4Z6M3X8Y2K7T5R9W0A1BC","type":"update.approve",
 "ts":"2026-11-21T10:02:11Z",
 "actor":{"user":"szef-biura","ip":"fd7a:115c:a1e0::5"},
 "auth":{"method":"local-totp","totp":"493021"},
 "params":{"release":"1.5.0","manifest_sha256":"4b1e…","not_before":"2026-11-22T22:00:00Z"}}
```

Executor odrzuca żądanie (wynik `rejected`), gdy: plik > 8192 B albo nie jest JSON; `v` ≠ 1; `id` nie jest ULID albo ≠ nazwa pliku albo już był; `|now − ts| > 120 s`; `type` spoza listy; `params` niezgodne z tabelą niżej; użytkownik nie istnieje lub jest wyłączony; TOTP nie pasuje albo krok czasu ≤ ostatniego przyjętego (`/var/lib/legatto/console-auth/<user>.step`, anty-replay). Seed TOTP: `/etc/legatto/secrets/console-totp/<user>` (0400 root) — konsola go nie zna. `actor.node` uzupełnia executor z `tailscale whois --json <ip>`.

Typy (`legatto_requests.types`) i parametry:

| Typ | `params` | Wykonanie |
|---|---|---|
| `breakglass.enable` | `hours` 1–8, `reason` 10–500 znaków, czysty tekst | `legatto-breakglass enable` |
| `breakglass.disable` | `reason` 0–500 | `legatto-breakglass disable` |
| `update.approve` | `release`, `manifest_sha256`, opcjonalnie `not_before` (UTC) albo `install_now: true` („Zainstaluj teraz”; wyklucza `not_before`) | `legatto-update approve` (`install_now` → `--install-now`: pomija tylko okno instalacji, nigdy opóźnienia kanału liczone od first-seen, promocji, atestacji ani zgody na poszerzenie egress; updater sam uruchamia `run` w tle, wynik nie czeka na instalację) |
| `update.reject` | `release`, `manifest_sha256`, `reason` 0–500 | `legatto-update reject` |
| `update.rollback` | opcjonalnie `to` (semver) | `legatto-update rollback` |
| `update.autosecurity` | `enabled` bool | `legatto-update autosecurity` |
| `device.enroll` | `kind` `staff`\|`office-device`, `login` (dla `staff`) | `legatto-tailnet enroll` → wynik z jednorazowym kluczem pre-auth (TTL 30 min) |
| `device.revoke` | `node_id` | `legatto-tailnet revoke` |
| `staff.set` | `staff`: lista loginów `^[a-z][a-z0-9.-]{1,40}$` | `legatto-tailnet staff-set` + `legatto-policy apply` |
| `features.set` | `feature` ∈ `legatto_feature_names`, `enabled` bool, `ics_hosts` (dla `ics`) | zapis `features.json` + `legatto-egress apply` |
| `recovery.generate` | — | `legatto-recovery-pack generate` |
| `console.user.add` | `login`, `display_name` | nowy seed TOTP; wynik z URI `otpauth://` |
| `console.user.remove` | `login` (nie ostatni aktywny) | |
| `console.user.reset_totp` | `login` | nowy seed; wynik z URI |
| `console.user.password` | `login`, `scrypt`: `scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>` (executor wymaga n ≥ 2^15, r = 8, p = 1, sól ≥ 16 B, hash 64 B) | zapis do `users.json` |
| `console.login` | — | weryfikacja TOTP z anty-replay; audyt `console.login` albo `console.login_failed`; hasło sprawdza konsola z `users.json` przed złożeniem żądania |
| `contacts.set` | `uodo{…}`, `iod{…}` — pola tekstowe (nazwa, e-mail, telefon, ≤ 200 znaków każde) | zapis `contacts.json` |
| `console.setup` | `login`, `display_name`, `scrypt` (jak `console.user.password`); `auth` = `{"method":"setup-code","code":"…"}` zamiast TOTP | pierwsze konto panelu (przy przekazaniu serwera biuru). Executor przyjmuje tylko, gdy: nie ma żadnego aktywnego konta poza awaryjnym; istnieje niewykorzystany kod `setup-code` młodszy niż 24 h (porównanie z hashem scrypt, `hmac.compare_digest`); `actor.node` z `tailscale whois` ma tag `tag:office-device` (węzeł dostawcy w oknie break-glass nie może założyć konta); `login` ≠ `awaryjny`. Po użyciu kod jest kasowany. Wynik `sensitive` z URI `otpauth://`; audyt `console.user.setup` |

Konto awaryjne `awaryjny` (`legatto_requests.console_emergency_login`; poświadczenia tylko w pakiecie odzyskiwania) jest zarezerwowane: `console.user.add|remove|password|reset_totp` i `console.setup` go odrzucają; nie liczy się jako „aktywne konto” dla `console.setup`.

Wynik `results/<id>.json`:

```json
{"v":1,"id":"01JDQ4Z6M3X8Y2K7T5R9W0A1BC","type":"update.approve","status":"ok",
 "code":"approved","message":"Wydanie 1.5.0 zatwierdzone; instalacja w oknie 22:00–05:00.",
 "ts":"2026-11-21T10:02:12Z","audit_seq":1043,"data":{},"sensitive":false}
```

`status`: `ok|rejected|error`; `code`: krótki identyfikator maszynowy; `message`: po polsku, dla admina. Wynik z `sensitive: true` (klucz pre-auth, URI TOTP, hasło pakietu odzyskiwania) executor usuwa po 10 minutach. Każde przetworzone żądanie daje wpis audytu `console.request` (bez `auth`).

### 4.4 Pliki statusu JSON

Katalog `/var/lib/legatto/status/` (`0750 root:legatto-status`), pliki `<nazwa>.json` (`0640 root:legatto-status`), zapis atomowy (plik tymczasowy w tym samym katalogu, `fsync`, `rename`). Czytają: `legatto-health` (monitoring) i konsola. Wspólna koperta: `{"v":1,"component":"<nazwa>","ts":"<UTC>","ok":true|false, …}`. Czas zawsze `YYYY-MM-DDTHH:MM:SSZ`.

| Plik | Pisze (tor) | Pola poza kopertą |
|---|---|---|
| `update.json` | updater | `installed{version,sequence,manifest_sha256,installed_at}`, `channel`, `sig` (`ok\|bad\|none`), `upd` (enum jak w Kuma; `yanked` = zweryfikowany indeks oznacza zainstalowane wydanie jako wycofane — bez automatycznego rollbacku, serwer czeka na nowsze wydanie albo decyzję admina), `yanked` (bool), `yanked_reason` (tekst z podpisanego indeksu, jedna linia ≤ 500 znaków, `null` gdy nie dotyczy; nigdy nie trafia do Kuma), `auto_security{policy,admin_optout}`, `last_check{ts,ok_ts,ok,index_sequence,index_expires}` (`ts` — ostatnia próba, `ok_ts` — ostatni udany fetch+verify indeksu; z niego liczony `chk_age`), `pending[]{version,sequence,type,manifest_sha256,state,earliest_install_at,egress_widening,changelog_url}`; `state` ∈ `waiting-promotion\|waiting-delay\|waiting-approval\|waiting-window\|blocked-baseline\|ready\|rejected\|expired` |
| `breakglass.json` | net | `active`, `window_id`, `actor`, `reason`, `started_at`, `expires_at` |
| `audit.json` | net | `seq`, `head`, `verified_at`, `chain_ok` |
| `tls.json` | platform | `not_after`, `days_left`, `last_renew_at`, `state` (`ok\|fail`) |
| `egress.json` | egress | `mode` (`observe\|enforce`), `release`, `denied_5m`, `last_apply_at` |
| `backup.json` | ops | `pgdump{state,last_ok_at,last_run_at,bytes,sha256}`, `hetzner_window` (okno z inwentarza — znacznik, że Owner projektu Hetzner włączył backup) |
| `restore-test.json` | ops | `state` (`ok\|fail\|none`), `mode` (`local\|hetzner`), `last_run_at`, `hetzner_last_ok_at`, `duration_s`, `checks{<nazwa>:bool}` |
| `health.json` | ops | `status` (`up\|down`), `msg` (dokładnie to, co poszło do Kuma), `fields{…}` |
| `intake.json` | publicsite | `last_ok_at`, `backlog`, `failed`, `quarantined` |
| `publish.json` | publicsite | `state`, `last_ok_at`, `deployment_id` |
| `worker.json` | publicsite | `state`, `release`, `version_id`, `deployed_at` |

Szczegóły oczekujących wydań (changelog, różnica allowlisty egress) updater zapisuje w `/var/lib/legatto/update/pending/<wersja>.json` (`0640 root:legatto-console`).

### 4.5 Payload Uptime Kuma (bez PII)

`legatto-health` (ops) składa `msg` wyłącznie z kluczy `legatto_kuma_fields`; wartość niepasująca do wyrażenia zamieniana jest na `ERR`. Zbieranie działa jako root (`legatto-health collect` → `status/health.json`), wysyłka jako `legatto-mon` przez `127.0.0.1:4750` (`legatto-health push`), token z credstore `legatto-kuma-push-token`.

| Klucz | Źródło | Wyrażenie |
|---|---|---|
| `v` | `update.json` | `^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$` |
| `ch` | `policy.json` | `^(canary\|early\|stable)$` |
| `sig` | `update.json` | `^(ok\|bad\|none)$` |
| `chk_age` | `update.json` | `^[0-9]{1,8}$` (sekundy) |
| `upd` | `update.json` | `^(ok\|pending\|waiting\|installing\|failed\|rb\|rej\|vuln\|stale\|yanked\|blocked-baseline\|optout)$` |
| `disk`, `ram` | system | `^[0-9]{1,3}$` (%) |
| `bk`, `bk_age` | `backup.json` | `^(ok\|fail\|run\|none)$`, `^[0-9]{1,5}h$` |
| `rt` | `restore-test.json` | `^(ok\|fail\|none)/[0-9]{1,4}d$` |
| `err` | journald (app, functions, prio 0–3, 5 min) | `^[0-9]{1,6}$` |
| `ct`, `ctbad` | docker | `^[0-9]{1,2}/[0-9]{1,2}$`, lista nazw tylko z `legatto_compose_services` |
| `bg` | `breakglass.json` | `^[01]$` |
| `aseq`, `ahead` | `audit.json` | `^[0-9]{1,9}$`, `^[0-9a-f]{16}$` (kotwica łańcucha) |
| `cert` | `tls.json` | `^[0-9]{1,3}$` |
| `egress`, `eg_deny` | `egress.json` | `^(observe\|enforce)$`, `^[0-9]{1,6}$` |
| `in_age`, `in_q`, `in_fail`, `pub_age` | `intake.json`, `publish.json` | `^[0-9]{1,7}$` |

`status=down`, gdy: `sig=bad`; `upd` ∈ {`failed`,`rb`,`rej`,`vuln`,`stale`,`yanked`}; `chk_age` > 86400; kontener unhealthy; `bk_age` > 26 h; dysk > 90 %; `in_age` > 900; `cert` < 14; łańcuch audytu uszkodzony.

### 4.6 CLI narzędzi hosta

Wspólne zasady: `--json` → wynik na stdout jako jeden obiekt JSON; komunikaty dla ludzi na stderr; argument `--actor JSON` (obiekt `actor` jak w audycie) jest wymagany dla każdej komendy zmieniającej stan wywoływanej przez executor lub Ansible. Wspólne kody wyjścia: **0** OK / nic do zrobienia, **1** nieoczekiwany błąd, **2** błędne argumenty, **3** blokada zajęta (inna instancja), **4** niespełniony warunek wstępny (nie root, brak konfiguracji). Kody 10–49 są specyficzne dla narzędzia.

**`legatto-update`** (updater; root; `flock` na `/run/legatto/update.lock`):

| Podkomenda | Działanie |
|---|---|
| `run` | jednostka timera: fetch → verify → gate → instalacja, jeśli bramki otwarte; czekanie na bramkę to wynik 0 |
| `fetch` | pobranie indeksu, manifestów, atestacji, promocji i artefaktów do `downloads/`; zapis first-seen |
| `verify [--release V]` | reguły podpisów, hashy, anty-rollbacku, KRL, ważności indeksu |
| `status [--json]` | treść `update.json` |
| `approve --release V --manifest-sha256 H [--not-before T \| --install-now] --actor J` | zgoda admina (feature lub poszerzenie egress). `--install-now` („zainstaluj teraz”, spool `install_now`): wydanie instaluje się poza `install_window`, gdy tylko pozwolą promocja i opóźnienie kanału (reguły 4–5 bez zmian); gdy jest już gotowe, updater od razu uruchamia `legatto-update.service` (`systemctl start --no-block`). Wyklucza `--not-before` (kod 2). W `pending/<v>.json` widać `approval.install_now` |
| `reject --release V --manifest-sha256 H [--reason R] --actor J` | odrzucenie przez admina |
| `rollback [--to V] --actor J` | powrót obrazów, konfiguracji i binariów; baza bez zmian |
| `autosecurity --enabled true\|false --actor J` | opt-out admina (nie może włączyć, gdy `policy.auto_security=false`) |
| `bootstrap [--bundle DIR] --actor J` | pierwsza instalacja (rola updater woła ją tylko przy `legatto_update_bootstrap: true` z playbooka bootstrap i tylko, gdy nie ma zainstalowanego wydania). Pobiera z `policy.update_base_url` przez proxy egress hosta najnowsze wydanie, które kanał biura może zainstalować, z tymi samymi regułami weryfikacji co `run` (podpisy, hashe, KRL, promocja kanału; bez czekania na opóźnienie, zgodę i okno — nic jeszcze nie działa). `--bundle DIR` (lustro w układzie `legatto_release_layout`, kopiowane przez rolę z `legatto_update_bootstrap_bundle`) updater przyjmuje tylko przy `policy.env = test` |
| `attest --release V --report FILE` | tylko serwer canary: z raportu `scripts/verify.sh --release` bierze `result`, `failed_checks` i sha256 pliku; zapisuje `/var/lib/legatto/update/attest/<v>/canary.json` + `canary.json.canary.sig` + kopię raportu `verify-report.json` (klucz `/etc/legatto/secrets/update-canary-ed25519`, tworzony przez rolę updater tylko przy `legatto_channel: canary`); audyt `update.attested`. Serwer niczego nie wysyła: na hosting wydań pliki przenosi dostawca narzędziem `attest-publish` (§4.7) |

Raport testów akceptacyjnych canary (`--report FILE` narzędzia weryfikacji dostawcy), JSON: `{"v":1,"office":"<slug>","release":"<V>","manifest_sha256":"…","result":"PASS"|"FAIL","failed_checks":["<id>",…],"checks":[{"id":"<id>","result":"PASS"|"FAIL"|"SKIP","detail":"…"}],"started_at":"<UTC>","finished_at":"<UTC>"}`. `id` pasuje do `^[a-z0-9][a-z0-9._-]{0,80}$` (jak `failed_checks` w atestacji); `detail` bez danych osobowych.

Kody: 10 weryfikacja odrzucona (podpis, hash, anty-rollback, KRL, schemat), 11 bramka zamknięta (promocja, opóźnienie, zgoda, okno), 12 preflight niespełniony (miejsce, baseline/kontrakt), 13 instalacja nieudana i wycofana, 14 wycofanie nieudane (krytyczne), 15 indeks wygasły lub cofnięty (`stale`), 16 skok zegara.

**`legatto-breakglass`** (net; root):

| Podkomenda | Działanie |
|---|---|
| `enable --hours N --reason T --actor J` | okno dla `group:vendor`: stan, polityka Headscale, sety nft z timeoutem, audyt |
| `disable [--reason T] --actor J` | zamknięcie: polityka normal, flush setów, zerwanie sesji, audyt, podsumowanie |
| `shorten --minutes N [--reason T] --actor J` | skrócenie otwartego okna: nowy koniec = min(`expires_at`, teraz + N min), N od `legatto_breakglass.shorten_min_minutes` (2) do 480; nigdy nie wydłuża (gdy teraz + N ≥ `expires_at` — wynik 0, `changed: false`, bez audytu). Aktualizuje stan, `breakglass.json` i timeout setów nft, audyt `breakglass.shorten` (`window_id`, `minutes`, `reason`, `expires_at_before`, `expires_at`); sesji nie zrywa — zamyka `reconcile`/timeout nft o nowej godzinie. `--json`: `window_id`, `expires_at_before`, `expires_at`, `changed`, `window_seconds`. Służy m.in. `scripts/verify.sh --close-by expire` |
| `reconcile [--sets-only]` | timer co minutę: wygaśnięcie, odświeżenie `vendor4/6`, naprawa dryfu |
| `status [--json]` | treść `breakglass.json` |
| `summary --window ID [--json]` | podsumowanie okna dla biura |

Kody: 20 okno już aktywne (enable) / nieaktywne (disable, shorten), 21 asercja polityki nieudana (sety nft i tak odcinają dostawcę; wpis `breakglass.error`; przy `shorten` — nieudana aktualizacja setów nft, nowy koniec i tak obowiązuje w stanie i `reconcile`).

**`legatto-policy`** (net; root): `render`, `check`, `apply`, `assert [--expect normal|breakglass]`. Kody: 22 `headscale policy check` odrzucił politykę, 23 asercja PacketFilter nieudana.

**`legatto-tailnet`** (net; root): `enroll --kind staff|office-device [--login L] --json` (wynik zawiera klucz pre-auth — tylko do pliku wyniku executora), `revoke --node-id N`, `staff-set --file F`, `nodes --json`. Kod 24: login lub węzeł nie istnieje.

**`legatto-fw-apply NEW` / `legatto-fw-confirm NEW` / `legatto-fw-rollback`** (net; root): bezpieczna podmiana reguł z rollbackiem po 120 s (`legatto_breakglass.fw_confirm_timeout_seconds`). Kod 25: `nft -c` odrzucił plik.

**`legatto-egress`** (egress; root):

| Podkomenda | Działanie |
|---|---|
| `render --release-dir D --out DIR` | ACL Smokescreen (host i role), `egress.nft` z danych paczki, `features.json` i `pinned.json` |
| `check --dir DIR` | `nft -c`, walidacja ACL |
| `diff --from D1 --to D2 --json` | różnica skutecznej allowlisty; wynik `{"widening":bool,"added":[…],"removed":[…]}` |
| `apply --release-dir D` | render + check + atomowa podmiana + restart proxy |
| `selftest [--json]` | testy E1–E10 (część health checku wydania) |
| `status [--json] [--write]` | `--write`: `status/egress.json` (`denied_5m` z journald) i zbiorczy wpis `egress.denied`; uruchamia `legatto-egress-status.timer` co minutę |
| `validate-data (--egress-json F \| --base F --features F)` | walidacja danych allowlisty przed złożeniem paczki (używa `release/build.sh`); wejście tylko JSON (`--egress-json`: manifest albo sam obiekt `egress`); YAML z `bundle/egress/` konwertuje CI (`yq`) — serwer nie ma parsera YAML |

`apply` przyjmuje opcjonalny `--actor J` (zmiana z panelu: `features.set`). `pinned.json` nie jest w paczce: renderuje go rola `egress` z `legatto_egress_pinned`.

Kody: 40 `diff` wykrył poszerzenie (updater wstrzymuje wydanie do zgody), 41 wydanie usuwa wpis z `pinned.json`, 42 walidacja nieudana, 43 `selftest` nieudany.

**`legatto-console-exec`** (console; root): `process [--once]`, `prune`, `snapshot`, `setup-code [--json]` (dostawca w oknie break-glass przy przekazaniu serwera biuru; drukuje jednorazowy kod ważny 24 h, na dysku tylko hash scrypt; świadomy wyjątek od §1 pkt 6, jak `legatto-tailnet enroll --json`; audyt `console.user.setup_code` bez kodu), `emergency-credentials --json` (wywołuje wyłącznie `legatto-recovery-pack generate`; rotuje hasło i seed TOTP konta `awaryjny` i drukuje je tylko do strumienia pakietu, nigdy do logu; audyt `console.user.emergency_rotate` bez wartości). Kod 50: co najmniej jedno żądanie odrzucone (nie błąd jednostki — jednostka kończy się 0).

**`legatto-secrets`** (platform; root): `init` (tworzy brakujące sekrety w `/etc/legatto/secrets`, nigdy nie nadpisuje), `check --json` (prawa i obecność, bez wartości).

**`legatto-health`** (ops): `collect` (root), `push` (`legatto-mon`), `--dry-run` drukuje payload Kuma (dowód „bez PII” dla verify). **`legatto-pgdump run`** (ops; root): `pg_dump -Fc` do `/var/backups/legatto/pg/`, rotacja, `backup.json`; uruchamiany `legatto_pgdump_lead_minutes` przed oknem backupu Hetzner. **`legatto-restore-test run [--report FILE]`** (ops; root): odtworzenie ostatniego dumpu do jednorazowego `supabase/postgres` w sieci `internal`, asercje, `restore-test.json`. **`legatto-recovery-pack generate|verify FILE`** (ops; root).

**`legatto-intake fetch|process|selftest`**, **`legatto-site-publish run`**, **`legatto-worker-deploy --release-dir D`** (publicsite; root, uruchamiają obraz aplikacji z paczki po digest). Intake ma dwa procesy: `fetch` — sieć `legatto-egress-intake`, token Queues, bez klucza i bez bazy, zapis szyfrogramów do `/var/lib/legatto/intake/inbox/`; `process` — sieć `legatto-int`, klucz X25519 i rola DB `legatto_intake`, bez sieci zewnętrznej, wynik do `acks/`; `fetch` potwierdza w kolejce tylko identyfikatory z `acks/`. `legatto-worker-deploy` wywołuje updater po zielonym health checku, gdy manifest ma artefakt `worker-bundle`; kod 60 = wdrożenie Workera nieudane i wycofane w Cloudflare (aplikacja na serwerze zostaje).

**`legatto-cf-bootstrap`** (publicsite; root; tylko z roli `cf_bootstrap` w oknie break-glass): jednorazowy token Cloudflare biura (TTL 24 h) wyłącznie na stdin; tworzy kolejki, Turnstile, projekt Pages, tokeny biura (Queues, Pages/Workers, DNS-01 strefy) z filtrem IP i zapisuje je do `/etc/credstore.encrypted/` (`legatto_credentials`). Żaden token nie wraca do kontrolera ani do logu. Jawne identyfikatory (konto, strefa, kolejki, sitekey) trafiają do `/etc/legatto/publicsite/cloudflare.json`. Pozostałe ścieżki toru: `intake_etc`, `cf_ca_bundle`, `publish_state`, `worker_state` w `legatto_paths`.

Pełne podkomendy publicsite (kody wyjścia są per narzędzie; wspólne 0–4 jak wyżej):
- `legatto-intake fetch|process|selftest|status|keygen [--rotate]|db-role --role legatto_intake|legatto_publisher` — `db-role` generuje hasło roli na serwerze i przekazuje do Postgresa tylko weryfikator SCRAM przez `docker exec -i supabase-db psql` na stdin (hasło nigdy w argv ani w logu). `selftest [--mode ping|verify] [--marker HEX32] [--wait S]` — podpisany POST `/api/selftest` przez Workera; `--mode verify` dodatkowo zakłada w CRM sprawę „[VERIFY] <marker>”. `--wait S` w ciągu S sekund dowodzi trzech rzeczy: (1) wiadomość pobrana z kolejki tokenem Queues to szyfrogram stałej wielkości (25 278 B, magic `LGF1`) bez znacznika i tekstu ramki — bramka hosta zachowuje kopię wyłącznie kopert self-testu (rodzaj 2); (2) procesor zapisał ją i zgłosił znacznik; (3) Cloudflare przyjął ack (wiadomość znikła z kolejki). Wynik JSON: `queue`, `received`, `removed` (`accepted`|`unconfirmed`|`retry`). Kody: 30 = nie dotarło albo nie usunięte w czasie, 31 = klucz istnieje (`keygen`), 32 = dowód nieudany (jawny tekst w kolejce albo ack nieprzyjęty). Test akceptacyjny formularza (kryterium `form.selftest`) wywołuje `selftest --mode verify --wait 300`, sprawdza sprawę w CRM i potem ją usuwa;
- `legatto-site-publish run|drift|status|guard --dir D` — kod 20: strażnik „zero adresu” odrzucił build;
- `legatto-worker-deploy --release-dir D [--actor J] [--no-selftest] [--selftest-timeout S] [--force]`, `legatto-worker-deploy status` — kody 0/1/2/3/4 jak wspólne, 60 = wdrożenie nieudane i wycofane w Cloudflare. `--no-selftest` i `--force` są tylko do pracy w oknie break-glass; updater ich nie używa.

### 4.7 Łańcuch wydań

Dokumenty i schematy (`release/schema/`, JSON Schema 2020-12):

| Dokument | Schemat | Ścieżka względem `legatto_update_base_url` | Namespace sshsig | Podpisuje |
|---|---|---|---|---|
| indeks | `index.schema.json` (`legatto-index/1`) | `index.json` | `legatto-index` | klucze wydań |
| manifest | `manifest.schema.json` (`legatto-release/1`) | `releases/<v>/manifest.json` | `legatto-release` | klucze wydań |
| atestacja canary | `attestation.schema.json` (`legatto-canary/1`) | `releases/<v>/attest/canary.json` | `legatto-canary` | klucz programowy serwera canary |
| promocja | `promotion.schema.json` (`legatto-promote/1`) | `releases/<v>/promote/<early\|stable>.json` | `legatto-promote` | klucze wydań |
| KRL | format OpenSSH KRL | `revoked.krl` | `legatto-revoke` | klucze wydań |
| polityka serwera | `policy.schema.json` (`legatto-policy/1`) | lokalnie `/etc/legatto/update/policy.json` | — (Ansible, break-glass) | — |
| plan Ansible dostawcy | — (prywatne narzędzia dostawcy) | poza serwerem | `legatto-plan` | klucz operatora |

**Podpisy.** `ssh-keygen -Y sign -f <klucz> -n <namespace> <plik>`; plik podpisu leży obok dokumentu jako `<plik>.<signer-id>.sig`, gdzie `signer-id` to część lokalna principala (`manifest.json.release-a.sig`). Weryfikacja na serwerze wyłącznie OpenSSH z Ubuntu: dla każdego `*.sig` `ssh-keygen -Y find-principals`, potem `ssh-keygen -Y verify -f /etc/legatto/update/allowed_signers -I <principal> -n <namespace> -s <sig> < <plik>`; podpis z kluczem w KRL nie liczy się. Wymagana liczba podpisów od **różnych** principali: `policy.json.signatures_required` (dziś 1).

`allowed_signers` (`trust/allowed_signers`; na serwerze zmiana tylko w oknie break-glass):

```
release-a@legatto.pl namespaces="legatto-release,legatto-promote,legatto-index,legatto-revoke" sk-ssh-ed25519@openssh.com AAAA…
release-b@legatto.pl namespaces="legatto-release,legatto-promote,legatto-index,legatto-revoke" sk-ssh-ed25519@openssh.com AAAA…
canary@legatto.pl namespaces="legatto-canary" ssh-ed25519 AAAA…
```

Dziś istnieje jeden klucz sprzętowy: `release-b` (zapasowy offline) zostanie dopisany przed pierwszą instalacją produkcyjną. Testy używają programowych kluczy ed25519 generowanych w teście; `allowed_signers` z kluczami testowymi istnieje tylko na serwerach z `legatto_env: test`.

**Reguły serwera** (updater; dokumenty mogą je tylko zaostrzyć):
1. Indeks: podpisy ważne, `sequence` ≥ ostatnio widzianego, `expires` w przyszłości, `expires − issued_at` ≤ `index_max_validity_days`; inaczej `upd=stale`, nic się nie instaluje.
2. Manifest: podpisy, `sha256` manifestu równy wpisowi w indeksie, zgodność ze schematem, `expires` w przyszłości, `sequence` > zainstalowanego i `version` > zainstalowanej (poza `rollback` admina), `min_installed` i `min_contract_version` spełnione.
3. Artefakty: rozmiar i `sha256` każdego pliku; digesty po `docker load` równe `images[].digest`; `binary` ∈ `legatto_binary_allowlist`, `deb` ∈ `legatto_deb_allowlist`; pliki `config` tylko dla applierów z `legatto_appliers` i ich stałych celów. Artefakt o tym samym `sha256` co plik już na serwerze (zachowane wydanie `releases/<v>/artifacts/` albo pobrany inny kandydat) updater dowiązuje twardo zamiast pobierać i przed użyciem liczy jego `sha256` od nowa; archiwum obrazów nie jest ładowane (`docker load`), gdy wszystkie jego obrazy `repo@digest` już są w magazynie Dockera.
4. Kanał `canary` instaluje każde poprawne wydanie. `early` wymaga `promote/early.json`, `stable` — `promote/stable.json` i ważnego `promote/early.json`; oba wiążą `manifest_sha256` i `canary_attestation_sha256` atestacji z wynikiem `PASS` i ważnym podpisem canary. Security przechodzi tę samą drogę.
5. Opóźnienia liczone od lokalnego first-seen dokumentu promocji: `min_delay_hours[type][channel]` z `policy.json` (min. feature 24/48 h, security 2/4 h); `promoted_at` niczego nie przyspiesza. Skok zegara > `clock_jump_block_minutes` blokuje instalację. `legatto-update.timer` sprawdza indeks co `legatto_update_timer_interval[kanał]` z rozrzutem `legatto_update_timer_jitter[kanał]` (canary 15 min, early i stable 1 h); interwał wpływa tylko na to, jak szybko serwer zauważy dokument, nie na opóźnienia.
6. `type=feature` zawsze czeka na `update.approve`. Każde poszerzenie egress (`legatto-egress diff` → 40) wstrzymuje całe wydanie do zgody admina, niezależnie od typu. `security` instaluje się sam w `install_window`, gdy `auto_security` i brak opt-outu admina.
7. Health check (`healthchecks` z manifestu, limit `health_timeout_seconds`); porażka → auto-rollback obrazów, konfiguracji i binariów, baza bez zmian.

**Budowa i publikacja.** Paczkę składa `release/build.sh` z tego repozytorium (commit `legatto-node` + wydanie aplikacji z `release/app.lock`; `manifest.source` = `node` i `app`); CI (`release-build.yml`) buduje z tego samego commita wzorzec z atestacją pochodzenia, dostawca podpisuje tylko zgodny manifest. Archiwum obrazu o niezmienionym `ref`+`digest` ma w kolejnych wydaniach te same bajty (sha256). Narzędzia publikacji dostawcy (prywatne; serwer tylko czyta): obiekty w `releases/<v>/` są niezmienne (`If-None-Match: *` i blokada bucketu R2 na `v1/releases/`); obiekt identyczny z artefaktem wcześniejszego wydania jest kopiowany po stronie R2 (`CopyObject`), nie wysyłany ponownie. `index.json` i `transparency.log` zmieniają się przez compare-and-swap. `transparency.log` to JSONL z łańcuchem hashy; każda zmiana dopisuje do niego wpis: `release.published`, `release.attested`, `release.promoted`, `release.yanked`, `index.resigned`, `index.published`.
- `attest-publish`: pobiera atestację z serwera canary (`legatto_paths.update_attest/<v>/`, SSH w oknie break-glass canary) albo z kopii lokalnej. Sprawdza schemat, podpis `canary@` (`legatto-canary`, `allowed_signers`), zgodność `manifest_sha256`/`version`/`sequence` z opublikowanym, podpisanym manifestem i wpisem indeksu oraz `verify_report_sha256`. Wgrywa `attest/verify-report.json`, `attest/canary.json.canary.sig` i na końcu `attest/canary.json`. Indeksu nie zmienia: `attestation_sha256` wpisuje dopiero promocja. Opublikowany wynik `FAIL` jest ostateczny dla tej wersji.
- `resign-index`: nowy podpis indeksu bez zmian w wydaniach (`sequence` + 1, `issued_at` = teraz, `expires` = `issued_at` + `legatto_index_validity_days`). Dostawca uruchamia go co najmniej raz w miesiącu, gdy nie było publikacji ani promocji, i po wygaśnięciu indeksu (`upd=stale`).
- `yank`: ustawia `yanked: true` i `yanked_reason` (publiczny, ≤ 500 znaków). Wpis zostaje w indeksie, więc wersji ani `sequence` nie da się użyć ponownie; flagi nie da się cofnąć. Updater pomija wpisy `yanked` (nie pobiera ich i nie instaluje na żadnym kanale), a promocja i `attest-publish` ich odmawiają. Serwer, który już zainstalował wycofane wydanie, zostaje na nim do następnego (zdalnego rollbacku nie ma) i dziś nie zgłasza tego stanu osobno.

### 4.8 Paczka i appliery

Paczka to katalog `releases/<v>/` z płaskimi plikami wymienionymi w `manifest.artifacts` (nazwy bez katalogów). Rodzaje: `legatto_artifact_kinds`. Kolejność przełączania: `legatto_appliers`. Stałe cele applierów (kod updatera, nie manifest):

| Applier | Cel | Walidator (przed jakąkolwiek zmianą) |
|---|---|---|
| `sql-migrations` | migrator (`docker compose run --rm migrator`) | nazwy rosnące, brak zastosowanych plików ze zmienionym hashem |
| `deb` | `apt-get install ./<plik>.deb` | `Package` z `dpkg-deb -f` ∈ allowlista, wersja = manifest |
| `binary` | `/opt/legatto/bin/<v>/<nazwa>`, symlink `bin/current` | sha256, `--version`; dla caddy `caddy validate` |
| `env-template` | `/run/legatto/env/*.env` (przez `legatto-secrets-render`) | tylko placeholdery z §4.1 i znane sekrety |
| `egress` | `legatto-egress apply` | `legatto-egress check`, `diff` |
| `systemd-unit` | `/etc/systemd/system/legatto-{stack,cron@,cron-*,secrets-render}.*` | `systemd-analyze verify`; każde `Exec*=` tylko z `/opt/legatto/sbin/` (narzędzia Ansible) albo `/opt/legatto/bin/current/`, bez powłoki (`/bin/sh -c`) i bez prefiksów `+`/`!`; jako root (bez `User=` lub `User=root`) mogą działać wyłącznie `legatto-stack.service` i `legatto-secrets-render.*`, a ich `Exec*=` muszą wskazywać `/opt/legatto/sbin/` — nigdy plik z paczki (`/opt/legatto/current/`, `/opt/legatto/bin/`); `legatto-cron@.service` ma `DynamicUser=yes`; pozostałe jednostki mają `User=` inny niż root; zakaz `PermissionsStartOnly` i rozszerzania `AmbientCapabilities`/`CapabilityBoundingSet`. `legatto-acme.*` instaluje Ansible (nie paczka) |
| `caddy-site` | `/etc/caddy/sites.d/*.caddy` | `caddy validate` z globalnym Caddyfile; zakaz `bind` i listenerów |
| `functions` | obraz `functions` (bez montowań) | struktura i rozmiar |
| `compose` | `/opt/legatto/releases/<v>/compose/`, symlink `current` | `docker compose config -q`; zakaz `privileged`, `network_mode: host`, `pid: host`, `ports` poza `127.0.0.1`, bind-mountów spoza allowlisty, `cap_add` spoza listy, sieci spoza `legatto_docker_networks`; `extra_hosts` tylko dokładnie te pary: `auth` → `host.docker.internal:172.30.1.10` (`legatto_ip_int_net.app`), `db` → `${LEGATTO_HOST_CRM}:${LEGATTO_TS_IP4}` (hairpin pg_net) |
| `worker` | `legatto-worker-deploy` | hash `worker.entry_sha256` |

Nigdy przez paczkę (tylko dostawca w oknie break-glass otwartym przez biuro): `allowed_signers`, `policy.json`, KRL na start, polityka Headscale, nftables, sshd, sudoers, auditd, globalny Caddyfile, `legatto-acme`, jednostki i ACL bazowe proxy hosta, `office.env`, `pinned.json`, sekrety, sam updater i executor.

Docker daemon (`/etc/docker/daemon.json`, rola `docker`, platform): `"bridge":"none"`, `"ip":"127.0.0.1"`, `default-network-opts.bridge.com.docker.network.bridge.host_binding_ipv4 = 127.0.0.1`, `"iptables":true`, `"ip6tables":true`, `"live-restore":true`, `"log-driver":"journald"`, `"no-new-privileges":true`, `"dns":["172.30.0.53"]` (`legatto_ip_host_net.dns_blackhole`), `"features":{"containerd-snapshotter":true}` (obrazy `repo@sha256` z `docker load` przy `pull_policy: never`). Tabela `inet legatto` (net) wystawia łańcuchy `egress_out` i `egress_fwd`, które wypełnia `/etc/nftables.d/egress.nft` (egress).

Stałe adresy w `legatto-int`: `legatto_ip_int_net` (app `172.30.1.10`; pula dynamiczna `172.30.1.128/25`). Kontener `auth` ma `extra_hosts: host.docker.internal:172.30.1.10`, a hook wysyłki e-maili to `http://host.docker.internal:3001/_internal/auth-hooks/send-email` — GoTrue przyjmuje `http://` tylko dla localhost i `host.docker.internal`.

### 4.10 Sekrety

- Repozytorium nie zawiera żadnych sekretów. Poświadczenia usług zewnętrznych dostawcy (dziś tylko token push monitoringu) są w jego prywatnym magazynie (sops) i nie trafiają na serwer w jawnej postaci poza credstore systemd.
- **Sekrety serwera** powstają na serwerze (`legatto-secrets init`, `cf_bootstrap`, `legatto-intake keygen`) w `/etc/legatto/secrets/` (0700/0400) albo w `/etc/credstore.encrypted/` (`legatto_credentials`, `LoadCredentialEncrypted=`). Token Cloudflare biura i token DNS-01 tworzy `cf_bootstrap` tokenem jednorazowym (TTL 24 h) podanym interaktywnie; nie trafiają do magazynu dostawcy.
- Klucz pól PII: `/run/legatto/keys/pii_field_key` (tmpfs), do kontenera `app` jako compose secret.

## 6. Testy

Każdy katalog `tests/<obszar>/` ma wykonywalny `run.sh` (kod 0 = PASS), działający na samym tym repozytorium, bez sekretów i bez Ansible; Docker dozwolony (obrazy po digest). Klucze w testach: programowe ed25519 tworzone w katalogu tymczasowym. `tests/run.sh` uruchamia wszystkie obszary.

- **net:** `legatto-audit` (append, verify, wykrycie modyfikacji, usunięcia i zamiany wpisów, równoległe zapisy), maszyna stanów `legatto-breakglass` z atrapami headscale/nft, `legatto-policy render` na plikach wzorcowych, `legatto-fw`, `legatto-tailnet`, zgodność stałych z kontraktem.
- **platform:** kopia upstream Supabase zgodna z tree hash, `docker compose config` upstream + override (Studio, postgres-meta, imgproxy i supavisor tylko w profilu `disabled`, bez obrazów w paczce), walidatory compose/unit/strony Caddy, szablony env, narzędzia `legatto-{secrets,acme,stack}`, jednostki z `bundle/systemd`.
- **updater:** zły podpis, zły namespace, klucz w KRL, za mało podpisów, zmieniony artefakt i digest, starsze wydanie, brak promocji, niespełnione opóźnienie, feature i poszerzenie egress bez zgody, wygasły indeks, skok zegara, nieudany health check → rollback, bootstrap z serwera wydań (promocja kanału, `--bundle` tylko w teście), ponowne użycie niezmienionych archiwów obrazów bez `docker load`, „zainstaluj teraz” (pomija tylko okno).
- **console:** wektory RFC 6238, anty-replay TOTP, scrypt, walidacja żądań spoolu, sesje i CSRF panelu, enkoder QR.
- **publicsite:** Worker (rozmiar koperty, Turnstile, podpis, selftest), strażnik „zero adresu", dwuprocesowy intake na atrapie kolejki.
- **ops:** `legatto-health` (pola Kuma tylko z allowlisty, test negatywny z danymi osobowymi w logach), `legatto-recovery-pack`, `legatto-pgdump` i `legatto-restore-test`.
- **egress:** render ACL i nft, `diff` (poszerzenie vs zawężenie, wpisy przypięte, wpisy IP), Smokescreen allow/deny.
- **release:** dobre i złe dokumenty każdego schematu z `release/schema/` (+ referencyjny `jsonschema`, gdy dostępny); `release/lib/relcore.py`: łańcuch `transparency.log`, semver, `allowed_signers`, magazyn plikowy i R2 (atrapa S3: `If-None-Match`/`If-Match`, HEAD z `x-amz-meta-sha256`, kopia po stronie serwera, blokada bucketu 409); `release/build.sh` na atrapie repozytorium: pełna paczka zgodna ze schematem, `manifest.source` = commit node + wydanie aplikacji, budowa jak w CI (bez pamięci obrazów) równa poza bajtami archiwów obrazów, ponowne użycie archiwów o niezmienionym digest z pamięci lokalnej i z opublikowanego wydania (sha256 z podpisanego manifestu, podmienione archiwum odrzucone), odmowy (brudne drzewo, istniejący katalog, brak specyfikacji).
