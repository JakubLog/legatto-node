# Przekazanie systemu biuru

Dokument dla posła i admina biura. Opisuje, co biuro dostaje, jak przechowywać pakiet odzyskiwania i co można zrobić samodzielnie w panelu biura. Model zaufania: `docs/SECURITY.md`.

## 1. Co biuro dostaje

| Element | Gdzie | Kto ma dostęp |
|---|---|---|
| Serwer (VPS) z CRM Legatto | projekt Hetzner Cloud biura — biuro jest właścicielem (Owner) | biuro; dostawca tylko w oknie dostępu serwisowego otwartym przez biuro |
| Prywatna sieć biura (tailnet, WireGuard) | serwer działa jako koordynator pod `vpn.<domena>` | urządzenia dodane przez biuro w panelu |
| CRM | `https://app.<domena>` — tylko z urządzeń w sieci biura | personel z kontem w CRM |
| Panel biura | `https://admin.app.<domena>/console/` — tylko z **urządzeń biura** | konta panelu (hasło + kod TOTP) |
| Strona posła i formularz kontaktowy | `https://<domena>` — Cloudflare Pages i Worker na koncie Cloudflare biura | publicznie; treść formularza szyfruje przeglądarka wyborcy kluczem biura |
| Pakiet odzyskiwania | plik `.age` + karta do wydruku + hasło | tylko biuro |
| Backup | wbudowany backup Hetzner w projekcie biura + ręczny eksport posła | biuro |

Dostawca po instalacji nie ma: członkostwa w koncie Cloudflare biura, roli w projekcie Hetzner, dostępu SSH ani dostępu do panelu poza oknem, które otworzy biuro. Dostawca widzi tylko status techniczny serwera w swoim monitoringu (bez danych osobowych): wersję, wynik weryfikacji podpisu, dysk, wiek kopii, liczniki.

## 2. Pakiet odzyskiwania

### 2.1 Co zawiera

Pakiet powstaje na serwerze i nie przechodzi przez dostawcę. Zawiera:

- konto awaryjne panelu `awaryjny` (hasło i seed TOTP; każde wygenerowanie nowego pakietu je zmienia i unieważnia poprzednie);
- hasło konta `recovery`, które działa wyłącznie na konsoli VPS w Hetzner (`sudo` z hasłem);
- klucz prywatny formularza (X25519) — bez niego nie da się odczytać zgłoszeń z kolejki;
- klucz główny Vault (pgsodium) i klucz pól danych osobowych;
- kontakty incydentów (karta).

Pakiet jest zaszyfrowany (`age`, hasło z 10 słów). Karta do wydruku zawiera szyfrogram jako kody QR i ponumerowane linie tekstu z sumą kontrolną — **bez hasła**.

### 2.2 Jak wygenerować

Panel → Pakiet odzyskiwania → „Wygeneruj nowy pakiet" (kod TOTP). Na stronie wyniku:

1. Zapisz hasło pakietu na papierze. Hasło pokazuje się **tylko raz**.
2. Pobierz plik pakietu i kartę do wydruku.
3. Pliki i hasło znikają z serwera po 10 minutach.

Generuj nowy pakiet po każdej zmianie kont panelu i kontaktów incydentów, po odzyskaniu dostępu z konta awaryjnego oraz co najmniej raz w roku.

### 2.3 Jak przechowywać

- Plik pakietu na **dwóch nośnikach** (np. dwa pendrive'y), w dwóch różnych miejscach.
- Karta wydrukowana i przechowywana razem z jednym z nośników (np. w sejfie biura).
- **Hasło osobno**, u innej osoby niż nośniki (np. u posła albo w sejfie bankowym).
- Nie wysyłaj hasła e-mailem ani SMS-em. Nie trzymaj hasła w tym samym menedżerze haseł co nośniki.
- Po wygenerowaniu nowego pakietu zniszcz stare nośniki i karty: stare konto awaryjne już nie działa, ale klucze danych w starym pakiecie nadal są aktualne, dopóki ich nie zmieniono.

Odszyfrowanie poza serwerem: pakiet to plik `age` z hasłem (`age -d -o pakiet.tar.gz <plik>.age`, program pyta o hasło). Sprawdzenie, czy klucze w pakiecie są aktualne, wykonuje na serwerze `legatto-recovery-pack verify` (root, w oknie serwisowym albo z konsoli VPS kontem `recovery`).

### 2.4 Kiedy go użyć

- Utrata wszystkich kont panelu: zaloguj się do panelu kontem `awaryjny` z urządzenia biura.
- Utrata wszystkich urządzeń biura: konsola VPS w Hetzner → konto `recovery` → rejestracja nowego urządzenia (§2.5).
- Utrata serwera i backupu: klucz formularza jest jedyną drogą do odczytania zgłoszeń, które czekają w kolejce Cloudflare (retencja 14 dni). Repo nie ma dziś narzędzia do importu tego klucza ani do odczytu kolejki poza serwerem biura — odzyskanie zgłoszeń wymaga pracy dostawcy.

### 2.5 Dostęp awaryjny z konsoli VPS

Gdy w tailnecie nie zostało żadne urządzenie biura albo panel nie działa:

1. Zaloguj się w Hetzner Console (biuro jest Ownerem projektu) → serwer → **Console**, użytkownik `recovery`, hasło z pakietu odzyskiwania.
2. Rejestracja nowego urządzenia biura:
   ```sh
   sudo legatto-tailnet enroll --kind office-device --actor '{"kind":"office-admin","id":"recovery"}' --json
   ```
   Wynik zawiera `login_server` i jednorazowy `key` (ważny 30 min). Dalej jak w `docs/ONBOARDING-DEVICE.md` §4 (polecenie `tailscale up` na komputerze).
3. Okno serwisowe dla dostawcy, gdy panel nie działa:
   ```sh
   sudo legatto-breakglass enable --hours 4 --reason "awaria panelu, prośba biura" --actor '{"kind":"office-admin","id":"recovery"}'
   ```
4. Po odzyskaniu dostępu wygeneruj w panelu nowy pakiet odzyskiwania (poprzednie konto awaryjne traci ważność).

## 3. Panel biura

Adres: `https://admin.app.<domena>/console/`. Otwiera się tylko z urządzenia biura w sieci biura (urządzenie pracownika ma dostęp tylko do CRM). Logowanie: login, hasło, kod TOTP. Sesja wygasa po 15 min bezczynności, najpóźniej po 8 h. Pięć błędnych kodów TOTP w 15 min blokuje konto.

Pierwsze konto zakłada biuro przy instalacji kodem jednorazowym od dostawcy (`/console/konfiguracja`, ważny 24 h, tylko z urządzenia biura).

| Strona | Co można zrobić |
|---|---|
| Status | stan aktualizacji, dostępu serwisowego, kopii bazy, testu odtworzenia, formularza, publikacji strony, certyfikatu, ruchu wychodzącego, dziennika audytu |
| Wydania | zainstalowana wersja i kanał; oczekujące wydania z opisem zmian, poprawkami bezpieczeństwa i poszerzeniami ruchu wychodzącego; zatwierdzenie (w oknie nocnym, opcjonalnie „nie wcześniej niż", albo „Zainstaluj teraz"), odrzucenie, wycofanie, włączenie i wyłączenie automatycznych poprawek bezpieczeństwa |
| Dostęp serwisowy | otwarcie i zamknięcie okna dla dostawcy; podsumowania okien (logowania SSH, polecenia sudo, uruchomienia Ansible, spójność dziennika) |
| Funkcje | włączanie i wyłączanie funkcji z ruchem zewnętrznym (§6) |
| Urządzenia | klucze rejestracji urządzeń (z kodami QR), lista urządzeń, usuwanie, lista personelu |
| Pakiet odzyskiwania | §2 |
| Kontakty incydentów | osoby zgłaszające naruszenia do UODO, zastępca, IOD (§7) |
| Konta panelu | dodawanie kont (hasło startowe + QR do TOTP), nowy kod TOTP, hasło tymczasowe, usuwanie; zmiana własnego hasła |

Każda akcja zmieniająca stan wymaga kodu TOTP i trafia do dziennika audytu z nazwą urządzenia, z którego ją wykonano.

## 4. Dostęp serwisowy (break-glass)

Domyślnie dostawca **nie ma** dostępu do serwera. Gdy potrzebna jest praca serwisowa (aktualizacja konfiguracji, awaria, test odtworzenia):

1. Dostawca prosi o okno i podaje powód.
2. Panel → Dostęp serwisowy → wybierz czas (1–8 h), wpisz powód (10–500 znaków; będzie widoczny w dzienniku) → „Otwórz dostęp serwisowy" + kod TOTP.
3. Okno zamyka się samo po czasie. Możesz je zamknąć wcześniej: „Zamknij dostęp teraz" — zamknięcie zrywa trwające sesje.
4. Po zamknięciu w tabeli „Okna dostępu i podsumowania" sprawdź: kto się logował, jakie polecenia wykonał, czy uruchamiano Ansible i czy dziennik jest spójny.

W oknie dostawca ma pełne uprawnienia administratora serwera. Ochroną jest wtedy Twoja zgoda, limit czasu i zapis wszystkiego, co zrobi.

Gdy panel nie działa, okno można otworzyć z konsoli VPS kontem `recovery` (§2.5).

## 5. Wydania i aktualizacje

- **Poprawki bezpieczeństwa** (`security`) instalują się same w nocnym oknie instalacji, po przejściu przez serwer testowy dostawcy i minimalnych opóźnieniach (biura pilotażowe ≥ 2 h, pozostałe ≥ 4 h od zobaczenia wydania). Możesz wyłączyć automat (Wydania → „Wyłącz automatyczne poprawki"); dostawca widzi to w monitoringu, a każda poprawka będzie czekać na Twoją zgodę.
- **Zmiany funkcjonalne** (`feature`) **nigdy nie instalują się bez Twojej zgody.** Przed zatwierdzeniem przeczytaj „Opis zmian" i sprawdź stan „czeka na Twoją decyzję". Zatwierdzone wydanie instaluje się w najbliższym oknie instalacji (albo nie wcześniej niż wskazany czas). „Zatwierdź i zainstaluj teraz" pomija tylko nocne okno: instalacja rusza od razu, ale nie wcześniej niż po obowiązkowym opóźnieniu kanału („Najwcześniejsza instalacja"); na kilka minut CRM jest wtedy niedostępny — wybieraj to poza godzinami pracy biura albo po uprzedzeniu zespołu.
- **Poszerzenie ruchu wychodzącego.** Jeśli wydanie dodaje nowy adres zewnętrzny, panel pokazuje tabelę „Poszerzenie ruchu wychodzącego — wymaga Twojej zgody" (rola, host, port). Bez Twojej zgody nie zainstaluje się całe wydanie, także poprawka bezpieczeństwa.
- **Odrzucenie** — „Odrzuć wydanie" z powodem; dostawca zobaczy to w monitoringu.
- **Wycofanie** — Wydania → „Wycofaj wydanie" przywraca poprzednie obrazy, konfigurację i programy; baza danych zostaje bez zmian. Nieudana instalacja wycofuje się sama.
- Stan „zablokowane — wymaga prac serwisowych" oznacza, że wydanie potrzebuje zmiany, którą wolno zrobić tylko w oknie dostępu serwisowego.

## 6. Backup i eksport danych

### 6.1 Backup Hetzner (włącza biuro)

Jedyną kopią poza serwerem jest wbudowany backup Hetzner: 7 dziennych obrazów całego dysku w projekcie biura.

1. Konsola Hetzner → serwer → Backups → włącz (biuro jako Owner; dostawca nie ma tokenu ani roli w projekcie).
2. Przekaż dostawcy okno backupu, które pokazuje Hetzner (np. `22-02` UTC). Serwer wykonuje spójny zrzut bazy 60 min przed tym oknem, więc każdy obraz zawiera aktualną kopię bazy.
3. Bez włączonego backupu monitoring pokazuje brak kopii i alarm.

Co miesiąc serwer sam sprawdza, czy ostatni zrzut bazy daje się odtworzyć. Okresowo dostawca sprawdza, czy daje się odtworzyć obraz Hetzner: biuro otwiera okno serwisowe i tworzy **tymczasowy** token API Hetzner, który dostawca wpisuje w test na osobnym, odizolowanym klonie serwera; po teście klon jest usuwany, a biuro usuwa token.

Świadomie przyjęte ograniczenia: kopie nie są szyfrowane kluczem biura (Hetzner ma do nich dostęp), są u tego samego dostawcy i na tym samym koncie co serwer, nie ma kopii tygodniowych ani miesięcznych. Szczegóły: `docs/SECURITY.md` §7.

### 6.2 Ręczny eksport danych posła

Niezależnie od backupu poseł może pobrać dane z CRM: strona eksportu danych w CRM, dostępna wyłącznie pod `https://admin.app.<domena>` (z urządzenia biura), dla posła z włączonym 2FA. Wynik to plik ZIP chroniony hasłem (AES-256), bez sekretów; każdy eksport zapisuje się w dzienniku audytu aplikacji. Zalecenie: eksport co miesiąc, przechowywany offline jak pakiet odzyskiwania.

## 7. Kontakty incydentów

Biuro jest **administratorem danych** i samo zgłasza naruszenia ochrony danych osobowych do UODO w ciągu 72 h (RODO art. 33). Dostawca zgłasza incydenty bezpieczeństwa produktu do CSIRT/ENISA (CRA art. 14) i powiadamia osoby wskazane przez biuro.

Panel → Kontakty incydentów: osoba zgłaszająca do UODO (wymagana), zastępca, IOD (jeśli wyznaczony), uwagi. Dane trafiają do pakietu odzyskiwania; nie trafiają do monitoringu dostawcy. Po zmianie kontaktów wygeneruj nowy pakiet.

## 8. Funkcje i co oznaczają dla danych

Panel → Funkcje. Włączenie funkcji jest zgodą biura na ruch wychodzący do wskazanej usługi (serwer od razu dopisuje jej adresy do listy dozwolonych połączeń). Klucze API usług (Anthropic, Resend, GetResponse) wpisuje administrator w ustawieniach CRM; aplikacja przechowuje je w Vault bazy.

| Funkcja | Domyślnie | Dokąd wychodzi ruch | Co to oznacza dla danych |
|---|---|---|---|
| Asystent AI (`ai`) | wyłączone | `api.anthropic.com` | treść zapytań i przetwarzanych dokumentów trafia do dostawcy modelu w USA (transfer poza EOG); możliwe dane szczególnych kategorii (art. 9 RODO). Włączaj tylko po decyzji administratora danych i ocenie podstawy transferu |
| Serwer MCP (`mcp`) | wyłączone | brak nowych adresów; działa tylko w sieci biura | narzędzia AI na urządzeniach biura (Claude Code, Cursor, VS Code, Claude Desktop z rozszerzeniem `.mcpb`) czytają CRM; dane trafiają do dostawcy modelu, z którego korzysta to narzędzie. Wymaga włączonego asystenta AI. claude.ai w przeglądarce i w aplikacji mobilnej nie jest obsługiwane |
| Powiadomienia e-mail (`email`) | wyłączone | `api.resend.com` | treść powiadomień i adresy odbiorców przechodzą przez Resend (USA) |
| GetResponse (`getresponse`) | wyłączone | `api.getresponse.com` | lista odbiorców newslettera i treść wysyłek u operatora GetResponse |
| Powiadomienia push (`push`) | wyłączone | usługi push Google, Mozilla, Apple, Microsoft | treść powiadomienia przechodzi przez usługę producenta przeglądarki |
| Kalendarze ICS (`ics`) | wyłączone | tylko hosty wpisane przez biuro | serwer pobiera kalendarze z tych hostów; operator hosta widzi adres serwera |
| Sprawdzanie haseł HIBP (`hibp`) | **włączone** | `api.pwnedpasswords.com` | wysyłany jest tylko 5-znakowy prefiks skrótu hasła (k-anonimowość) |

Niezależnie od przełączników: e-maile logowania do CRM (potwierdzenia, reset hasła) wychodzą z domeny biura przez Resend (`api.resend.com`) — to transfer adresów e-mail personelu do USA.

## 9. Odpowiedzialności w skrócie

| Zadanie | Biuro | Dostawca |
|---|---|---|
| Konta Hetzner, Cloudflare, domena; rachunki | ✔ | — |
| Włączenie backupu Hetzner, tymczasowe tokeny do testu odtworzenia | ✔ | prowadzi test |
| Urządzenia, personel, konta panelu | ✔ | — |
| Otwieranie okien serwisowych | ✔ | prosi, pracuje w oknie |
| Zatwierdzanie wydań `feature` i poszerzeń ruchu wychodzącego | ✔ | wydaje i opisuje |
| Włączanie funkcji z ruchem zewnętrznym | ✔ (zgoda administratora danych) | — |
| Pakiet odzyskiwania i jego przechowywanie | ✔ | — |
| Zgłoszenie naruszenia do UODO (72 h) | ✔ | informuje i dostarcza fakty |
| Zgłoszenia CRA do CSIRT/ENISA | — | ✔ |
| Wydania, monitoring, poprawki bezpieczeństwa | — | ✔ |
