# Bezpieczeństwo

## 1. Zgłaszanie podatności

Podatności w Legatto zgłaszaj **prywatnie** przez GitHub Security Advisories:

- oprogramowanie serwera biura (to repozytorium): `https://github.com/JakubLog/legatto-node/security/advisories/new`;
- aplikacja: `https://github.com/JakubLog/legatto/security/advisories/new`.

Nie zgłaszaj podatności w publicznych issues.

> **Do uzupełnienia:** domena Legatto nie ma dziś adresu `security@` (są tylko `kontakt@legatto.pl`, `rodo@legatto.pl` i `formularz@legatto.pl`). Prywatne zgłaszanie podatności trzeba włączyć w ustawieniach obu repozytoriów (Settings → Code security → Private vulnerability reporting). Do tego czasu kanałem jest `kontakt@legatto.pl` z tematem „Podatność".

W zgłoszeniu podaj: komponent i wersję (panel biura → Wydania pokazuje wersję), kroki odtworzenia, skutek. Nie testuj na serwerach biur — wszystkie serwery produkcyjne przetwarzają dane wyborców.

Dostawca potwierdza zgłoszenie, ocenia je i wydaje poprawkę jako wydanie `security`. Aktywnie wykorzystywaną podatność dostawca zgłasza przez platformę ENISA do CSIRT-u w terminach CRA art. 14: wczesne ostrzeżenie w 24 h, zgłoszenie w 72 h, raport końcowy najpóźniej 14 dni od udostępnienia poprawki.

## 2. Model zaufania — strony

| Strona | Rola |
|---|---|
| Biuro poselskie | administrator danych; właściciel projektu Hetzner, konta Cloudflare i domeny; jedyny, kto otwiera dostęp serwisowy i zatwierdza wydania funkcjonalne |
| Dostawca Legatto | wytwórca oprogramowania i podmiot przetwarzający; podpisuje wydania, utrzymuje hosting wydań i monitoring; dostęp do serwera tylko w oknie od biura |
| Hetzner | dostawca VPS i backupu; ma dysk, pamięć i kopie |
| Cloudflare | hosting strony posła, Workera, kolejki (konto biura) i hostingu wydań (konto dostawcy) |
| Usługi zewnętrzne | Resend (zawsze: e-maile logowania), opcjonalnie Anthropic, GetResponse, usługi push — tylko po włączeniu przez biuro |

## 3. Co dostawca może, a czego nie może bez zgody biura

| Może bez zgody biura | Nie może bez zgody biura |
|---|---|
| opublikować podpisane wydanie `security`, które zainstaluje się samo po canary, promocji i minimalnych opóźnieniach (biuro może wyłączyć automat w panelu) | połączyć się po SSH ani z panelem biura poza oknem break-glass |
| widzieć status techniczny: wersję, wynik weryfikacji podpisu, dysk, RAM, wiek kopii, liczniki (bez danych osobowych) | odczytać backupu, kolejki formularzy ani kluczy danych |
| zarządzać hostingiem wydań `updates.legatto.pl` i swoją instancją monitoringu | zainstalować wydania `feature` ani poszerzyć listy dozwolonych połączeń wychodzących — oba wymagają zatwierdzenia w panelu |
| — | zmienić kluczy zaufania updatera, polityki ACL, firewalla, sshd, sudoers poza oknem break-glass |
| — | wejść na konto Cloudflare biura po instalacji ani do projektu Hetzner (brak stałej roli) |

Mechanizmy:
- **Dostęp serwisowy:** ACL Headscale i sety nftables odcinają konta dostawcy poza oknem; okno 1–8 h otwiera admin biura kodem TOTP (TOTP sprawdza uprzywilejowany executor, nie panel). Każde okno ma podsumowanie: logowania, polecenia sudo z wyjściem, uruchomienia Ansible.
- **Ansible:** łączy się tylko w oknie; każde uruchomienie wymaga planu (`--check --diff`) podpisanego kluczem sprzętowym operatora, nie starszego niż 4 h, z niezmienionym stanem obu repozytoriów.
- **Dziennik audytu:** `/var/log/legatto/audit.log`, JSONL z łańcuchem hashy, tylko dopisywanie (`chattr +a`), jeden zapisujący; kotwica łańcucha (`aseq`, `ahead`) co 5 min trafia do monitoringu poza serwerem.

**W oknie break-glass dostawca ma roota, czyli technicznie wszystko.** Kontrola jest wtedy organizacyjna i detekcyjna: zgoda biura, limit czasu, zapis sesji, log zakotwiczony poza serwerem, podsumowanie dla biura.

## 4. Gdzie architektura nie chroni

1. **Urządzenie pracownika.** Zainfekowany laptop z ważną sesją widzi to, co pracownik. Headscale nie sprawdza stanu urządzeń.
2. **Dostawca jako wytwórca.** Podpisane wydanie jest docelowo **równoważne rootowi**: pakiety `.deb`, binaria i skrypty instalacyjne działają jako root. Typowane appliery chronią przed przypadkową zmianą granic i wymuszają jawność, nie przed złośliwym podpisującym. Łańcuch wydań spowalnia i ujawnia, nie uniemożliwia: podpis kluczem sprzętowym, przebudowa porównawcza z CI, canary z atestacją, jawna promocja, minimalne opóźnienia liczone przez serwer, zgoda biura na `feature` i poszerzenie egress, publiczny `transparency.log`.
3. **Maszyna podpisu w chwili podpisu.** Klucz sprzętowy chroni przed kradzieżą klucza, nie przed podpisaniem podmienionej treści. Ograniczają to przebudowa porównawcza, canary i opóźnienia.
4. **Jeden klucz wydań.** Dziś istnieje jeden klucz sprzętowy i wymagany jest jeden podpis. Kradzież klucza razem z PIN-em wystarcza do podpisu. Klucz zapasowy jeszcze nie istnieje; rotacja klucza wymaga okna break-glass w każdym biurze.
5. **Dostawca VPS.** Hetzner ma dysk, pamięć, konsolę i kopie. Dane w spoczynku nie są szyfrowane kluczem biura (szyfrowanie LUKS jest kwestią otwartą).
6. **Operator strefy DNS biura.** Kto kontroluje strefę domeny biura w Cloudflare, może przekierować `vpn.<domena>`, uzyskać certyfikat i podszyć się pod koordynatora tailnetu. Zabezpieczenie: twarde zabezpieczenie konta Cloudflare biura (klucz sprzętowy), CAA, monitoring logów CT.
7. **Cloudflare i konto CF biura.** Podmiana strony lub Workera pozwala czytać nowe zgłoszenia w locie. Szyfrowanie formularza w przeglądarce zawęża to do czynnej podmiany skryptu strony.
8. **Root na serwerze.** Obchodzi egress, fałszuje status, może dopisać własny węzeł do tailnetu. Zostaje kotwica dziennika audytu poza serwerem.
9. **Usługi wielodostępne na allowliście.** Poczta, push, AI są kanałem wycieku mimo filtra po nazwie hosta, bo cudze konto u tego samego dostawcy ma tę samą nazwę. Dlatego są wyłączone domyślnie (poza e-mailami Auth przez Resend).
10. **Trwała blokada.** Utrata urządzeń biura, kont panelu i pakietu odzyskiwania zostawia tylko konsolę VPS (konto `recovery`, hasło też w pakiecie).

## 5. Dostęp i powierzchnia ataku

- Z internetu: wyłącznie Headscale (`443/tcp`, `3478/udp`, `41641/udp`). API Headscale bez kluczy API; brak publicznych rekordów `app.`/`admin.app.`.
- CRM, panel, Studio i SSH: tylko w tailnecie. Panel i funkcje wrażliwe aplikacji (`admin-*`, eksport) są dostępne tylko na `admin.app.<domena>` (adres IPv6 tailnetu, tylko `tag:office-device`); na `app.<domena>` Caddy zwraca 404, a baza z `legatto.surface_enforce=on` odrzuca wywołania bez nagłówka powierzchni admin.
- **MCP tylko w tailnecie.** Serwer MCP aplikacji działa wyłącznie pod `https://app.<domena>/api/mcp` w sieci biura — dla klientów lokalnych na urządzeniach w tailnecie (Claude Code, Cursor, VS Code, Claude Desktop z rozszerzeniem `.mcpb` Legatto). Nie ma publicznego endpointu ani Cloudflare Tunnel; claude.ai w przeglądarce i w aplikacji mobilnej nie jest obsługiwane. MCP jest domyślnie wyłączone i działa tylko przy włączonym asystencie AI; narzędzie AI na urządzeniu przekazuje dane CRM do swojego dostawcy modelu.
- Formularz publiczny: treść szyfruje przeglądarka (X25519); Worker sprawdza rozmiar, Turnstile, limity, podpisuje kopertę; serwer odbiera kolejkę dwoma procesami — z siecią bez klucza i z kluczem bez sieci.
- Egress: kontenery w sieciach bez trasy na zewnątrz, proxy z allowlistą nazw per rola, nftables per użytkownik, adres metadanych zawsze odcięty. Wydanie może allowlistę zawęzić; każde poszerzenie czeka na zgodę admina.

## 6. Transfery poza EOG

| Usługa | Kiedy | Dane |
|---|---|---|
| Resend (USA) | **zawsze** — e-maile logowania do CRM (potwierdzenia, reset hasła) z domeny biura; dodatkowo powiadomienia, gdy biuro włączy `email` | adresy e-mail personelu, treść wiadomości systemowych i powiadomień |
| Anthropic (USA) | tylko po włączeniu `ai` przez biuro | treść zapytań i dokumentów przetwarzanych przez asystenta; możliwe dane szczególnych kategorii (art. 9 RODO) |
| GetResponse | tylko po włączeniu `getresponse` | odbiorcy i treść newslettera |
| Usługi push (Google, Mozilla, Apple, Microsoft) | tylko po włączeniu `push` | treść powiadomień |
| Cloudflare | zawsze (strona, Worker, kolejka) | szyfrogramy zgłoszeń i metadane techniczne; Cloudflare widzi adres IP wyborcy, do serwera trafia tylko jego skrót (limity) |

Decyzja o włączeniu funkcji z transferem należy do biura jako administratora danych (panel → Funkcje). Alternatywa dla Resend na później: AWS SES.

## 7. Backup — ryzyka przyjęte świadomie

Jedynym backupem poza serwerem jest wbudowany backup Hetzner (7 dziennych obrazów dysku) plus ręczny eksport posła. Biuro i dostawca przyjęli świadomie:

1. **Kopie nieszyfrowane kluczem biura.** Hetzner ma dostęp do obrazów tak samo jak do dysku serwera.
2. **Ten sam dostawca i to samo konto co serwer.** Przejęcie projektu Hetzner biura albo awaria Hetznera obejmuje serwer i kopie jednocześnie. Kopie można też skasować z tego samego konta — nie ma blokady usuwania.
3. **Brak retencji tygodniowej i miesięcznej.** Najstarsza kopia ma 7 dni; uszkodzenie danych zauważone później nie jest odwracalne z backupu.
4. **Spójność.** Spójność bazy zapewnia `pg_dump` wykonywany 60 min przed oknem backupu; obraz dysku sam w sobie nie jest spójny transakcyjnie.

Środki łagodzące: miesięczny test odtworzenia zrzutu na serwerze, okresowy test na odizolowanym klonie z obrazu Hetzner, ręczny eksport posła przechowywany offline, pakiet odzyskiwania z kluczami danych. Otwarte: szyfrowanie LUKS danych.

## 8. Łańcuch dostaw i repozytoria

- Kod działający na serwerze biura jest publiczny (to repozytorium, AGPL-3.0-only), tak samo aplikacja. Narzędzia wdrożeniowe dostawcy (playbooki, budowanie i publikacja wydań) są prywatne; nie zmieniają tego, co serwer przyjmie — o tym decyduje kod z tego repozytorium (weryfikacja podpisów, kanały, zgoda biura, break-glass).
- Akcje GitHub przypięte po pełnym SHA, obrazy po digest; CI bez sekretów i bez publikacji, workflowy z `permissions: {}` i uprawnieniami per job. Wydanie podpisuje człowiek kluczem sprzętowym poza CI.
- `gitleaks` w pre-commit i w CI.
- **Stan na 2026-11-22:** repo aplikacji nie ma jeszcze chronionej gałęzi `main` ani wymogu SHA pinningu; to repozytorium nie jest jeszcze opublikowane na GitHubie.
