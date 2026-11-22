# Dodanie telefonu lub laptopa do sieci biura

Instrukcja dla asystenta biura. CRM (`https://app.<domena>`) działa tylko na urządzeniach dodanych do prywatnej sieci biura. Sieć działa przez aplikację **Tailscale** połączoną z serwerem biura (nie z firmą Tailscale). Dodanie jednego urządzenia trwa kilka minut.

W tekście `<domena>` to domena posła, np. `jankowalski.pl`.

Miejsca oznaczone **[do sprawdzenia]** nie zostały jeszcze przećwiczone na prawdziwym telefonie; nazwy przycisków w aplikacji Tailscale mogą się różnić. Po pierwszym onboardingu uzupełnimy je zrzutami ekranu.

## 1. Co jest potrzebne

- Urządzenie: telefon z Androidem albo iPhone; laptop z macOS albo Windows.
- Ktoś z dostępem do **panelu biura** (admin biura) — wygeneruje jednorazowy klucz.
- 30 minut od wygenerowania klucza: klucz jest jednorazowy i po 30 minutach wygasa. Jeśli nie zdążysz, admin wygeneruje nowy.

## 2. Krok admina: klucz rejestracji

Admin biura, na urządzeniu biura:

1. Otwiera `https://admin.app.<domena>/console/` i loguje się (hasło + kod z aplikacji uwierzytelniającej).
2. Jeśli urządzenie należy do nowej osoby: **Urządzenia → Personel** → dopisuje login tej osoby (małe litery, np. `anna.nowak`) → „Zapisz listę".
3. **Urządzenia → Dodaj urządzenie**:
   - Rodzaj: „urządzenie pracownika (dostęp do CRM)" — dla telefonów i laptopów personelu; „urządzenie biura (CRM i panel admina)" — tylko dla urządzeń, z których admin będzie używał panelu;
   - Pracownik: login z listy (tylko dla urządzenia pracownika);
   - kod TOTP → „Utwórz klucz rejestracji".
4. Na ekranie pojawiają się:
   - **kod QR nr 1 — „Adres serwera koordynacji"** (`https://vpn.<domena>`);
   - **kod QR nr 2 — „Klucz rejestracji"**;
   - dla komputerów: gotowe polecenie `tailscale up --login-server=https://vpn.<domena> --auth-key=…`.

Ekran z kluczem znika z serwera po 10 minutach — nie zamykaj go, dopóki urządzenie się nie połączy.

## 3. Telefon

### 3.1 Android

1. Zainstaluj **Tailscale** ze Sklepu Google Play.
2. Otwórz aplikację, ale **nie loguj się** kontem Google ani Microsoft.
3. W menu (⋮) wybierz zmianę serwera — „Use an alternate server" / „Change server" **[do sprawdzenia]**.
4. Wpisz adres z kodu QR nr 1. Najprościej: zeskanuj kod aparatem telefonu, skopiuj odczytany tekst i wklej go w polu adresu **[do sprawdzenia]**.
5. Wybierz logowanie kluczem — „Use an auth key" — i w ten sam sposób wklej klucz z kodu QR nr 2 **[do sprawdzenia]**.
6. Zgódź się na utworzenie połączenia VPN, gdy Android o to zapyta.
7. Upewnij się, że w ustawieniach Tailscale włączone jest „Use Tailscale DNS" — bez tego nazwa `app.<domena>` nie zadziała.

### 3.2 iPhone

1. Zainstaluj **Tailscale** z App Store.
2. Otwórz aplikację, ale **nie loguj się** kontem Apple, Google ani Microsoft.
3. Wybierz własny serwer koordynacji — „Use a custom coordination server" / „Use alternate server" **[do sprawdzenia]**, wklej adres z kodu QR nr 1 (zeskanuj kod aparatem, skopiuj tekst).
4. Wybierz logowanie kluczem („Use an auth key") i wklej klucz z kodu QR nr 2. **[do sprawdzenia: czy aplikacja na iOS ma tę opcję]**
5. Zgódź się na dodanie konfiguracji VPN.
6. Sprawdź, że „Use Tailscale DNS" jest włączone.

### 3.3 Pierwsze otwarcie CRM na telefonie

1. Włącz Tailscale (przełącznik „Connected").
2. W przeglądarce otwórz `https://app.<domena>`.
3. Zaloguj się swoim kontem CRM (login i hasło dostajesz od posła lub administratora CRM — to inne konto niż konto panelu).
4. Dodaj stronę do ekranu początkowego, jeśli chcesz mieć ją pod ręką.

## 4. Laptop

### 4.1 Windows

1. Pobierz i zainstaluj **Tailscale** ze strony `tailscale.com/download`.
2. **Nie loguj się** w okienku Tailscale.
3. Otwórz **PowerShell jako administrator** (Start → wpisz „PowerShell" → prawy przycisk → „Uruchom jako administrator").
4. Wpisz polecenie z panelu (część z ekranu admina):
   ```
   tailscale up --login-server=https://vpn.<domena> --auth-key=<klucz>
   ```
   Klucz przepisz z ekranu admina albo admin przekaże Ci polecenie osobiście. Klucz jest jednorazowy — po użyciu do niczego się nie nada.
5. Po chwili ikona Tailscale pokaże stan „Connected".

### 4.2 macOS

1. Zainstaluj **Tailscale** (App Store albo `tailscale.com/download`).
2. **Nie loguj się** w okienku Tailscale.
3. Polecenie `tailscale` w Terminalu: jeśli Terminal go nie zna, w menu Tailscale wybierz instalację narzędzia wiersza poleceń („Install CLI") **[do sprawdzenia]**.
4. Otwórz **Terminal** i wpisz polecenie z panelu:
   ```
   tailscale up --login-server=https://vpn.<domena> --auth-key=<klucz>
   ```
   (jeśli system zapyta o hasło administratora komputera — podaj je).
5. Zezwól na dodanie konfiguracji VPN, gdy macOS o to zapyta.

### 4.3 Pierwsze otwarcie

- CRM: `https://app.<domena>`, logowanie kontem CRM.
- Tylko urządzenie biura: panel `https://admin.app.<domena>/console/`.

## 5. Gdy coś nie działa

| Objaw | Co zrobić |
|---|---|
| „Klucz wygasł" / „invalid key" | Klucz był ważny 30 minut albo został już użyty. Poproś admina o nowy. |
| Tailscale połączony, ale `app.<domena>` się nie otwiera | Sprawdź, czy włączone jest „Use Tailscale DNS". Wyłącz i włącz Tailscale. Na komputerze nie używaj innego VPN w tym samym czasie. |
| CRM działa, panel admina nie | Urządzenie zostało dodane jako „urządzenie pracownika" — panel otwiera się tylko z „urządzenia biura". Admin musi dodać je ponownie jako urządzenie biura. Panel działa też tylko po IPv6 w sieci biura; jeśli system urządzenia ma IPv6 wyłączone, włącz je. |
| Urządzenie nagle straciło dostęp | Rejestracja urządzenia wygasa po 180 dniach. Admin widzi datę w kolumnie „Wygasa" i może wygenerować nowy klucz. Możliwe też, że admin usunął urządzenie albo Twój login z listy personelu. |

## 6. Zgubiony lub skradziony telefon albo laptop

Działaj od razu — w telefonie mogła zostać otwarta sesja CRM.

1. **Zgłoś to adminowi biura** (telefonicznie, od razu).
2. **Admin: odetnij urządzenie.** Panel → Urządzenia → w tabeli „Urządzenia w tailnecie" znajdź urządzenie (nazwa, użytkownik, ostatnia aktywność) → „Usuń" + kod TOTP. Urządzenie traci dostęp do serwera natychmiast, trwające połączenia są zrywane.
3. **Zmień hasło do CRM** z innego urządzenia. Jeśli w zgubionym telefonie była aplikacja z kodami 2FA do CRM, poproś posła lub administratora CRM o ponowne ustawienie 2FA.
4. **Jeśli to było urządzenie biura albo był w nim kod TOTP panelu:** inny admin w panelu → Konta panelu → „Nowy kod TOTP" i „Hasło tymczasowe" dla tego konta. Jeśli nie ma innego admina — konto awaryjne z pakietu odzyskiwania (`docs/HANDOVER.md` §2.4).
5. **Oceńcie, czy doszło do naruszenia ochrony danych.** Odpowiada za to biuro jako administrator danych; zgłoszenie do UODO trzeba złożyć w ciągu 72 h od stwierdzenia naruszenia (`docs/HANDOVER.md` §7).
6. Nowe urządzenie dodaj według tej instrukcji (nowy klucz z panelu).

Gdy osoba odchodzi z biura: admin usuwa jej login z listy **Urządzenia → Personel** — to odłącza wszystkie jej urządzenia naraz.
