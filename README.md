# legatto-node

Oprogramowanie serwera biura poselskiego [Legatto](https://github.com/JakubLog/legatto): wszystko, co działa na serwerze biura albo decyduje o tym, co może na nim zrobić dostawca. Licencja: AGPL-3.0-only (`LICENSE`).

Kod jest publiczny, żeby biuro, audytor albo dziennikarz mógł sprawdzić model zaufania w kodzie, a nie na słowo: kto i kiedy ma dostęp do serwera, jakie wydania serwer przyjmie i dokąd serwer może łączyć się z internetem.

## Co tu jest

| Katalog | Co |
|---|---|
| `updater/` | `legatto-update`: pobiera wydania, weryfikuje podpisy (sshsig), sumy, kanały i opóźnienia, czeka na zgodę biura, instaluje, wycofuje |
| `office-console/` | panel admina biura (`admin.app.<domena>`) i jego uprzywilejowany wykonawca: break-glass, wydania, urządzenia, funkcje, pakiet odzyskiwania |
| `sbin/` | narzędzia hosta: `legatto-breakglass`, `legatto-policy`, `legatto-audit`, `legatto-fw`, `legatto-tailnet`, `legatto-health`, `legatto-pgdump`, `legatto-restore-test`, `legatto-recovery-pack`, `legatto-secrets`, `legatto-studio`, `legatto-stack`, `legatto-acme` |
| `egress/` | `legatto-egress`: allowlista ruchu wychodzącego (proxy Smokescreen + nftables), obraz proxy |
| `headscale/` | szablon polityki ACL tailnetu (personel, urządzenia biura, dostawca tylko w oknie break-glass) |
| `bundle/` | zawartość paczki wydania: compose (Supabase upstream + override), strony Caddy, jednostki systemd, dane allowlisty egress |
| `worker/` | Cloudflare Worker formularza na stronie posła (szyfrogram z przeglądarki → kolejka) |
| `site-publisher/` | narzędzia hosta strony publicznej i odbioru formularza (`legatto-intake`, `legatto-site-publish`, `legatto-worker-deploy`, `legatto-cf-bootstrap`) |
| `release/schema/` | schematy dokumentów wydań: manifest, promocja, atestacja canary, indeks, polityka serwera |
| `contract/` | kontrakt: nazwy, ścieżki, porty, jednostki, CLI (`contract.yml`) i przypięte wersje (`versions.yml`) |
| `trust/allowed_signers` | publiczne klucze, którymi podpisywane są wydania |
| `docs/` | `ARCHITECTURE.md`, `SECURITY.md` (model zaufania, zgłaszanie podatności), `HANDOVER.md` (dla biura), `ONBOARDING-DEVICE.md` (dla personelu) |

## Czego tu nie ma

Narzędzia wdrożeniowe dostawcy (playbooki instalacji, budowanie i publikacja wydań, inwentarze biur) są prywatne. Nie zmieniają tego, co serwer przyjmie: serwer instaluje tylko wydania podpisane kluczem z `trust/allowed_signers`, przechodzące kanały i bramki z `updater/`, a dostęp dostawcy otwiera wyłącznie biuro (`sbin/legatto-breakglass`, `headscale/`).

## Sprawdzanie

```sh
tests/run.sh                       # wszystkie testy (docker, python3 >= 3.12, yq, yamllint, shellcheck)
tests/run.sh updater console       # wybrane obszary
scripts/lint.sh                    # yamllint, shellcheck, składnia Pythona, schematy
scripts/check-actions-pinned.sh    # akcje CI po SHA, obrazy po digest
```

CI (`.github/workflows/`, akcje po SHA, obrazy po digest, bez sekretów): `lint`, `test` (każdy obszar osobno), `scan` (`osv-scanner` po lockfile'ach, `trivy fs`: podatności, błędy konfiguracji, sekrety), `secrets-scan` (`gitleaks` po całej historii). Zależności aktualizuje Renovate (`renovate.json`) wyłącznie przez pull requesty do ręcznego przeglądu, bez auto-merge; `contract/versions.yml` zmienia się ręcznie.

Weryfikacja podpisu wydania na dowolnej maszynie:

```sh
ssh-keygen -Y verify -f trust/allowed_signers -I release-a@legatto.pl \
  -n legatto-release -s manifest.json.release-a.sig < manifest.json
```

## Zgłaszanie podatności

`docs/SECURITY.md` §1. Nie zgłaszaj podatności w publicznych issues.
