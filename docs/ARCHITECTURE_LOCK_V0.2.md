# Architecture Lock v0.2 — OSINT research plane

Status: frozen for `v0.2.0`. Ten dokument zastępuje v0.1 jako bieżący kontrakt
produktu. Dokumenty v0.1 pozostają historycznym zapisem control-plane.

## Cel

Przyjmować e-mail, telefon, osobę, username, domenę albo IP; uruchamiać właściwe
pasywne źródła; oddzielać fakty od kandydatów; opcjonalnie weryfikować
indeksowane strony `.onion`; nie zwracać haseł ani surowych rekordów wycieków.

## Trust zones

```text
Browser/API
    |
    v
Private Control Plane -----> fixed-host passive providers
    |
    | hashed subject + typed skills
    v
OSA Execution Force Engine
    |
    | COMPLETED receipt only
    v
Research Worker --SOCKS5H--> Tor Gateway --> Ahmia / v3 .onion
    |
    v
Metadata-only result --> per-request evidence chain
```

### Public preview

- bez konta i bez trwałego storage;
- fixed-host HTTPS do XposedOrNot, LeakCheck (jeśli skonfigurowany), GitHub,
  Wikidata, RDAP i Ahmia;
- DNS/reverse DNS przez resolver runtime;
- brak OSA Engine, shella, CLI tools i bezpośredniego `.onion`;
- każdy brak backingu ma jawny status.

### Private control plane

- Bearer auth;
- identyfikator jest walidowany przed wywołaniem Engine;
- Engine dostaje wyłącznie `sha256:<normalized identifier>`, rodzaj, cel i listę
  skill IDs;
- stan inny niż `COMPLETED` zatrzymuje wszystkie adaptery;
- receipt jest redagowany i hashowany przed zapisaniem.

### Research worker

- wewnętrzny Bearer token i wymagany hash receiptu;
- nie przyjmuje arbitralnego URL-a;
- konstruuje wyłącznie adres wyszukiwania Ahmia;
- z wyników dopuszcza wyłącznie host v3 `.onion`, port 80/443, HTTP(S);
- stałe argv `curl`, bez shella, bez redirectów, limit 15 s / 500 kB / 5 stron;
- worker nie jest podłączony do zwykłej sieci egress; widzi tylko Tor gateway;
- odpowiedź zawiera URL, tytuł, rozmiar i SHA-256, nie treść strony.

## Inwarianty

1. Brak zgody/celu → brak planu i brak ruchu sieciowego.
2. Brak `COMPLETED` receiptu → brak prywatnego wykonania.
3. Model językowy nie jest granicą bezpieczeństwa.
4. Query nie trafia do Engine, trwałego ledgeru ani logów workera.
5. `NO_MATCH` nigdy nie jest interpretowane jako „brak ekspozycji”.
6. Ahmia index match nie jest dowodem treści strony.
7. Kandydat osoby/username nie jest potwierdzoną tożsamością.
8. Żaden adapter breach nie zwraca hasła ani pełnego rekordu.

## Capability map

| Identyfikator | Skille domenowe | Live/public | Private worker |
|---|---|---|---|
| e-mail | `email-exposure` | XposedOrNot, opcjonalnie LeakCheck | Holehe adapter boundary |
| telefon | `phone-intelligence` | E.164, opcjonalnie LeakCheck | PhoneInfoga/Ignorant boundary |
| osoba | `person-discovery` | Wikidata + search pack | przyszła korelacja grafowa |
| username | `username-discovery` | GitHub + profile map + LeakCheck | Sherlock/Maigret/WhatsMyName boundary |
| domena | `domain-intelligence` | DNS + RDAP | Amass/SpiderFoot boundary |
| IP | `ip-intelligence` | reverse DNS + RDAP | brak aktywnego skanowania |
| każdy typ | `darkweb-index-search` | Ahmia index | Tor content verification |

„Boundary” oznacza jawny, niewykonywany jeszcze adapter procesu prywatnego, a nie
fałszywe twierdzenie o integracji.

## Następny lock

v0.3 może dodać kolejkę zadań, persistent encrypted case store, izolowane
procesy Sherlock/Maigret/PhoneInfoga oraz rate-limit per operator. Nie może
osłabić żadnego inwariantu v0.2 bez nowego ADR.
