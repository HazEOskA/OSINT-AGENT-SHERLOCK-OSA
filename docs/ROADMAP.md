# Roadmap

## v0.2 — OSINT core (current)

- e-mail, telefon, osoba, username, domena i IP;
- 10 typed OSINT skills i deterministyczny resolver;
- live passive adapters + metadata-only breach reporting;
- Ahmia index z prawidłowym verification state;
- Engine-gated private Tor worker, fixed argv i network separation;
- per-request SHA-256 evidence;
- OSINT-first panel i 20-repo benchmark.

## v0.2.1 — public preview hardening

- per-IP/operator rate limit i budżet providerów;
- privacy notice per source i jawna zgoda na przekazanie query;
- provider circuit breakers i cache wyłącznie negatywnych capability checks;
- metryki błędów bez PII.

## v0.3 — isolated CLI workers

- osobne procesy dla Sherlock, Maigret, WhatsMyName, PhoneInfoga i Amass;
- adapter manifest z wersją obrazu, licencją, timeoutem i output schema;
- kolejka zadań, idempotency key, cancel/kill switch;
- szyfrowany case store z konfigurowalnym retention;
- graf encji z ręcznym zatwierdzaniem relacji.

## v0.4 — stronger isolation

- Firecracker lifecycle controller;
- gVisor jako defense-in-depth tam, gdzie kompatybilny;
- podpisane immutable worker images i SBOM;
- testy ucieczki oraz niezależna walidacja sieci.

## v0.5 — authorised external assets

- DNS/HTTP ownership challenge;
- dokładna allowlista FQDN/IP/port z krótkim expiry;
- osobna approval binding i emergency stop;
- przegląd prawny/policy przed włączeniem aktywnych kontroli.
