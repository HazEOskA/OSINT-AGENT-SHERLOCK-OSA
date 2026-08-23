# Sherlock OSA

**Evidence-first, bounded OSINT research runtime sterowany przez OSA Execution Force Engine.**

Sherlock OSA nie ufa modelowi językowemu jako granicy bezpieczeństwa. OSA Execution Force Engine prowadzi misję, deterministyczny broker egzekwuje podpisany scope, a research działa jako bounded fan-out → evidence → correlation → trusted pivots z twardym limitem 300 s.

## Status v0.3.0

### BACKED

- jeden control plane przez OSA Execution Force Engine;
- `RESEARCH_PASSIVE` dla `EMAIL | USERNAME | URL | DOMAIN | INDICATOR`;
- recursive research kernel: dedupe, max depth, identifiers, evidence, invocations i 300 s hard deadline;
- poison/injection checker: `TAINTED` evidence nie może tworzyć kolejnych pivotów;
- SSE/JSON research endpoints;
- target passive hashowany w evidence ledgerze;
- raw source evidence pozostaje ephemeral;
- `purge_after=true` usuwa lokalny scope i decisions z SQLite;
- publiczny Vercel deploy pozostaje stateless LAB replay demo.

### SOURCE PACK v1

Network resolvers działają w killowalnych subprocessach. Target przechodzi przez `stdin`, nie argv.

- **Holehe 1.61** — `EMAIL` → account-registration signals na 100+ usługach; recovery email/phone hints są celowo odrzucane;
- **Maigret 0.6.4** — `USERNAME` → profile discovery na top 500 publicznych serwisów per lookup, parsing profilu oraz kontrolowane `URL/EMAIL/USERNAME` pivots;
- **Internet Archive CDX** — `URL | DOMAIN` → historyczne publiczne captures/URL-e;
- **crt.sh Certificate Transparency** — `DOMAIN` → zwalidowane publiczne nazwy certyfikatów/subdomeny.

Provider-specific depth bounds zatrzymują powtórne masowe odpytywanie: Maigret `<=1`, Holehe `<=2`, Wayback URL `<=2`, Wayback domain `<=1`, crt.sh `<=1`.

**Truth boundary:** lokalna rejestracja source packa i wersje Holehe/Maigret są mechanicznie sprawdzane. Globalna dostępność Internetu ani konkretnej usługi nie jest deklarowana jako BACKED — jest oceniana per lookup.

## Architecture

```text
EMAIL / USERNAME / URL / DOMAIN / INDICATOR
                    │
                    ▼
             OSA Engine Scope
                    │
             Capability Broker
                    │
                    ▼
          Bounded Research Engine
        ┌───────────┼──────────────┬───────────┐
        ▼           ▼              ▼           ▼
 seed-expansion   Holehe         Maigret    Wayback / CT
    local        subprocess      subprocess    subprocess
        └───────────┴──────────────┴───────────┘
                    ▼
             normalized evidence
                    │
               PoisonChecker
              ┌─────┴─────┐
            CLEAN       TAINTED
              │           └── no pivots
              ▼
          correlation/dedupe
              │
        trusted identifiers
              │
              └── bounded recursion
                    │
                    ▼
                report/SSE
                    │
                    ▼
             local DB purge
```

Przykładowe ścieżki:

`EMAIL → username/domain → Holehe + Maigret → profile URL → Wayback → historical URLs`

`DOMAIN → crt.sh → validated subdomains`

OSA Engine jest przypięty do SHA `f365360383511fea13cd3f7af36ecbbc720ce38d`. Repo `HazEOskA/osa-execution-force-skills` pozostaje źródłem prawdy dla routingu i kontraktów Engine; Sherlock nie tworzy drugiego routera.

## Instalacja core

```bash
git clone https://github.com/HazEOskA/OSINT-AGENT-SHERLOCK-OSA.git
cd OSINT-AGENT-SHERLOCK-OSA
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cp .env.example .env
sherlock-osa serve --env-file .env
```

## Instalacja research runtime

```bash
python -m pip install -e '.[research]'
python scripts/source_smoke.py
sherlock-osa serve --env-file .env
```

```bash
docker build -f Dockerfile.research -t sherlock-osa:research .
docker run --env-file .env -p 8787:8787 sherlock-osa:research
```

Domyślny `Dockerfile` pozostaje dependency-clean Apache core. `Dockerfile.research` instaluje opcjonalne Holehe/Maigret; Wayback/crt.sh adapters używają biblioteki standardowej.

## API research

1. `POST /api/v1/missions` — podpisana misja `RESEARCH_PASSIVE`.
2. `GET /api/v1/research/sources` — source/dependency health.
3. `POST /api/v1/research` — bounded research JSON.
4. `POST /api/v1/research/stream` — ten sam research przez SSE.

Domyślnie `purge_after=true`.

## Validation

```bash
python scripts/source_smoke.py
python scripts/verify.py
python scripts/smoke.py
python scripts/smoke_demo.py
```

CI instaluje dokładnie `holehe==1.61` i `maigret==0.6.4`, weryfikuje pełny source registry, uruchamia unit/contracts, vertical smoke i public replay smoke. CI nie wykonuje masowego researchu na zewnętrznych serwisach.

## Licencje / sprzedaż

Kod Sherlock OSA core: **Apache-2.0**.

Source pack nie vendoruje kodu Holehe ani Maigret. Holehe pozostaje **GPLv3**, Maigret **MIT**; dlatego domyślny core image i research image są rozdzielone. Komercyjne użycie jest możliwe, ale dystrybucja research package/image wymaga spełnienia obowiązków odpowiednich licencji. SaaS nadal wymaga sprawdzenia terms źródeł, lawful basis, privacy law i retention dla konkretnego use case.

Szczegóły: [`docs/RESEARCH_SOURCE_PACK_V0.3.md`](docs/RESEARCH_SOURCE_PACK_V0.3.md).

## Boundary

Sherlock v0.3.0 nie zawiera breach dumps, infostealer logs ani funkcji nieautoryzowanego kasowania danych z cudzych systemów. `external_deletion_performed=false`. `purge_after` dotyczy lokalnego SQLite; nie jest deklaracją usunięcia danych z OSA Engine ani zewnętrznych providerów.
