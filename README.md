# Sherlock OSA

**Evidence-first, bounded OSINT research runtime sterowany przez OSA Execution Force Engine.**

Sherlock OSA nie ufa modelowi językowemu jako granicy bezpieczeństwa. OSA Execution Force Engine rozpoznaje intencję i prowadzi misję, a deterministyczny broker poza modelem egzekwuje podpisany scope. Research działa jako bounded fan-out → evidence → correlation → trusted pivots, z twardym limitem 300 s.

## Status v0.3.0

### BACKED

- jeden control plane przez OSA Execution Force Engine;
- `RESEARCH_PASSIVE` dla `EMAIL | USERNAME | URL | DOMAIN | INDICATOR`;
- bounded recursive research kernel: dedupe, max depth, max identifiers, max evidence, max invocations i 300 s hard deadline;
- poison/injection checker: `TAINTED` evidence nie może tworzyć kolejnych pivotów;
- SSE/JSON research endpoints;
- privacy-safe evidence metadata: target passive jest hashowany w ledgerze;
- raw source evidence pozostaje ephemeral;
- `purge_after=true` usuwa lokalny scope i decisions z SQLite;
- publiczny Vercel deploy pozostaje stateless LAB replay demo.

### SOURCE PACK v1

Opcjonalny runtime `.[research]` integruje dwa niezależne projekty przez killowalne subprocessy:

- **Holehe 1.61** — email → registered-account signals na 100+ usługach. Sherlock nie zachowuje recovery email/phone hints;
- **Maigret 0.6.4** — username → profile discovery na rankingu do 500 publicznych serwisów na lookup, z profile parsing i kontrolowanymi URL/email/username pivots.

Target jest przekazywany workerowi przez `stdin`, nie argv. Każdy source worker ma timeout i może zostać zabity przez parent runtime. Maigret jest ograniczony do source depth `<=1`, Holehe do `<=2`, aby recursive graph nie zamienił się w niekontrolowany fan-out.

**Truth boundary:** obecność i wersje zależności są mechanicznie sprawdzane. Globalna dostępność Internetu/konkretnej usługi nie jest deklarowana jako BACKED — jest oceniana per lookup.

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
        ┌───────────┼──────────────┐
        ▼           ▼              ▼
 seed-expansion   Holehe         Maigret
   local          subprocess      subprocess
        └───────────┼──────────────┘
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

Core nie instaluje zależności Holehe/Maigret.

## Instalacja research runtime

```bash
python -m pip install -e '.[research]'
python scripts/source_smoke.py
sherlock-osa serve --env-file .env
```

Docker research image:

```bash
docker build -f Dockerfile.research -t sherlock-osa:research .
docker run --env-file .env -p 8787:8787 sherlock-osa:research
```

Domyślny `Dockerfile` pozostaje dependency-clean Apache core. `Dockerfile.research` instaluje opcjonalny source pack.

## API research

1. `POST /api/v1/missions` — utwórz podpisaną misję `RESEARCH_PASSIVE` z capability `osint.research.run` + source capabilities.
2. `GET /api/v1/research/sources` — dependency/version health source packa.
3. `POST /api/v1/research` — bounded research JSON.
4. `POST /api/v1/research/stream` — ten sam research jako SSE.

Domyślnie `purge_after=true`.

## Validation

```bash
python scripts/source_smoke.py
python scripts/verify.py
python scripts/smoke.py
python scripts/smoke_demo.py
```

CI instaluje dokładnie `holehe==1.61` i `maigret==0.6.4`, sprawdza dependency health offline, następnie uruchamia cały istniejący suite, vertical smoke i public replay smoke. Testy nie wykonują masowego researchu po zewnętrznych serwisach.

## Licencje / sprzedaż

Kod Sherlock OSA core: **Apache-2.0**.

Source pack nie vendoruje kodu Holehe ani Maigret — instaluje je jako opcjonalne zależności i uruchamia w oddzielnych subprocessach. Holehe jest **GPLv3**, Maigret **MIT**. GPL dopuszcza użycie komercyjne, ale dystrybucja obrazu/pakietu zawierającego GPL ma obowiązki licencyjne. Dlatego core i research image są rozdzielone. Dla SaaS należy nadal zachować notices i warunki używanych usług.

Szczegóły: [`docs/RESEARCH_SOURCE_PACK_V0.3.md`](docs/RESEARCH_SOURCE_PACK_V0.3.md).

## Boundary

Sherlock v0.3.0 nie zawiera breach dumps, infostealer logs ani funkcji nieautoryzowanego kasowania danych z cudzych systemów. `external_deletion_performed=false`. Legalne data-erasure workflows mogą być osobną warstwą opartą o oficjalne API/procedury administratorów danych.
