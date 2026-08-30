# Sherlock OSA

Sherlock OSA is a digital-footprint privacy product, not a terminal-first mission demo.

The primary flow is:

**IDENTITY → EXPOSURE → RISK → REMOVAL → VERIFICATION**

A user enters an email. Sherlock calls a backend EmailOSINT adapter, normalizes the provider response, redacts credential-like fields, and turns the result into a privacy report: linked accounts, breach exposure, infostealer signals, AI synthesis, risk and concrete cleanup actions.

The older OSA Execution Force mission runtime remains available as a secondary control/evidence layer. It is not the primary product UI.

## Architecture

### Layer 1 — primary lookup engine

`POST /api/v1/lookup/email`

Backend adapter:

- endpoint: `EMAILOSINT_ENDPOINT`
- default: `https://www.emailosint.org/v1/lookup/email`
- optional provider key: `EMAILOSINT_API_KEY`
- configurable auth header/scheme
- JSON and SSE provider responses accepted
- credential/session/token-like fields redacted before they are returned to the browser

Normalized response:

```text
identity
  └─ linked_accounts
exposure
  ├─ breaches
  └─ infostealer
risk
removal
  └─ actions
verification
provider
  └─ raw (redacted)
```

When `EMAILOSINT_API_KEY` is empty, the adapter can use the provider's unauthenticated/free mode. When a provider key is configured, Sherlock requires the operator `SHERLOCK_API_KEY` on the lookup endpoint so a public deployment cannot consume paid quota anonymously.

### Layer 2 — Sherlock enrichment

The existing bounded research pack remains available for additional enrichment:

- Holehe
- Maigret
- Wayback CDX
- crt.sh
- correlation / evidence / poison gate

These sources are secondary to the product lookup path.

### Layer 3 — OSA agent runtime

OSA Execution Force remains the mission/control layer:

- engine pin: `f365360383511fea13cd3f7af36ecbbc720ce38d`
- signed mission scope
- deterministic capability broker
- evidence ledger
- replay
- bounded research orchestration

This layer exists for governed agent workflows. It is not required to understand the landing page or the primary product value.

## Configuration

Copy `.env.example` and configure the values you need.

Minimum live runtime variables:

```bash
SHERLOCK_API_KEY=...
SHERLOCK_MISSION_SIGNING_SECRET=...
OSA_ACTIONS_API_KEY=...
```

Primary provider:

```bash
EMAILOSINT_ENDPOINT=https://www.emailosint.org/v1/lookup/email
EMAILOSINT_API_KEY=
EMAILOSINT_AUTH_HEADER=Authorization
EMAILOSINT_AUTH_SCHEME=Bearer
```

If your EmailOSINT plan uses a different auth header/scheme, change only the two auth variables. No frontend change is required.

## Run

```bash
python -m pip install -e '.[research]'
sherlock-osa serve --env-file .env
```

Open the shown URL and use the primary email lookup.

## API

Primary product:

```text
POST /api/v1/lookup/email
```

Body:

```json
{"email":"name@example.com"}
```

Secondary runtime:

```text
GET  /api/v1/health
GET  /api/v1/research/sources
POST /api/v1/missions
POST /api/v1/research
POST /api/v1/research/stream
GET  /api/v1/evidence/verify
```

## Truth contract

Sherlock does not fabricate a replacement result when the provider fails.

- provider HTTP error → explicit `EMAILOSINT_HTTP_ERROR`
- provider unreachable → explicit `EMAILOSINT_UNAVAILABLE`
- invalid provider response → explicit `EMAILOSINT_INVALID_RESPONSE`
- no synthetic accounts/breaches are generated
- raw provider data exposed to the UI is recursively redacted for credential-like fields

The landing reports only what the provider returned plus deterministic privacy actions derived from the presence of account/breach/infostealer signals.
