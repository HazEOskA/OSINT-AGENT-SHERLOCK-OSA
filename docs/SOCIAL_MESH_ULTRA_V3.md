# Sherlock Social Mesh Ultra V3

Social Mesh Ultra V3 expands Sherlock OSA's existing bounded investigation engine with dataset-driven public username probes, EmailOSINT catch-all social classification, phone metadata enrichment, and a user-facing social relationship graph.

## Design sources

The implementation borrows architectural patterns, not incompatible source code, from mature OSINT projects:

- **Sherlock Project** — declarative per-site probe definitions, status/message/regex detection, known claimed/unclaimed fixtures. Runtime dataset pin: `376018708c0f6948d3f978a9ae2915024e794654` (MIT).
- **WhatsMyName** — structured `uri_check`, `uri_pretty`, positive/negative codes and strings, categories including `dating` and `social`, protection metadata, known-positive fixtures. Runtime dataset pin: `e62338e4fc88536a330733d355a9d33a3a1697c6` (CC BY-SA 4.0 data; referenced at runtime, not vendored).
- **socialscan** — explicit AVAILABLE/UNAVAILABLE/INVALID/FAILURE semantics, token prerequisites, rate-limit handling, and the important rule that probes should not cause side effects such as submitting registration forms. Architecture only; source code is not copied.
- **Blackbird** — large cross-platform username/email coverage plus higher-level profile synthesis.
- **SpiderFoot** — event-driven expansion where newly discovered entities feed compatible modules and correlation rules.
- **PhoneInfoga** — phone normalization and numbering-plan metadata while avoiding false claims of owner identity or precise real-time location.
- **GHunt** — useful Google-OSINT architecture, but authenticated Google-cookie/session workflows are intentionally excluded from automatic Sherlock scans.

## Public probe safety contract

The dataset-driven Site Probe Engine is intentionally constrained:

- public HTTP GET/HEAD only;
- no automatic login to third-party accounts;
- no capture or storage of Google/session cookies;
- no proxy rotation to defeat provider limits;
- no CAPTCHA bypass;
- no form submission / registration side effects;
- dataset POST probes are skipped;
- `HTTP 200` alone is not universally considered proof of account existence;
- ambiguous results remain `UNKNOWN`;
- rate limits, blocks, timeouts and errors remain explicit;
- lower-confidence detectors can be quarantined when known-positive/known-negative canaries disagree with the configured detection rule.

## Runtime datasets

Datasets are fetched from commit-pinned raw GitHub references at runtime instead of being copied into this repository. This keeps provenance and licensing explicit while allowing Sherlock to normalize the definitions into one probe model.

The normalized model tracks:

- site name and source dataset;
- category;
- profile URL and probe URL;
- GET/HEAD/POST method metadata;
- username regex constraints;
- positive and negative status codes;
- positive and negative response signatures;
- anti-automation/auth protection hints;
- known-positive/known-negative fixtures when available;
- dataset commit and attribution.

## Social taxonomy

User-facing account signals are grouped into:

- `GOOGLE`
- `DATING`
- `SOCIAL`
- `MESSAGING`
- `DEVELOPER`
- `GAMING`
- `MUSIC`
- `VIDEO`
- `SHOPPING`
- `FINANCE`
- `FORUMS`
- `ADULT`
- `OTHER`

The category is presentation metadata, not identity proof.

## EmailOSINT catch-all

Parity+ still preserves EmailOSINT's normalized and redacted output. Social Graph V3 additionally walks:

1. normalized `identity.signals`,
2. every preserved provider SSE event regardless of event name,
3. the preserved safe provider payload.

This avoids losing a Google/social/dating account signal merely because the upstream provider introduced a new event name that is not part of Sherlock's older normalized event allow-list.

Credential-, token-, cookie-, secret- and session-like values remain redacted by the EmailOSINT safety layer before Social Graph V3 sees the payload.

## Social Mesh fan-out

A direct username may trigger the dataset-driven Site Probe Engine. An email first creates a deterministic local-part username pivot, allowing the same Social Mesh to run for that derived username.

Person-name search generates deterministic username candidates, but only the canonical first candidate is allowed to invoke the hundreds-site Social Mesh. Remaining variants enter at a deeper investigation depth so lower-cost profile sources can still evaluate them without multiplying hundreds of requests by every name spelling.

Found profile URLs become typed URL pivots and may continue through the existing bounded web/archive/domain pipeline.

## Phone intelligence

`phonenumbers==9.0.38` is pinned for offline numbering-plan metadata. It can report, where the library has data:

- E.164/international/national formatting;
- country/region;
- number type;
- carrier label;
- general geographic description;
- associated time zones.

It explicitly does **not** claim to identify the owner, track a phone, or provide a precise current location. HIBP remains an optional keyed account-exposure source for phone/email identifiers.

## Truth model

`FOUND` means a configured source produced a positive account-presence signal. It does not mean two accounts belong to the same human.

Identity resolution remains separate from source observation. Same-username similarity is insufficient by itself to merge identities.

## Bounded operation

The existing investigation governance remains in force. `MAX` retains a hard 300-second deadline. Dataset probes run in an isolated subprocess and therefore can be killed by the parent research engine if their time budget expires.

## UI

Parity UI now renders a dedicated Social Graph section with prominent Google, Dating, Social and Messaging counts, category-grouped account cards, source provenance, evidence/profile links, and relationship-graph counts. Raw machine data remains under the DEV disclosure.

## Verification

Offline CI covers:

- category classification;
- explicit service-category precedence;
- WMN and Sherlock dataset parsing;
- dataset deduplication;
- side-effect guard for POST probes;
- ambiguous HTTP-200 handling;
- positive/negative signature precedence;
- catch-all EmailOSINT event classification;
- merging of Site Probe Engine results into the Social Graph;
- offline phone metadata truth constraints;
- JavaScript syntax and Social Graph UI contract;
- exact `phonenumbers` dependency pin.

A green CI proves code, dependency and container contracts. It does not claim that every external site is reachable or unchanged at runtime; live probe outcomes remain observable per source.
