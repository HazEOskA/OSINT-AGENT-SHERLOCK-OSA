# Sherlock OSA — Research Source Pack v0.3

## Contract

The source pack is subordinate to `RESEARCH_PASSIVE`. It cannot create its own mission, widen scope, enable a new route, or bypass the OSA Engine receipt and Capability Broker.

Each remote source is executed in a separate Python subprocess. The identifier is transmitted through stdin, never command-line arguments. The parent process enforces a bounded timeout and kills the subprocess on expiry.

## Sources

### Holehe 1.61

- input: `EMAIL`
- capability: `osint.email.lookup`
- role: account-registration signals across 100+ services
- retained fields: service/domain existence signal, aggregate rate-limit/error counts
- deliberately discarded: recovery email, recovery phone and other recovery hints
- source recursion depth: max 2
- upstream license: GPLv3

### Maigret 0.6.4

- input: `USERNAME`
- capability: `osint.username.lookup`
- role: public-profile discovery; database ranking limited to top 500 sites per lookup
- parsing: enabled
- returned pivots: validated `URL`, `EMAIL`, `USERNAME` only
- arbitrary IDs and arbitrary text are never auto-promoted to pivots
- source recursion depth: max 1
- upstream license: MIT

## Poison / returning-agent boundary

Remote profile data is untrusted. Source workers may collect structured remote fields, but the parent research engine runs `PoisonChecker` before a result can create pivots. Evidence marked `TAINTED` remains visible as evidence but cannot expand the graph.

The source worker also applies strict typed pivot validation. For example `javascript:` URLs and arbitrary numeric IDs are not promoted.

## Global bounds

- hard research deadline: 300 s
- per source module timeout: 60 s
- graph max depth: 4
- identifiers: 256
- evidence records: 1000
- engine module invocations: 1200
- parallel module tasks: 24
- stop after no trusted progress: 2 rounds

Provider-specific source depth bounds exist in addition to the global limits to prevent recursive mass enumeration.

## Retention

Raw source results are returned to the caller but not persisted to SQLite. Passive target plaintext is not stored in the append-only evidence ledger; target/scope evidence uses hashes. With default `purge_after=true`, local mission and decision rows are removed after the research response is prepared.

The evidence ledger retains aggregate/hash metadata such as result hash, seed-set hash, counts, timing, stop reason and tainted count.

## Truth states

`source_health()` proves package presence and exact pinned version only. It does not claim that every external site is reachable, has not changed its anti-bot flow, or will return a result. External reachability is therefore evaluated per lookup.

## Distribution boundary

The default `Dockerfile` installs Apache-2.0 Sherlock core only. `Dockerfile.research` installs the optional third-party source pack. Holehe remains GPLv3 and Maigret remains MIT; Sherlock does not vendor or relicense their source code.

Commercial use is possible, but anyone distributing the research image/package must satisfy the applicable third-party license obligations. SaaS operators should also review target-site terms, privacy law, retention policy and lawful-basis requirements for their jurisdiction and use case.
