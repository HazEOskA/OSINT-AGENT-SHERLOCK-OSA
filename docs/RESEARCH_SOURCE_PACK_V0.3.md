# Sherlock OSA — Research Source Pack v0.3

## Contract

The source pack is subordinate to `RESEARCH_PASSIVE`. It cannot create its own mission, widen scope, enable a new route, or bypass the OSA Engine receipt and Capability Broker.

Every network source runs in a separate Python subprocess. The identifier is transmitted through stdin, never command-line arguments. The parent process owns timeout/cancellation and kills the subprocess on expiry.

## Sources

### Holehe 1.61

- input: `EMAIL`
- capability: `osint.email.lookup`
- role: account-registration signals across 100+ services
- retained: service/domain existence signal and aggregate rate-limit/error counts
- discarded: recovery email, recovery phone and other recovery hints
- source depth: max 2
- upstream license: GPLv3

### Maigret 0.6.4

- input: `USERNAME`
- capability: `osint.username.lookup`
- role: public-profile discovery; top 500 ranked sites per lookup
- parsing: enabled
- pivots: validated `URL`, `EMAIL`, `USERNAME` only
- arbitrary IDs/text are never auto-promoted
- source depth: max 1
- upstream license: MIT

### Internet Archive CDX

- input: `URL | DOMAIN`
- capabilities: `osint.url.trace | osint.domain.passive`
- role: historical public URL/capture discovery
- exact matching for URL seeds; domain matching for DOMAIN seeds
- response is normalized from CDX JSON fields `timestamp, original, statuscode, mimetype`
- only valid HTTP(S) originals are retained
- URL source depth: max 2; domain source depth: max 1

### crt.sh Certificate Transparency

- input: `DOMAIN`
- capability: `osint.domain.passive`
- role: public certificate-name/subdomain discovery
- JSON result names are normalized and restricted to the exact target domain or its subdomains
- wildcard prefix is stripped before validation
- source depth: max 1

## Example graph

`EMAIL -> local username/domain -> Holehe + Maigret -> profile URL -> Wayback -> historical URLs`

and in parallel:

`DOMAIN -> crt.sh -> validated subdomains`

Source-specific depth limits prevent archived URLs/subdomains from recursively re-triggering the same provider indefinitely.

## Poison / returning-agent boundary

Remote data is untrusted. Source workers collect structured remote fields, but the parent research engine runs `PoisonChecker` before a result can create pivots. `TAINTED` evidence remains evidence but cannot expand the graph.

Typed pivot validation rejects non-http(s) URLs, arbitrary numeric IDs, out-of-scope certificate names and malformed domains before they reach graph expansion.

## Global bounds

- hard research deadline: 300 s
- parent per-module ceiling: 60 s
- source subprocess internal ceiling: 55 s
- graph max depth: 4
- identifiers: 256
- evidence records: 1000
- module invocations: 1200
- parallel module tasks: 24
- stop after no trusted progress: 2 rounds

## Retention

Raw source results are returned to the caller but not persisted to SQLite. Passive target plaintext is not stored in the append-only evidence ledger; target/scope evidence uses hashes. With default `purge_after=true`, local mission and decision rows are removed after the research response is prepared.

The ledger retains aggregate/hash metadata: result hash, seed-set hash, counts, timing, stop reason and tainted count. This local purge does not claim deletion from external providers or the OSA Engine.

## Truth states

`source_health()` proves local source registration plus exact package versions for Holehe/Maigret. It does not claim that every external service is reachable or unchanged. Internet reachability and provider behavior are evaluated per lookup.

## Distribution boundary

The default `Dockerfile` installs Apache-2.0 Sherlock core only. `Dockerfile.research` installs optional Holehe/Maigret dependencies. Holehe remains GPLv3 and Maigret remains MIT; Sherlock does not vendor or relicense their source code. Wayback/CDX and crt.sh resolvers are Sherlock adapter code calling public interfaces.

Commercial use is possible, but distribution and SaaS operation still require the applicable third-party license, site terms, privacy-law, lawful-basis and retention review for the actual jurisdiction/use case.
