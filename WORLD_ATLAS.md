# WORLD OSINT ATLAS

Preview-only Sherlock OSA feature.

## Live catalog inputs

The atlas dynamically aggregates and de-duplicates:

1. OSINT Framework — lockfale/OSINT-Framework public/arf.json
2. Awesome OSINT — jivoi/awesome-osint
3. Awesome Threat Intelligence — hslatman/awesome-threat-intelligence
4. OSINT4ALL — osint4all/osint4all.github.io README.md (GitHub mirror of start.me OSINT4ALL)
5. Sherlock native research-source registry from /api/v1/health

The OSINT Framework dataset is fetched at runtime instead of copied into this repo, so upstream additions appear without a Sherlock code release.

## Boundaries

- SHERLOCK LIVE: source is wired into Sherlock's runtime.
- CATALOG ONLY: resource is discoverable but is not automatically executed.
- Potentially intrusive/offensive categories remain catalog-only.
- Inclusion is not an endorsement, availability guarantee, identity claim, or legal authorization.

The catalog keeps provider metadata such as API, local-install, registration, pricing, and OPSEC fields when the upstream source provides them.

## P0.2 catalogue integration (catalogue-only)

- The backend uses the existing Markdown parser to read the OSINT4ALL GitHub mirror; no third-party code is copied or executed.
- `GET /api/v1/world-atlas/catalog` returns normalized catalog entries, preserved source provenance, and source health. `/tools` consumes this endpoint instead of independently crawling raw catalogs.
- `SHERLOCK LIVE` labels only currently ready native adapters from the existing runtime health endpoint; gated adapters are explicitly distinguished.
- All OSINT4ALL entries are `CATALOG_ONLY` or `CATALOG_ONLY_RESTRICTED`, including any potentially intrusive resource. No automatic new tools or permissions are granted.
- Unreachable upstream catalogs are shown as errors/degraded states, not as successful sync; cached source errors are preserved until refresh.
- Live reachability and licensing of third-party tools remain unverified by offline fixtures. Catalog inclusion is not execution authorization.
- This phase does not change Search Core, research service, source worker, Source Registry, or Sherlock Enterprise.

## P0.3 Agent Capability Registry (read-only)

- Authenticated operator-only endpoint: `GET /api/v1/agent/capabilities` using existing Bearer token validation. Unauthenticated requests receive `401`.
- The endpoint composes native `SOURCE_DESCRIPTORS` and the existing World Atlas catalog in a versioned, stable, deduplicated inventory, preserving upstream provenance.
- `ADAPTER_READY` means dependencies and local configuration are ready and an existing policy mode matches; it **does not** prove live provider reachability, scope authorization, or execution.
- `CATALOG_ONLY`, `RESTRICTED`, and `UNAVAILABLE` entries cannot be executed by the registry. Unknown catalog execution classes fail closed to `RESTRICTED`.
- Catalog resources have no runtime adapter and no granted execution authority. Every entry explicitly has `authorization_granted: false`; existing `CapabilityBroker` remains the sole signed-scope authorization authority.
- Provider pricing, licensing, and external availability are not independently validated. The registry never contacts providers other than the existing catalog-sync fetch for metadata.
- No modifications to Search Core, `source_registry.py`, `policy.py`, source workers, Enterprise, or execution routes in P0.3.
