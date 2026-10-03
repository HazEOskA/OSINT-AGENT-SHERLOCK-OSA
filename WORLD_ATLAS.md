# WORLD OSINT ATLAS

Preview-only Sherlock OSA feature.

## Live catalog inputs

The atlas dynamically aggregates and de-duplicates:

1. OSINT Framework — lockfale/OSINT-Framework public/arf.json
2. Awesome OSINT — jivoi/awesome-osint
3. Awesome Threat Intelligence — hslatman/awesome-threat-intelligence
4. Sherlock native research-source registry from /api/v1/health

The OSINT Framework dataset is fetched at runtime instead of copied into this repo, so upstream additions appear without a Sherlock code release.

## Boundaries

- SHERLOCK LIVE: source is wired into Sherlock's runtime.
- CATALOG ONLY: resource is discoverable but is not automatically executed.
- Potentially intrusive/offensive categories remain catalog-only.
- Inclusion is not an endorsement, availability guarantee, identity claim, or legal authorization.

The catalog keeps provider metadata such as API, local-install, registration, pricing, and OPSEC fields when the upstream source provides them.
