# Sherlock OSA — Phase 2 synthetic evidence intake

Status: **synthetic fixtures only**, no real customer files, no real-person targets, no
public API, no model inference, no network probes. This document is an implementation
boundary, NOT an authorization to deploy production.

## Implemented components

- \`src/sherlock_osa/case_artifacts.py\`: synthetic-only upload of bounded in-memory
  bytes, expected SHA-256 verification, extension/MIME format check, local atomic
  fixture file write, SQLite metadata transaction, per-tenant/per-case access,
  duplicate rejection, per-filename versions, tamper check, bounded byte-offset
  citations for UTF-8 text/CSV, and audit append.
- \`tests/test_case_artifacts.py\`: only fictional fixture data.
- \`migrations/003_case_artifacts_synthetic.sql\`: unapplied production-schema
  candidate, RLS against current assignment and trusted case/tenant context.
- \`tests/postgres/test_artifacts_rls.sql\`: fixture-only PostgreSQL 16 RLS tests.
- \`.github/workflows/case-security-isolated.yml\`: branch-only ephemeral CI
  tests (SQLite + PostgreSQL). Existing project CI remains unchanged.

### File contract

- TXT UTF-8, CSV UTF-8, PDF by basic header/trailer checks.
- Max 512 KiB per fixture; MIME must match extension and bounded payload validation.
- All PDF bytes are **QUARANTINED**: no OCR, extraction, embedded scripts, or
  citation parsing. PDF validity/absence of malware is **NOT** established.
- TXT/CSV are **UNSCANNED**, not malware-free. No bytes are sent to LLM or external tools.
- Only CaseScope with \`lawful_basis_reference=DEMO-SYNTHETIC-*\` and
  \`case.artifact.ingest\` is eligible; this is a policy flag, **not** technical
  proof that inputs contain no real personal data. DO NOT use with real data.
- No user-selectable storage path: metadata only returns digests, artifact IDs,
  type, timestamp and scan state; no external upload endpoint.

### Security truth

The backing store is a **local unencrypted test fixture filesystem**, not S3,
encrypted storage, object lock, or WORM. SHA-256 detects changed bytes; it does not
prove who originally possessed the file. SQLite writes and filesystem writes are
not a distributed atomic transaction: a crash can leave orphan fixture objects.
An external reconciler, immutable object storage, AV, MIME sandboxing, and
post-upload access verification are required for real customers.

The existing CasePrincipal is not wired to production identity. Neither custom
PostgreSQL GUCs nor RLS alone authenticate tenants and actors, and an attacker
who can run arbitrary SQL may forge those settings. Do not expose a SQL executor
or an unauthenticated endpoint. Case-scoped access must be enforced via trusted
identity, transaction-scoped context and least-privilege DB roles.

External audit checkpoint persistence is NOT connected, and the current
PostgreSQL schema lacks audited append-only enforcement. Prior signed audit
checkpoints only detect truncation if a trusted operator keeps one independently.

## Definition of Done / current boundary

- Distinct tenants and distinct cases cannot read/write synthetic fixtures in tests.
- Viewer metadata access does not grant fixture write access.
- Hash mismatch, MIME mismatch, oversized, duplicate, corrupted payload fail closed.
- Evidence spans cite exact bytes and digest; PDF cannot create text spans.
- Restart opens existing synthetic metadata and verifies blob digest.
- No imported content can instruct the runtime: it remains unexecuted bytes.

## Blockers before Phase 3 or customer testing

1. Confirm trusted IdP, actor-to-tenant mapping and restricted SQL API approach.
2. Confirm encrypted object store + per-case retention/delete/export design.
3. Confirm independently durable audit anchoring (WORM/object lock/KMS).
4. Add real AV/sandbox and battle-tested PDF/CSV parsing services with limits.
5. Map AI/planner approval to exact CaseScope and minimum-permission tools.
6. Legal/privacy review before processing any identifiable subject data.
7. Keep proprietary Detective Brain/LLM prompts in separately approved PRIVATE code.

No claim of production deployment, legal compliance or completed Detective AI.
