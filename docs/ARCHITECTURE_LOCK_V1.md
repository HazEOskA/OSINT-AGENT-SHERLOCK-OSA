# Sherlock OSA — Architecture Lock V1 / Phase 0–1

**Status:** implementation foundation on isolated branch; **NOT PRODUCTION READY**.
**Approved target:** HazEOskA/OSINT-AGENT-SHERLOCK-OSA.
**Non-goals:** merge, production deploy, real-person investigations, LLM inference, OSINT execution, ingestion of customer documents, voice, multi-tenant production service.

## Goal / boundary

A private detective creates an authorized case, uploads legitimately held evidence in a future phase, receives explainable hypotheses, and resumes work with a case-scoped AI Companion. The current Phase 1 implements **only** identity-independent, offline authorization and data-contract foundations for that workflow.

The existing public Apache-2.0 Sherlock source mesh, correlation engine and ProofReport remain unchanged. This public Phase 1 introduces no proprietary Detective Brain logic. **Do not place future commercial algorithms or client data in this public repo**; private-code location and license are a separate approval decision.

## Approved execution model

Authenticated Investigator → Tenant Membership → CaseScope rev N → Fixture-Only Plan → Different Authorized Approver → Signed Approval → Authorization Check → NO EXECUTOR.

External tool execution is physically unconnected. LLM content and supplied documents cannot define policy. A future adapter must independently validate principal, tenant, case, latest scope digest, exact plan digest, approval signature and expiry **inside the same execution gate**, and independently enforce source-level allowlists. Never wire full_search() directly to this gate without binding its automatic module capability selection to CaseScope first.

## Phase 1 files

- src/sherlock_osa/case_foundation.py: local single-process SQLite reference, tenant + membership, case, immutable per-revision scope, fixture-only plan, separate approver, HMAC receipt, chained audit and integrity verification.
- migrations/001_case_foundation_postgres.sql: **unapplied** production schema candidate. tenant_id on all rows, PostgreSQL RLS FORCE + missing-context denial. Requires real Postgres runtime tests and trusted identity context before use.
- tests/test_case_foundation.py: negative authorization, cross-tenant, stale scope, signature tamper, audit, persistence, no network.

## Invariants

1. Access requires a trusted CasePrincipal and membership loaded from the DB. Callers do not supply a role.
2. All case queries bind both tenant_id and case_id. Cross-tenant identifiers do not reveal data.
3. An approved plan binds immutable scope_sha256, plan_sha256, tenant/case and expiry; the latest approval supersedes older approvals. Plan proposer cannot approve their own plan (four-eyes).
4. Scope changes invalidate previously approved plans by hash and revision. A DENY, missing, expired or modified approval fails closed.
5. Receipt is HMAC SHA-256. Raw credentials are not logged. SQLite audit hashes detect casual tampering; no externally anchored WORM claim.
6. No source probes, customer files, personal identifiers or external AI calls occur in Phase 1. check_authorization() explicitly returns execution=NOT_CONNECTED.
7. The SQLite store is a **test-only prototype**, not secure or scalable multi-tenant storage. Postgres RLS, real authorization middleware and storage separation are deployment requirements.

## Next phase gates

- Bind a production identity provider to CasePrincipal, enforce transactional auth and role authorization; remove test-only provisioning from runtime packaging or isolate it to test harness.
- Test PostgreSQL RLS with multiple DB identities plus malicious SET LOCAL/missing tenant contexts, and ensure application role cannot bypass/alter policies.
- Build append-only database privileges and externally anchor audit digests; rotate keys and define retention/deletion.
- Add document ingest, evidence provenance, hypothesis/graph schema, case chat and report versioning only after this gate passes.
- Privacy/legal review before any personal data of clients or subjects.

## Claims / proof

This file is a contract and plan. Local tests prove only their asserted behavior. CI and any deployed system must be verified separately. No claim of production security, GDPR compliance or completed Detective AI is made.
