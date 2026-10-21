-- Sherlock Case Foundation Phase 1: PostgreSQL target schema (NOT deployed).
-- Apply only after security review with a dedicated NON-BYPASSRLS application role.
-- The trusted auth middleware MUST set app.tenant_id in a transaction using SET LOCAL.
-- Never accept app.tenant_id or app.actor_id from an unauthenticated request body.
-- CREATE ROLE / privilege management, KMS, migrations orchestration, and backups are
-- deployment-specific and NOT provided by this document.

BEGIN;
CREATE TABLE IF NOT EXISTS cf_tenants (
  tenant_id text PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS cf_memberships (
  tenant_id text NOT NULL REFERENCES cf_tenants(tenant_id),
  actor_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('OWNER','INVESTIGATOR','REVIEWER','VIEWER')),
  PRIMARY KEY (tenant_id,actor_id)
);
CREATE TABLE IF NOT EXISTS cf_cases (
  tenant_id text NOT NULL REFERENCES cf_tenants(tenant_id),
  case_id text NOT NULL,
  title text NOT NULL,
  purpose text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS cf_scopes (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  revision integer NOT NULL CHECK(revision > 0),
  scope_data jsonb NOT NULL,
  scope_sha256 text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,case_id,revision),
  FOREIGN KEY(tenant_id,case_id) REFERENCES cf_cases(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS cf_plans (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  plan_id text NOT NULL,
  revision integer NOT NULL,
  scope_sha256 text NOT NULL,
  plan_data jsonb NOT NULL,
  plan_sha256 text NOT NULL,
  proposed_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,case_id,plan_id),
  FOREIGN KEY(tenant_id,case_id) REFERENCES cf_cases(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS cf_approvals (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  approval_id text NOT NULL,
  plan_id text NOT NULL,
  scope_sha256 text NOT NULL,
  plan_sha256 text NOT NULL,
  revision integer NOT NULL,
  actor_id text NOT NULL,
  decision text NOT NULL CHECK(decision IN ('APPROVE','DENY')),
  expires_at timestamptz NOT NULL,
  receipt_signature text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,case_id,approval_id),
  FOREIGN KEY(tenant_id,case_id) REFERENCES cf_cases(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS cf_audit (
  tenant_id text NOT NULL REFERENCES cf_tenants(tenant_id),
  seq bigint NOT NULL,
  case_id text,
  actor_id text NOT NULL,
  action text NOT NULL,
  target_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  payload_sha256 text NOT NULL,
  prev_hash text NOT NULL,
  event_hash text NOT NULL,
  PRIMARY KEY(tenant_id,seq)
);

-- RLS must be enabled AND forced: fail closed if tenant setting missing.
-- Table owners and privileged superusers may bypass RLS: never run apps as those roles.
DO $$
DECLARE tablename text;
BEGIN
  FOREACH tablename IN ARRAY ARRAY[
    'cf_tenants','cf_memberships','cf_cases','cf_scopes',
    'cf_plans','cf_approvals','cf_audit'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tablename);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tablename);
    EXECUTE format(
      'CREATE POLICY tenant_fence ON %I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'',true), '''')) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'',true), ''''))',
      tablename
    );
  END LOOP;
END $$;

-- Additional non-RLS guards are mandatory before production:
-- * tenant-scoped authenticated membership and role checks inside trusted API;
-- * no direct user SQL privileges, no RLS-bypass service credentials;
-- * append-only enforcement for cf_scopes, cf_approvals and cf_audit;
-- * external audit anchoring and key rotation;
-- * privilege separation for provisioning tenants/memberships.
COMMIT;
