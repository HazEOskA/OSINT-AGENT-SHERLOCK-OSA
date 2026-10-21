-- Phase 0-1 P0 hardening migration: per-case need-to-know RLS.
-- Apply AFTER 001_case_foundation_postgres.sql; NOT DEPLOYED.
-- Privileged fixture/provisioner creates cf_case_assignments in one trusted transaction.
-- The application role must NOT have INSERT/UPDATE/DELETE on cf_case_assignments.
-- SET LOCAL app.tenant_id, app.case_id and app.actor_id require trusted middleware.
-- IMPORTANT: PostgreSQL custom GUCs CAN be changed by roles with arbitrary SQL.
-- RLS context alone is NOT protection against SQL injection / raw SQL access.
BEGIN;

ALTER TABLE cf_cases ADD COLUMN IF NOT EXISTS acl_revision bigint NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS cf_case_assignments (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  actor_id text NOT NULL,
  case_role text NOT NULL CHECK(case_role IN ('OWNER','INVESTIGATOR','REVIEWER','VIEWER')),
  granted_by text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,case_id,actor_id),
  FOREIGN KEY(tenant_id,case_id) REFERENCES cf_cases(tenant_id,case_id),
  FOREIGN KEY(tenant_id,actor_id) REFERENCES cf_memberships(tenant_id,actor_id)
);

ALTER TABLE cf_case_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE cf_case_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_fence ON cf_case_assignments;
DROP POLICY IF EXISTS assignment_self ON cf_case_assignments;
CREATE POLICY assignment_self ON cf_case_assignments
  FOR SELECT USING (
    tenant_id = NULLIF(current_setting('app.tenant_id',true),'')
    AND actor_id = NULLIF(current_setting('app.actor_id',true),'')
  );

-- These case-bound data tables require an explicit *current* assignment and
-- a trusted context bound to one tenant, actor, and case. No implicit tenant
-- OWNER access to every case.
DO $$
DECLARE tablename text;
BEGIN
  FOREACH tablename IN ARRAY ARRAY[
    'cf_cases','cf_scopes','cf_plans','cf_approvals','cf_audit'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_fence ON %I', tablename);
    EXECUTE format('DROP POLICY IF EXISTS case_membership_fence ON %I', tablename);
    EXECUTE format(
      'CREATE POLICY case_membership_fence ON %I USING (
        tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')
        AND case_id = NULLIF(current_setting(''app.case_id'', true), '''')
        AND EXISTS (
          SELECT 1 FROM cf_case_assignments a
          WHERE a.tenant_id = %I.tenant_id
            AND a.case_id = %I.case_id
            AND a.actor_id = NULLIF(current_setting(''app.actor_id'', true), '''')
        )
      ) WITH CHECK (
        tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')
        AND case_id = NULLIF(current_setting(''app.case_id'', true), '''')
        AND EXISTS (
          SELECT 1 FROM cf_case_assignments a
          WHERE a.tenant_id = %I.tenant_id
            AND a.case_id = %I.case_id
            AND a.actor_id = NULLIF(current_setting(''app.actor_id'', true), '''')
        )
      )', tablename, tablename, tablename, tablename, tablename
    );
  END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_cf_assignments_actor
  ON cf_case_assignments(tenant_id,actor_id,case_id);
COMMIT;

-- Deployment blockers:
-- * authenticated SQL middleware and trusted per-request transaction context;
-- * enforce no arbitrary SQL access to the app role and explicit least-privileges;
-- * service-controlled case provisioning: RLS makes naive self-insertion impossible;
-- * append-only audit/approval controls, immutable externally anchored log;
-- * integration test with a real auth service and approved user role privileges.
