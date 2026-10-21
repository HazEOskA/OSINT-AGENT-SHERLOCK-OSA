-- PostgreSQL 16/17 isolated RLS security tests. Synthetic data ONLY.
-- psql -X -v ON_ERROR_STOP=1 -f tests/postgres/test_case_rls.sql
-- Run as temporary CI database superuser (creates a non-BYPASSRLS test role).
\set ON_ERROR_STOP on

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cf_rls_test_client') THEN
    CREATE ROLE cf_rls_test_client NOLOGIN NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO cf_rls_test_client;
GRANT SELECT ON cf_tenants, cf_memberships, cf_cases, cf_case_assignments,
                cf_scopes, cf_plans, cf_approvals, cf_audit TO cf_rls_test_client;
GRANT INSERT, UPDATE, DELETE ON cf_scopes TO cf_rls_test_client;

INSERT INTO cf_tenants(tenant_id) VALUES ('t-a'),('t-b');
INSERT INTO cf_memberships(tenant_id,actor_id,role) VALUES
 ('t-a','alice','OWNER'),('t-a','bob','INVESTIGATOR'),
 ('t-a','erin','VIEWER'),('t-b','alice','OWNER');
INSERT INTO cf_cases(tenant_id,case_id,title,purpose,created_by,created_at) VALUES
 ('t-a','a-1','Synthetic A1','test','alice',now()),
 ('t-a','a-2','Synthetic A2','test','alice',now()),
 ('t-b','b-1','Synthetic B1','test','alice',now());
INSERT INTO cf_case_assignments(tenant_id,case_id,actor_id,case_role,granted_by,created_at) VALUES
 ('t-a','a-1','alice','OWNER','alice',now()),
 ('t-a','a-1','bob','INVESTIGATOR','alice',now()),
 ('t-a','a-2','alice','OWNER','alice',now()),
 ('t-b','b-1','alice','OWNER','alice',now());

DO $$
DECLARE count_rls int;
BEGIN
 SELECT count(*) INTO count_rls
 FROM pg_class WHERE relname IN ('cf_cases','cf_scopes','cf_plans','cf_approvals','cf_audit','cf_case_assignments')
 AND relrowsecurity AND relforcerowsecurity;
 IF count_rls <> 6 THEN RAISE EXCEPTION 'RLS_FORCE_MISSING expected 6 got %', count_rls; END IF;
 IF (SELECT rolbypassrls FROM pg_roles WHERE rolname='cf_rls_test_client')
 THEN RAISE EXCEPTION 'TEST_ROLE_BYPASSES_RLS'; END IF;
END $$;

-- In the absence of all trusted settings: absolutely no rows visible.
SET ROLE cf_rls_test_client;
BEGIN;
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 0 THEN RAISE EXCEPTION 'UNSET_CONTEXT_EXPOSES_CASES'; END IF;
 IF (SELECT count(*) FROM cf_case_assignments) <> 0 THEN RAISE EXCEPTION 'UNSET_CONTEXT_EXPOSES_ASSIGNMENTS'; END IF;
END $$;
ROLLBACK;

-- Bob is assigned a-1, but must not see a-2 in the SAME tenant.
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.actor_id','bob',true);
SELECT set_config('app.case_id','a-1',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 1 THEN RAISE EXCEPTION 'EXPECTED_ONE_CASE_FOR_BOB'; END IF;
 IF (SELECT count(*) FROM cf_cases WHERE case_id='a-2') <> 0 THEN RAISE EXCEPTION 'CROSS_CASE_LEAK'; END IF;
 IF (SELECT count(*) FROM cf_case_assignments) <> 1 THEN RAISE EXCEPTION 'ASSIGNMENT_LEAK'; END IF;
END $$;
ROLLBACK;

-- Bob cannot see a-2 even if middleware changes case context.
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.actor_id','bob',true);
SELECT set_config('app.case_id','a-2',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 0 THEN RAISE EXCEPTION 'SAME_TENANT_UNASSIGNED_CASE_LEAK'; END IF;
END $$;
ROLLBACK;

-- Bob cannot read tenant B just by pointing the case context at B.
BEGIN;
SELECT set_config('app.tenant_id','t-b',true);
SELECT set_config('app.actor_id','bob',true);
SELECT set_config('app.case_id','b-1',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 0 THEN RAISE EXCEPTION 'CROSS_TENANT_READ_LEAK'; END IF;
END $$;
ROLLBACK;

-- SELECT/INSERT/UPDATE/DELETE must all fence inaccessible case rows.
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.actor_id','bob',true);
SELECT set_config('app.case_id','a-1',true);
DO $$
DECLARE updated int;
BEGIN
 INSERT INTO cf_scopes(tenant_id,case_id,revision,scope_data,scope_sha256,created_by,created_at)
 VALUES('t-a','a-1',1,'{}','fixture','bob',now());
 IF (SELECT count(*) FROM cf_scopes) <> 1 THEN RAISE EXCEPTION 'OWN_SCOPE_INSERT_FAILED'; END IF;

 UPDATE cf_scopes SET scope_sha256='tampered' WHERE case_id='a-2';
 GET DIAGNOSTICS updated = ROW_COUNT;
 IF updated <> 0 THEN RAISE EXCEPTION 'CROSS_CASE_UPDATE_ALLOWED'; END IF;

 DELETE FROM cf_scopes WHERE case_id='a-2';
 GET DIAGNOSTICS updated = ROW_COUNT;
 IF updated <> 0 THEN RAISE EXCEPTION 'CROSS_CASE_DELETE_ALLOWED'; END IF;

 BEGIN
   INSERT INTO cf_scopes(tenant_id,case_id,revision,scope_data,scope_sha256,created_by,created_at)
   VALUES('t-a','a-2',1,'{}','forged','bob',now());
   RAISE EXCEPTION 'CROSS_CASE_INSERT_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 BEGIN
   INSERT INTO cf_scopes(tenant_id,case_id,revision,scope_data,scope_sha256,created_by,created_at)
   VALUES('t-b','b-1',1,'{}','forged','bob',now());
   RAISE EXCEPTION 'CROSS_TENANT_INSERT_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
ROLLBACK;
RESET ROLE;

-- Revocation by the trusted provisioner revokes visibility immediately.
DELETE FROM cf_case_assignments WHERE tenant_id='t-a' AND case_id='a-1' AND actor_id='bob';
SET ROLE cf_rls_test_client;
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.actor_id','bob',true);
SELECT set_config('app.case_id','a-1',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 0 THEN RAISE EXCEPTION 'REVOKED_MEMBER_STILL_SEES_CASE'; END IF;
END $$;
ROLLBACK;

-- SET LOCAL context must not leak to the next transaction/pooled session.
BEGIN;
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_cases) <> 0 THEN RAISE EXCEPTION 'STALE_TRANSACTION_CONTEXT'; END IF;
END $$;
ROLLBACK;
RESET ROLE;

-- IMPORTANT limitation intentionally NOT misrepresented as a passing security test:
-- A SQL-injection attacker with arbitrary SQL under the application role can issue
-- SET LOCAL app.actor_id='alice', app.tenant_id='t-b', app.case_id='b-1'.
-- PostgreSQL custom GUCs alone cannot authenticate these claims.
-- Trusted SQL middleware, restrictions on dynamic SQL and role privileges remain BLOCKED.
\echo 'PostgreSQL synthetic tenant/case RLS tests completed (not production authorization proof)'
