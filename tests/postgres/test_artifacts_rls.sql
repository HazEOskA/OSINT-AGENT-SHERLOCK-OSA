-- Synthetic PostgreSQL Phase 2 RLS tests, run AFTER test_case_rls.sql.
-- psql -X -v ON_ERROR_STOP=1 -f tests/postgres/test_artifacts_rls.sql
\set ON_ERROR_STOP on
GRANT SELECT, INSERT ON cf_case_artifacts, cf_case_evidence_spans TO cf_rls_test_client;
GRANT SELECT ON cf_case_assignments TO cf_rls_test_client;
INSERT INTO cf_case_assignments(tenant_id,case_id,actor_id,case_role,granted_by,created_at)
VALUES('t-a','a-1','erin','VIEWER','alice',now());

DO $$
DECLARE v int;
BEGIN
 SELECT count(*) INTO v FROM pg_class WHERE relname IN
 ('cf_case_artifacts','cf_case_evidence_spans') AND relrowsecurity AND relforcerowsecurity;
 IF v <> 2 THEN RAISE EXCEPTION 'ARTIFACT_RLS_MISSING'; END IF;
END $$;

SET ROLE cf_rls_test_client;
-- Fail closed when GUC context is absent.
BEGIN;
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_case_artifacts) <> 0 THEN RAISE EXCEPTION 'MISSING_CONTEXT_LEAK'; END IF;
 IF (SELECT count(*) FROM cf_case_evidence_spans) <> 0 THEN RAISE EXCEPTION 'MISSING_CONTEXT_SPAN_LEAK'; END IF;
END $$;
ROLLBACK;

-- Owner sees assigned case only and may INSERT synthetic metadata and citation.
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.case_id','a-1',true);
SELECT set_config('app.actor_id','alice',true);
INSERT INTO cf_case_artifacts(tenant_id,case_id,artifact_id,filename,version,mime_type,
 byte_length,sha256,storage_ref,classification,scan_status,acquired_at,uploaded_by,created_at,scope_sha256)
VALUES('t-a','a-1','art-fixture-1','fiction.txt',1,'text/plain',
 7,repeat('a',64),'fixtures/a1/art-1','SYNTHETIC','UNSCANNED',now(),'alice',now(),'scope-sha');
INSERT INTO cf_case_evidence_spans(tenant_id,case_id,evidence_id,artifact_id,locator_kind,
 locator_value,locator_length,quote_sha256,observed_at,created_by)
VALUES('t-a','a-1','ev-fixture-1','art-fixture-1','BYTE_RANGE',
 0,3,repeat('b',64),now(),'alice');
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_case_artifacts) <> 1 THEN RAISE EXCEPTION 'OWNER_READ_WRITTEN_ARTIFACT'; END IF;
 IF (SELECT count(*) FROM cf_case_evidence_spans) <> 1 THEN RAISE EXCEPTION 'OWNER_READ_WRITTEN_SPAN'; END IF;
END $$;
-- Cross-case INSERT/SELECT cannot happen even in same tenant.
DO $
BEGIN
 BEGIN
 INSERT INTO cf_case_artifacts(tenant_id,case_id,artifact_id,filename,version,mime_type,
 byte_length,sha256,storage_ref,classification,scan_status,acquired_at,uploaded_by,created_at,scope_sha256)
 VALUES('t-a','a-2','forged','forged.txt',1,'text/plain',1,repeat('d',64),
 'fixtures/a2/no','SYNTHETIC','UNSCANNED',now(),'alice',now(),'scope-sha');
 RAISE EXCEPTION 'CROSS_CASE_ARTIFACT_WRITE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $;
-- Cross-tenant INSERT impossible.
DO $$
BEGIN
 BEGIN
  INSERT INTO cf_case_artifacts(tenant_id,case_id,artifact_id,filename,version,mime_type,
    byte_length,sha256,storage_ref,classification,scan_status,acquired_at,uploaded_by,created_at,scope_sha256)
  VALUES('t-b','b-1','forged-b','forged.txt',1,'text/plain',1,repeat('e',64),
    'fixtures/b1/no','SYNTHETIC','UNSCANNED',now(),'alice',now(),'scope-sha');
  RAISE EXCEPTION 'CROSS_TENANT_ARTIFACT_WRITE_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
ROLLBACK;

-- Recreate fixture in single committed transaction through set_config; verified reader isolation.
RESET ROLE;
INSERT INTO cf_case_artifacts(tenant_id,case_id,artifact_id,filename,version,mime_type,
byte_length,sha256,storage_ref,classification,scan_status,acquired_at,uploaded_by,created_at,scope_sha256)
VALUES('t-a','a-1','art-fixture-2','fixture.txt',1,'text/plain',7,
repeat('f',64),'fixtures/a1/art-2','SYNTHETIC','UNSCANNED',now(),'alice',now(),'scope-sha');
INSERT INTO cf_case_evidence_spans(tenant_id,case_id,evidence_id,artifact_id,locator_kind,
 locator_value,locator_length,quote_sha256,observed_at,created_by)
VALUES('t-a','a-1','ev-fixture-2','art-fixture-2','BYTE_RANGE',0,3,repeat('c',64),now(),'alice');

SET ROLE cf_rls_test_client;
BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.case_id','a-1',true);
SELECT set_config('app.actor_id','erin',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_case_artifacts) <> 1 THEN RAISE EXCEPTION 'VIEWER_CANNOT_READ'; END IF;
 IF (SELECT count(*) FROM cf_case_evidence_spans) <> 1 THEN RAISE EXCEPTION 'VIEWER_CANNOT_READ_SPAN'; END IF;
 BEGIN
  INSERT INTO cf_case_artifacts(tenant_id,case_id,artifact_id,filename,version,mime_type,
   byte_length,sha256,storage_ref,classification,scan_status,acquired_at,uploaded_by,created_at,scope_sha256)
  VALUES('t-a','a-1','viewer-forgery','f.txt',1,'text/plain',1,repeat('9',64),
   'invalid','SYNTHETIC','UNSCANNED',now(),'erin',now(),'scope-sha');
  RAISE EXCEPTION 'VIEWER_INSERT_ALLOWED';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
END $$;
ROLLBACK;

BEGIN;
SELECT set_config('app.tenant_id','t-a',true);
SELECT set_config('app.case_id','a-2',true);
SELECT set_config('app.actor_id','erin',true);
DO $$
BEGIN
 IF (SELECT count(*) FROM cf_case_artifacts) <> 0 THEN RAISE EXCEPTION 'SAME_TENANT_UNASSIGNED_LEAK'; END IF;
END $$;
ROLLBACK;
RESET ROLE;
\echo 'Synthetic artifact and evidence RLS checks passed; application identity hardening remains BLOCKED'
