-- Sherlock Phase 2: synthetic evidence metadata target model. NOT deployed.
-- Requires migrations 001 and 002. Only intended for a versioned isolated CI DB.
-- A trusted server must bind tenant/case/actor context. Do not expose raw SQL.
BEGIN;
CREATE TABLE IF NOT EXISTS cf_case_artifacts (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  artifact_id text NOT NULL,
  filename text NOT NULL,
  version integer NOT NULL CHECK(version > 0),
  mime_type text NOT NULL,
  byte_length integer NOT NULL CHECK(byte_length > 0),
  sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
  storage_ref text NOT NULL,
  classification text NOT NULL CHECK(classification='SYNTHETIC'),
  scan_status text NOT NULL CHECK(scan_status IN ('UNSCANNED','QUARANTINED')),
  acquired_at timestamptz NOT NULL,
  uploaded_by text NOT NULL,
  created_at timestamptz NOT NULL,
  scope_sha256 text NOT NULL,
  PRIMARY KEY (tenant_id,case_id,artifact_id),
  UNIQUE (tenant_id,case_id,sha256),
  UNIQUE (tenant_id,case_id,filename,version),
  FOREIGN KEY (tenant_id,case_id) REFERENCES cf_cases(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS cf_case_evidence_spans (
  tenant_id text NOT NULL,
  case_id text NOT NULL,
  evidence_id text NOT NULL,
  artifact_id text NOT NULL,
  locator_kind text NOT NULL CHECK(locator_kind IN ('BYTE_RANGE','CSV_ROW')),
  locator_value bigint NOT NULL CHECK(locator_value >= 0),
  locator_length bigint NOT NULL CHECK(locator_length > 0),
  quote_sha256 text NOT NULL CHECK(quote_sha256 ~ '^[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  created_by text NOT NULL,
  PRIMARY KEY(tenant_id,case_id,evidence_id),
  FOREIGN KEY (tenant_id,case_id,artifact_id)
    REFERENCES cf_case_artifacts(tenant_id,case_id,artifact_id)
);

ALTER TABLE cf_case_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE cf_case_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE cf_case_evidence_spans ENABLE ROW LEVEL SECURITY;
ALTER TABLE cf_case_evidence_spans FORCE ROW LEVEL SECURITY;

-- Both scope and current assignment are required for reads.
-- Write roles are checked again by application middleware and in RLS.
CREATE POLICY cf_artifact_read ON cf_case_artifacts FOR SELECT USING (
  tenant_id = NULLIF(current_setting('app.tenant_id', true),'')
  AND case_id = NULLIF(current_setting('app.case_id', true),'')
  AND EXISTS (
    SELECT 1 FROM cf_case_assignments a
    WHERE a.tenant_id=cf_case_artifacts.tenant_id
      AND a.case_id=cf_case_artifacts.case_id
      AND a.actor_id=NULLIF(current_setting('app.actor_id',true),'')
  )
);
CREATE POLICY cf_artifact_insert ON cf_case_artifacts FOR INSERT WITH CHECK (
  tenant_id = NULLIF(current_setting('app.tenant_id', true),'')
  AND case_id = NULLIF(current_setting('app.case_id', true),'')
  AND EXISTS (
    SELECT 1 FROM cf_case_assignments a
    WHERE a.tenant_id=cf_case_artifacts.tenant_id
      AND a.case_id=cf_case_artifacts.case_id
      AND a.actor_id=NULLIF(current_setting('app.actor_id',true),'')
      AND a.case_role IN ('OWNER','INVESTIGATOR')
  )
);
CREATE POLICY cf_span_read ON cf_case_evidence_spans FOR SELECT USING (
  tenant_id = NULLIF(current_setting('app.tenant_id', true),'')
  AND case_id = NULLIF(current_setting('app.case_id', true),'')
  AND EXISTS (
    SELECT 1 FROM cf_case_assignments a
    WHERE a.tenant_id=cf_case_evidence_spans.tenant_id
      AND a.case_id=cf_case_evidence_spans.case_id
      AND a.actor_id=NULLIF(current_setting('app.actor_id',true),'')
  )
);
CREATE POLICY cf_span_insert ON cf_case_evidence_spans FOR INSERT WITH CHECK (
  tenant_id = NULLIF(current_setting('app.tenant_id', true),'')
  AND case_id = NULLIF(current_setting('app.case_id', true),'')
  AND EXISTS (
    SELECT 1 FROM cf_case_assignments a
    WHERE a.tenant_id=cf_case_evidence_spans.tenant_id
      AND a.case_id=cf_case_evidence_spans.case_id
      AND a.actor_id=NULLIF(current_setting('app.actor_id',true),'')
      AND a.case_role IN ('OWNER','INVESTIGATOR')
  )
);
CREATE INDEX IF NOT EXISTS idx_cf_artifact_case ON cf_case_artifacts(tenant_id,case_id,filename,version);
CREATE INDEX IF NOT EXISTS idx_cf_span_artifact ON cf_case_evidence_spans(tenant_id,case_id,artifact_id);
COMMIT;

-- OPEN GATES: no UPDATE/DELETE grants (append-only application role); provisioning,
-- owner handling, key management, WORM audit, encrypted object storage, DLP/AV,
-- public API auth, and production legal review are NOT implemented.
