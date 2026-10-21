"""Synthetic-only Phase 2 evidence intake (prototype).

No HTTP exposure, external calls, OCR, LLM, AV claims, or real-subject support.
Originals are private *filesystem fixtures*; this is NOT encrypted/WORM storage.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sherlock_osa.case_foundation import (
    CaseFoundation, CaseGateError, CasePrincipal, WRITERS, _digest, _parse_utc,
)

MAX_FIXTURE_BYTES = 512 * 1024
SUPPORTED_TYPES = {
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".pdf": "application/pdf",
}
SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")
ARTIFACT_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_artifacts (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    mime_type TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    storage_ref TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification='SYNTHETIC'),
    scan_status TEXT NOT NULL CHECK(scan_status IN ('UNSCANNED','QUARANTINED')),
    acquired_at TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    scope_sha256 TEXT NOT NULL,
    PRIMARY KEY (tenant_id,case_id,artifact_id),
    UNIQUE (tenant_id,case_id,sha256),
    UNIQUE (tenant_id,case_id,filename,version),
    FOREIGN KEY (tenant_id,case_id) REFERENCES case_files(tenant_id,case_id)
);
CREATE TABLE IF NOT EXISTS case_evidence_spans (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    locator_kind TEXT NOT NULL CHECK(locator_kind IN ('BYTE_RANGE','CSV_ROW')),
    locator_value INTEGER NOT NULL,
    locator_length INTEGER NOT NULL,
    quote_sha256 TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id,case_id,evidence_id),
    FOREIGN KEY (tenant_id,case_id,artifact_id)
        REFERENCES case_artifacts(tenant_id,case_id,artifact_id)
);
CREATE INDEX IF NOT EXISTS idx_case_artifacts ON case_artifacts(tenant_id,case_id,filename,version);
CREATE INDEX IF NOT EXISTS idx_case_spans ON case_evidence_spans(tenant_id,case_id,artifact_id);
"""


def _filename(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not 1 <= len(value) <= 120:
        raise CaseGateError("INVALID_FILENAME")
    if value != value.strip() or value in {".", ".."}:
        raise CaseGateError("INVALID_FILENAME")
    if any(ord(ch) < 32 for ch in value) or "/" in value or "\\" in value or ":" in value:
        raise CaseGateError("INVALID_FILENAME")
    ext = Path(value).suffix.lower()
    if ext not in SUPPORTED_TYPES:
        raise CaseGateError("BLOCKED_EXTENSION")
    return value, ext


def _validate_payload(content: bytes, ext: str, claimed_media_type: str) -> str:
    if not isinstance(content, bytes):
        raise CaseGateError("INVALID_PAYLOAD")
    if not 0 < len(content) <= MAX_FIXTURE_BYTES:
        raise CaseGateError("FIXTURE_SIZE_BLOCKED")
    if claimed_media_type != SUPPORTED_TYPES[ext]:
        raise CaseGateError("MIME_MISMATCH")
    if ext == ".pdf":
        if not content.startswith(b"%PDF-") or b"%%EOF" not in content[-2048:]:
            raise CaseGateError("INVALID_PDF_MAGIC")
        # PDF parsing, embedded content, JS, or macros are NEVER executed.
        return "QUARANTINED"
    if b"\x00" in content or content.startswith((b"%PDF-", b"PK\x03\x04", b"\x7fELF")):
        raise CaseGateError("BINARY_DISGUISED_AS_TEXT")
    try:
        decoded = content.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CaseGateError("INVALID_UTF8") from exc
    if ext == ".csv":
        try:
            rows = list(csv.reader(io.StringIO(decoded, newline=""), strict=True))
        except csv.Error as exc:
            raise CaseGateError("INVALID_CSV") from exc
        if not 1 <= len(rows) <= 1000 or not all(1 <= len(row) <= 50 for row in rows):
            raise CaseGateError("CSV_BOUNDS_EXCEEDED")
    return "UNSCANNED"


class SyntheticCaseArtifactStore:
    """Persist fixture blobs + references without exposing a web entrypoint."""

    def __init__(self, foundation: CaseFoundation, root: str | Path) -> None:
        self.foundation = foundation
        self.root = Path(root).resolve()
        if self.root == foundation.path.parent.resolve():
            raise CaseGateError("ISOLATE_ARTIFACT_STORAGE")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with foundation._lock, foundation._connection() as db:
            db.executescript(ARTIFACT_SCHEMA)

    def _case_access(self, db: sqlite3.Connection, principal: CasePrincipal, case_id: str,
                     *, write: bool = False) -> tuple[sqlite3.Row, dict[str, Any], str]:
        self.foundation._authorized(db, principal, WRITERS if write else None)
        case = self.foundation._assert_case(db, principal, case_id, WRITERS if write else None)
        scope_row, scope = self.foundation._latest_scope(db, principal, case_id)
        if not scope["lawful_basis_reference"].startswith("DEMO-SYNTHETIC-"):
            raise CaseGateError("SYNTHETIC_CASE_ONLY")
        if _parse_utc(scope["expires_at"]) <= self.foundation._now():
            raise CaseGateError("SCOPE_EXPIRED")
        if write and "case.artifact.ingest" not in scope["allowed_capabilities"]:
            raise CaseGateError("INGEST_OUT_OF_SCOPE")
        return case, scope, str(scope_row["scope_sha256"])

    def _location(self, principal: CasePrincipal, case_id: str, artifact_id: str) -> Path:
        # Path never contains client names or caller-controlled relative components.
        tenant = hashlib.sha256(principal.tenant_id.encode()).hexdigest()
        case = hashlib.sha256(case_id.encode()).hexdigest()
        return self.root / tenant / case / artifact_id

    @staticmethod
    def _assert_digest(row: sqlite3.Row, data: bytes) -> None:
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["byte_length"]:
            raise CaseGateError("ARTIFACT_INTEGRITY_FAILED")

    def _artifact_row(self, db: sqlite3.Connection, principal: CasePrincipal,
                      case_id: str, artifact_id: str) -> sqlite3.Row:
        row = db.execute(
            "SELECT * FROM case_artifacts WHERE tenant_id=? AND case_id=? AND artifact_id=?",
            (principal.tenant_id, case_id, artifact_id),
        ).fetchone()
        if row is None:
            raise CaseGateError("ARTIFACT_NOT_FOUND")
        return row

    @staticmethod
    def _metadata(row: sqlite3.Row) -> dict[str, Any]:
        return {k: row[k] for k in (
            "artifact_id", "filename", "version", "mime_type", "byte_length",
            "sha256", "classification", "scan_status", "acquired_at",
            "uploaded_by", "created_at", "scope_sha256"
        )}

    def ingest(self, principal: CasePrincipal, case_id: str, *,
               filename: str, media_type: str, content: bytes,
               expected_sha256: str, acquired_at: str, origin: str) -> dict[str, Any]:
        filename, ext = _filename(filename)
        scan = _validate_payload(content, ext, media_type)
        if (not isinstance(expected_sha256, str) or not SHA256_HEX.fullmatch(expected_sha256)):
            raise CaseGateError("INVALID_EXPECTED_DIGEST")
        sha = hashlib.sha256(content).hexdigest()
        if sha != expected_sha256:
            raise CaseGateError("DIGEST_MISMATCH")
        if origin != "DEMO_SYNTHETIC":
            raise CaseGateError("SYNTHETIC_ORIGIN_REQUIRED")
        acquired = _parse_utc(acquired_at).isoformat()
        artifact_id = "artifact-" + uuid4().hex
        location = self._location(principal, case_id, artifact_id)
        with self.foundation._lock:
            # The only stored blob is a locally bounded, explicitly synthetic fixture.
            # Asymmetric filesystem/DB commit can leave an orphan, never a false receipt.
            staged: Path | None = None
            try:
                with self.foundation._connection() as db:
                    db.execute("BEGIN IMMEDIATE")
                    self._case_access(db, principal, case_id, write=True)
                    dup = db.execute(
                        "SELECT artifact_id FROM case_artifacts "
                        "WHERE tenant_id=? AND case_id=? AND sha256=?",
                        (principal.tenant_id, case_id, sha),
                    ).fetchone()
                    if dup is not None:
                        raise CaseGateError("DUPLICATE_ARTIFACT")
                    last = db.execute(
                        "SELECT COALESCE(MAX(version),0) AS v FROM case_artifacts "
                        "WHERE tenant_id=? AND case_id=? AND filename=?",
                        (principal.tenant_id, case_id, filename),
                    ).fetchone()
                    version = int(last["v"]) + 1
                    location.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    descriptor, name = tempfile.mkstemp(prefix=".stage-", dir=location.parent)
                    staged = Path(name)
                    try:
                        with os.fdopen(descriptor, "wb") as output:
                            output.write(content)
                            output.flush()
                            os.fsync(output.fileno())
                        os.chmod(staged, 0o600)
                        os.replace(staged, location)
                        staged = None
                    except BaseException:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                        raise
                    now = self.foundation._now().isoformat()
                    scope_sha = self.foundation._latest_scope(db, principal, case_id)[0]["scope_sha256"]
                    db.execute(
                        "INSERT INTO case_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (principal.tenant_id, case_id, artifact_id, filename, version,
                         media_type, len(content), sha, str(location.relative_to(self.root)),
                         "SYNTHETIC", scan, acquired, principal.actor_id, now, scope_sha),
                    )
                    self.foundation._audit(db, principal, case_id, "ARTIFACT_INGESTED",
                                           artifact_id, {"sha256": sha, "version": version})
                    db.commit()
                    return {"artifact_id": artifact_id, "sha256": sha, "version": version,
                            "scan_status": scan, "classification": "SYNTHETIC"}
            except BaseException:
                # On any failure after atomic rename remove orphan; never publish a bad record.
                location.unlink(missing_ok=True)
                if staged is not None:
                    staged.unlink(missing_ok=True)
                raise

    def list_artifacts(self, principal: CasePrincipal, case_id: str) -> list[dict[str, Any]]:
        with self.foundation._lock, self.foundation._connection() as db:
            self._case_access(db, principal, case_id)
            rows = db.execute(
                "SELECT * FROM case_artifacts WHERE tenant_id=? AND case_id=? "
                "ORDER BY filename,version",
                (principal.tenant_id, case_id),
            ).fetchall()
            return [self._metadata(row) for row in rows]

    def verify_artifact(self, principal: CasePrincipal, case_id: str, artifact_id: str) -> dict[str, Any]:
        with self.foundation._lock, self.foundation._connection() as db:
            self._case_access(db, principal, case_id)
            row = self._artifact_row(db, principal, case_id, artifact_id)
            blob = self._location(principal, case_id, artifact_id)
            if not blob.is_file() or blob.is_symlink():
                raise CaseGateError("ARTIFACT_UNAVAILABLE")
            data = blob.read_bytes()
            self._assert_digest(row, data)
            return {"artifact_id": artifact_id, "integrity": "VERIFIED",
                    "sha256": row["sha256"], "scan_status": row["scan_status"]}

    def add_text_span(self, principal: CasePrincipal, case_id: str, artifact_id: str,
                      *, byte_offset: int, byte_length: int, quote_sha256: str,
                      observed_at: str) -> dict[str, str]:
        if (type(byte_offset) is not int or type(byte_length) is not int
            or byte_offset < 0 or not 1 <= byte_length <= 4096):
            raise CaseGateError("INVALID_SPAN_RANGE")
        if not isinstance(quote_sha256, str) or not SHA256_HEX.fullmatch(quote_sha256):
            raise CaseGateError("INVALID_QUOTE_DIGEST")
        when = _parse_utc(observed_at).isoformat()

        def op(db: sqlite3.Connection) -> dict[str, str]:
            self._case_access(db, principal, case_id, write=True)
            row = self._artifact_row(db, principal, case_id, artifact_id)
            if row["mime_type"] not in {"text/plain", "text/csv"}:
                raise CaseGateError("PDF_PARSER_NOT_CONNECTED")
            path = self._location(principal, case_id, artifact_id)
            if not path.is_file() or path.is_symlink():
                raise CaseGateError("ARTIFACT_UNAVAILABLE")
            data = path.read_bytes()
            self._assert_digest(row, data)
            if byte_offset + byte_length > len(data):
                raise CaseGateError("SPAN_OUT_OF_BOUNDS")
            quote = data[byte_offset:byte_offset + byte_length]
            if hashlib.sha256(quote).hexdigest() != quote_sha256:
                raise CaseGateError("QUOTE_DIGEST_MISMATCH")
            evidence_id = "evidence-" + uuid4().hex
            db.execute(
                "INSERT INTO case_evidence_spans VALUES(?,?,?,?,?,?,?,?,?,?)",
                (principal.tenant_id, case_id, evidence_id, artifact_id,
                 "BYTE_RANGE", byte_offset, byte_length, quote_sha256, when,
                 principal.actor_id),
            )
            self.foundation._audit(db, principal, case_id, "EVIDENCE_SPAN_ATTACHED",
                                   evidence_id, {"artifact_id": artifact_id,
                                                 "quote_sha256": quote_sha256})
            return {"evidence_id": evidence_id, "artifact_id": artifact_id,
                    "quote_sha256": quote_sha256}
        return self.foundation._write(op)

    def list_evidence(self, principal: CasePrincipal, case_id: str, artifact_id: str) -> list[dict[str, Any]]:
        with self.foundation._lock, self.foundation._connection() as db:
            self._case_access(db, principal, case_id)
            self._artifact_row(db, principal, case_id, artifact_id)
            rows = db.execute(
                "SELECT evidence_id, artifact_id, locator_kind, locator_value, locator_length, "
                "quote_sha256, observed_at FROM case_evidence_spans "
                "WHERE tenant_id=? AND case_id=? AND artifact_id=? ORDER BY evidence_id",
                (principal.tenant_id, case_id, artifact_id),
            ).fetchall()
            return [dict(row) for row in rows]
