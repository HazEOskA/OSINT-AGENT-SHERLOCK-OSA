"""Phase 1 case security foundation. Not wired to any public HTTP endpoint.

SQLite is ONLY a local, single-process prototype. Production needs a trusted
identity provider, PostgreSQL row-level security, and an external audit anchor.
No OSINT tools, ingestion, language models, or remote network calls run here.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from contextlib import contextmanager
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4

ROLES = frozenset({"OWNER", "INVESTIGATOR", "REVIEWER", "VIEWER"})
WRITERS = frozenset({"OWNER", "INVESTIGATOR"})
APPROVERS = frozenset({"OWNER", "REVIEWER"})
SCHEMA_VERSION = "case-foundation.v1"


class CaseGateError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CasePrincipal:
    """Authenticated principal supplied by a trusted server, never by a request body."""

    tenant_id: str
    actor_id: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required(value: str, name: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CaseGateError(f"INVALID_{name.upper()}")
    return value.strip()


def _values(items: Sequence[str], name: str, *, allow_empty: bool = False) -> list[str]:
    if isinstance(items, (str, bytes)) or not isinstance(items, (list, tuple)):
        raise CaseGateError(f"INVALID_{name.upper()}")
    normalized = [_required(item, name, 200) for item in items]
    if (not normalized and not allow_empty) or len(normalized) > 100 or len(normalized) != len(set(normalized)):
        raise CaseGateError(f"INVALID_{name.upper()}")
    return sorted(normalized)


def _parse_utc(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CaseGateError("INVALID_EXPIRY") from exc
    if dt.tzinfo is None:
        raise CaseGateError("INVALID_EXPIRY")
    return dt.astimezone(UTC)


_SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS case_tenants (
    tenant_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS case_memberships (
    tenant_id TEXT NOT NULL REFERENCES case_tenants(tenant_id),
    actor_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('OWNER','INVESTIGATOR','REVIEWER','VIEWER')),
    PRIMARY KEY(tenant_id, actor_id)
);
CREATE TABLE IF NOT EXISTS case_files (
    tenant_id TEXT NOT NULL REFERENCES case_tenants(tenant_id),
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acl_revision INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS case_assignments (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    case_role TEXT NOT NULL CHECK(case_role IN ('OWNER','INVESTIGATOR','REVIEWER','VIEWER')),
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, case_id, actor_id),
    FOREIGN KEY(tenant_id, case_id) REFERENCES case_files(tenant_id, case_id),
    FOREIGN KEY(tenant_id, actor_id) REFERENCES case_memberships(tenant_id, actor_id)
);
CREATE TABLE IF NOT EXISTS case_scopes (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    body_json TEXT NOT NULL,
    scope_sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, case_id, revision),
    FOREIGN KEY(tenant_id, case_id) REFERENCES case_files(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS case_plans (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    scope_sha256 TEXT NOT NULL,
    body_json TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, case_id, plan_id),
    FOREIGN KEY(tenant_id, case_id) REFERENCES case_files(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS case_approvals (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    scope_sha256 TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('APPROVE','DENY')),
    expires_at TEXT NOT NULL,
    receipt_signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(tenant_id, case_id, approval_id),
    FOREIGN KEY(tenant_id, case_id) REFERENCES case_files(tenant_id, case_id)
);
CREATE TABLE IF NOT EXISTS case_audit (
    tenant_id TEXT NOT NULL REFERENCES case_tenants(tenant_id),
    seq INTEGER NOT NULL,
    case_id TEXT,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    PRIMARY KEY(tenant_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_assignments_actor ON case_assignments(tenant_id, actor_id, case_id);
CREATE INDEX IF NOT EXISTS idx_scopes_case ON case_scopes(tenant_id, case_id, revision);
CREATE INDEX IF NOT EXISTS idx_approvals_plan ON case_approvals(tenant_id, case_id, plan_id);
"""


class CaseFoundation:
    """Bounded local contract implementation; no execution adapter and no public API."""

    def __init__(
        self,
        path: str | Path,
        *,
        signing_secret: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(signing_secret, bytes) or len(signing_secret) < 32:
            raise CaseGateError("WEAK_SIGNING_SECRET")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        with self._connection() as db:
            db.executescript(_SCHEMA)

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise CaseGateError("CLOCK_MUST_BE_UTC_AWARE")
        return now.astimezone(UTC)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA secure_delete=ON")
        return db

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def _authorized(self, db: sqlite3.Connection, principal: CasePrincipal, roles: frozenset[str] | None = None) -> None:
        if not isinstance(principal, CasePrincipal):
            raise CaseGateError("AUTH_REQUIRED")
        row = db.execute(
            "SELECT role FROM case_memberships WHERE tenant_id=? AND actor_id=?",
            (principal.tenant_id, principal.actor_id),
        ).fetchone()
        if row is None:
            raise CaseGateError("ACCESS_DENIED")
        if roles is not None and row["role"] not in roles:
            raise CaseGateError("ACCESS_DENIED")

    def _assert_case(self, db: sqlite3.Connection, principal: CasePrincipal, case_id: str,
                     roles: frozenset[str] | None = None) -> sqlite3.Row:
        """A tenant member must ALSO hold an explicit grant for this exact case."""
        row = db.execute(
            "SELECT f.*, a.case_role FROM case_files AS f "
            "JOIN case_assignments AS a ON a.tenant_id=f.tenant_id AND a.case_id=f.case_id "
            "WHERE f.tenant_id=? AND f.case_id=? AND a.actor_id=?",
            (principal.tenant_id, case_id, principal.actor_id),
        ).fetchone()
        if row is None:
            raise CaseGateError("CASE_NOT_FOUND")
        if roles is not None and row["case_role"] not in roles:
            raise CaseGateError("ACCESS_DENIED")
        return row

    def _latest_scope(self, db: sqlite3.Connection, principal: CasePrincipal, case_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = db.execute(
            "SELECT * FROM case_scopes WHERE tenant_id=? AND case_id=? ORDER BY revision DESC LIMIT 1",
            (principal.tenant_id, case_id),
        ).fetchone()
        if row is None:
            raise CaseGateError("SCOPE_NOT_FOUND")
        body = json.loads(row["body_json"])
        if _digest(body) != row["scope_sha256"] or body.get("revision") != row["revision"]:
            raise CaseGateError("SCOPE_INTEGRITY_FAILED")
        return row, body

    def _audit(self, db: sqlite3.Connection, principal: CasePrincipal, case_id: str | None, action: str, target_id: str, payload: object) -> None:
        prev = db.execute(
            "SELECT seq, event_hash FROM case_audit WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
            (principal.tenant_id,),
        ).fetchone()
        seq = int(prev["seq"]) + 1 if prev else 1
        prev_hash = str(prev["event_hash"]) if prev else "0" * 64
        event = {
            "tenant_id": principal.tenant_id,
            "seq": seq,
            "case_id": case_id,
            "actor_id": principal.actor_id,
            "action": action,
            "target_id": target_id,
            "occurred_at": self._now().isoformat(),
            "payload_sha256": _digest(payload),
            "prev_hash": prev_hash,
        }
        db.execute(
            "INSERT INTO case_audit(tenant_id,seq,case_id,actor_id,action,target_id,occurred_at,payload_sha256,prev_hash,event_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (*event.values(), _digest(event)),
        )

    def _write(self, callback: Callable[[sqlite3.Connection], Any]) -> Any:
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            result = callback(db)
            db.commit()
            return result

    def bootstrap_tenant_for_tests(self, tenant_id: str, members: Mapping[str, str]) -> None:
        """TEST FIXTURE ONLY. Never expose through HTTP or production account setup."""
        tenant_id = _required(tenant_id, "tenant_id")
        if not members:
            raise CaseGateError("EMPTY_MEMBERSHIP")

        def op(db: sqlite3.Connection) -> None:
            db.execute("INSERT INTO case_tenants(tenant_id) VALUES(?)", (tenant_id,))
            for actor_id, role in members.items():
                if role not in ROLES:
                    raise CaseGateError("INVALID_ROLE")
                db.execute(
                    "INSERT INTO case_memberships(tenant_id,actor_id,role) VALUES(?,?,?)",
                    (tenant_id, _required(actor_id, "actor_id"), role),
                )
        self._write(op)

    def assign_case_member(self, principal: CasePrincipal, case_id: str, *,
                           actor_id: str, role: str) -> None:
        """Only a tenant OWNER assigned as case OWNER can grant the existing tenant role."""
        actor_id = _required(actor_id, "actor_id")
        if role not in ROLES:
            raise CaseGateError("INVALID_ROLE")

        def op(db: sqlite3.Connection) -> None:
            self._authorized(db, principal, frozenset({"OWNER"}))
            self._assert_case(db, principal, case_id, frozenset({"OWNER"}))
            member = db.execute(
                "SELECT role FROM case_memberships WHERE tenant_id=? AND actor_id=?",
                (principal.tenant_id, actor_id),
            ).fetchone()
            if member is None or member["role"] != role:
                raise CaseGateError("MEMBER_ROLE_MISMATCH")
            db.execute(
                "INSERT INTO case_assignments(tenant_id,case_id,actor_id,case_role,granted_by,created_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,case_id,actor_id) "
                "DO UPDATE SET case_role=excluded.case_role, granted_by=excluded.granted_by, "
                "created_at=excluded.created_at",
                (principal.tenant_id, case_id, actor_id, role, principal.actor_id, self._now().isoformat()),
            )
            db.execute("UPDATE case_files SET acl_revision=acl_revision+1 WHERE tenant_id=? AND case_id=?",
                       (principal.tenant_id, case_id))
            self._audit(db, principal, case_id, "CASE_ACCESS_GRANTED", actor_id, {"role": role})
        self._write(op)

    def revoke_case_member(self, principal: CasePrincipal, case_id: str, *, actor_id: str) -> None:
        actor_id = _required(actor_id, "actor_id")

        def op(db: sqlite3.Connection) -> None:
            self._authorized(db, principal, frozenset({"OWNER"}))
            self._assert_case(db, principal, case_id, frozenset({"OWNER"}))
            if actor_id == principal.actor_id:
                raise CaseGateError("SELF_REVOKE_DENIED")
            row = db.execute(
                "DELETE FROM case_assignments WHERE tenant_id=? AND case_id=? AND actor_id=? RETURNING actor_id",
                (principal.tenant_id, case_id, actor_id),
            ).fetchone()
            if row is None:
                raise CaseGateError("ASSIGNMENT_NOT_FOUND")
            db.execute("UPDATE case_files SET acl_revision=acl_revision+1 WHERE tenant_id=? AND case_id=?",
                       (principal.tenant_id, case_id))
            self._audit(db, principal, case_id, "CASE_ACCESS_REVOKED", actor_id, {"revoked": True})
        self._write(op)

    def _make_scope(
        self,
        *,
        revision: int,
        allowed_capabilities: Sequence[str],
        allowed_sources: Sequence[str],
        allowed_subjects: Sequence[str],
        prohibited_actions: Sequence[str],
        lawful_basis_reference: str,
        expires_at: str,
    ) -> dict[str, Any]:
        if _parse_utc(expires_at) <= self._now():
            raise CaseGateError("SCOPE_EXPIRED")
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": revision,
            "allowed_capabilities": _values(allowed_capabilities, "capabilities"),
            "allowed_sources": _values(allowed_sources, "sources"),
            "allowed_subjects": _values(allowed_subjects, "subjects"),
            "prohibited_actions": _values(prohibited_actions, "prohibited", allow_empty=True),
            "lawful_basis_reference": _required(lawful_basis_reference, "lawful_basis_reference", 500),
            "expires_at": _parse_utc(expires_at).isoformat(),
        }

    def create_case(self, principal: CasePrincipal, *, title: str, purpose: str,
                    allowed_capabilities: Sequence[str], allowed_sources: Sequence[str],
                    allowed_subjects: Sequence[str], prohibited_actions: Sequence[str],
                    lawful_basis_reference: str, expires_at: str) -> dict[str, str]:
        title, purpose = _required(title, "title"), _required(purpose, "purpose", 1000)
        scope = self._make_scope(revision=1, allowed_capabilities=allowed_capabilities,
                                 allowed_sources=allowed_sources, allowed_subjects=allowed_subjects,
                                 prohibited_actions=prohibited_actions, lawful_basis_reference=lawful_basis_reference,
                                 expires_at=expires_at)
        case_id = f"case-{uuid4().hex}"
        scope_sha = _digest(scope)

        def op(db: sqlite3.Connection) -> None:
            self._authorized(db, principal, WRITERS)
            db.execute("INSERT INTO case_files(tenant_id,case_id,title,purpose,created_by,created_at) "
                       "VALUES(?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, title, purpose, principal.actor_id, self._now().isoformat()))
            creator = db.execute(
                "SELECT role FROM case_memberships WHERE tenant_id=? AND actor_id=?",
                (principal.tenant_id, principal.actor_id),
            ).fetchone()
            db.execute("INSERT INTO case_assignments VALUES(?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, principal.actor_id, creator["role"],
                        principal.actor_id, self._now().isoformat()))
            db.execute("INSERT INTO case_scopes VALUES(?,?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, 1, _canonical(scope).decode(), scope_sha,
                        principal.actor_id, self._now().isoformat()))
            self._audit(db, principal, case_id, "CASE_CREATED", case_id, {"scope_sha256": scope_sha})
        self._write(op)
        return {"tenant_id": principal.tenant_id, "case_id": case_id, "scope_sha256": scope_sha}

    def get_case(self, principal: CasePrincipal, case_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as db:
            self._authorized(db, principal)
            row = self._assert_case(db, principal, case_id)
            scope_row, scope = self._latest_scope(db, principal, case_id)
            return {"tenant_id": principal.tenant_id, "case_id": case_id, "title": row["title"],
                    "purpose": row["purpose"], "scope": scope, "scope_sha256": scope_row["scope_sha256"]}

    def revise_scope(self, principal: CasePrincipal, case_id: str, *,
                     allowed_capabilities: Sequence[str], allowed_sources: Sequence[str],
                     allowed_subjects: Sequence[str], prohibited_actions: Sequence[str],
                     lawful_basis_reference: str, expires_at: str) -> dict[str, Any]:
        def op(db: sqlite3.Connection) -> dict[str, Any]:
            self._authorized(db, principal, frozenset({"OWNER"}))
            self._assert_case(db, principal, case_id, frozenset({"OWNER"}))
            old, _ = self._latest_scope(db, principal, case_id)
            revision = int(old["revision"]) + 1
            scope = self._make_scope(revision=revision, allowed_capabilities=allowed_capabilities,
                                     allowed_sources=allowed_sources, allowed_subjects=allowed_subjects,
                                     prohibited_actions=prohibited_actions, lawful_basis_reference=lawful_basis_reference,
                                     expires_at=expires_at)
            sha = _digest(scope)
            db.execute("INSERT INTO case_scopes VALUES(?,?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, revision, _canonical(scope).decode(), sha,
                        principal.actor_id, self._now().isoformat()))
            self._audit(db, principal, case_id, "SCOPE_REVISED", str(revision),
                        {"old_sha256": old["scope_sha256"], "new_sha256": sha})
            return {"revision": revision, "scope_sha256": sha}
        return self._write(op)

    def propose_plan(self, principal: CasePrincipal, case_id: str, *,
                     capabilities: Sequence[str], sources: Sequence[str],
                     subjects: Sequence[str], description: str) -> dict[str, str]:
        """Only plans fixture analysis. No tool execution is connected in Phase 1."""
        description = _required(description, "description", 1000)
        capabilities = _values(capabilities, "capabilities")
        sources = _values(sources, "sources")
        subjects = _values(subjects, "subjects")

        def op(db: sqlite3.Connection) -> dict[str, str]:
            self._authorized(db, principal, WRITERS)
            case = self._assert_case(db, principal, case_id, WRITERS)
            current, scope = self._latest_scope(db, principal, case_id)
            if _parse_utc(scope["expires_at"]) <= self._now():
                raise CaseGateError("SCOPE_EXPIRED")
            if (not set(capabilities) <= set(scope["allowed_capabilities"])
                or not set(sources) <= set(scope["allowed_sources"])
                or not set(subjects) <= set(scope["allowed_subjects"])):
                raise CaseGateError("PLAN_OUT_OF_SCOPE")
            action = "case.analysis.fixture"
            if action in scope["prohibited_actions"]:
                raise CaseGateError("ACTION_PROHIBITED")
            plan_id = f"plan-{uuid4().hex}"
            body = {"schema_version": SCHEMA_VERSION, "action": action,
                    "capabilities": capabilities, "sources": sources, "subjects": subjects,
                    "description": description, "scope_sha256": current["scope_sha256"],
                    "revision": current["revision"], "acl_revision": case["acl_revision"]}
            plan_sha = _digest(body)
            db.execute("INSERT INTO case_plans VALUES(?,?,?,?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, plan_id, current["revision"],
                        current["scope_sha256"], _canonical(body).decode(), plan_sha,
                        principal.actor_id, self._now().isoformat()))
            self._audit(db, principal, case_id, "PLAN_PROPOSED", plan_id, {"plan_sha256": plan_sha})
            return {"plan_id": plan_id, "plan_sha256": plan_sha,
                    "scope_sha256": current["scope_sha256"]}
        return self._write(op)

    def _get_plan(self, db: sqlite3.Connection, principal: CasePrincipal, case_id: str, plan_id: str) -> sqlite3.Row:
        plan = db.execute(
            "SELECT * FROM case_plans WHERE tenant_id=? AND case_id=? AND plan_id=?",
            (principal.tenant_id, case_id, plan_id),
        ).fetchone()
        if plan is None:
            raise CaseGateError("PLAN_NOT_FOUND")
        body = json.loads(plan["body_json"])
        if _digest(body) != plan["plan_sha256"] or body.get("scope_sha256") != plan["scope_sha256"]:
            raise CaseGateError("PLAN_INTEGRITY_FAILED")
        return plan

    def _receipt(self, approval: Mapping[str, str]) -> str:
        return hmac.new(self._secret, _canonical(approval), hashlib.sha256).hexdigest()

    def decide_plan(self, principal: CasePrincipal, case_id: str, plan_id: str, *,
                    decision: str, ttl_seconds: int = 900) -> dict[str, str]:
        if decision not in {"APPROVE", "DENY"}:
            raise CaseGateError("INVALID_DECISION")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise CaseGateError("INVALID_APPROVAL_TTL")

        def op(db: sqlite3.Connection) -> dict[str, str]:
            self._authorized(db, principal, APPROVERS)
            case = self._assert_case(db, principal, case_id, APPROVERS)
            scope_row, scope = self._latest_scope(db, principal, case_id)
            plan = self._get_plan(db, principal, case_id, plan_id)
            if plan["proposed_by"] == principal.actor_id:
                raise CaseGateError("FOUR_EYES_REQUIRED")
            if plan["scope_sha256"] != scope_row["scope_sha256"]:
                raise CaseGateError("STALE_SCOPE")
            if json.loads(plan["body_json"]).get("acl_revision") != case["acl_revision"]:
                raise CaseGateError("STALE_ASSIGNMENTS")
            expiry = min(self._now() + timedelta(seconds=ttl_seconds), _parse_utc(scope["expires_at"]))
            if expiry <= self._now():
                raise CaseGateError("SCOPE_EXPIRED")
            approval_id = f"approval-{uuid4().hex}"
            receipt = {"tenant_id": principal.tenant_id, "case_id": case_id,
                       "approval_id": approval_id, "plan_id": plan_id,
                       "scope_sha256": scope_row["scope_sha256"], "plan_sha256": plan["plan_sha256"],
                       "revision": int(plan["revision"]), "actor_id": principal.actor_id,
                       "decision": decision, "expires_at": expiry.isoformat()}
            signature = self._receipt(receipt)
            db.execute("INSERT INTO case_approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (principal.tenant_id, case_id, approval_id, plan_id,
                        scope_row["scope_sha256"], plan["plan_sha256"], plan["revision"],
                        principal.actor_id, decision, expiry.isoformat(), signature, self._now().isoformat()))
            self._audit(db, principal, case_id, "APPROVAL_DECIDED", approval_id,
                        {"decision": decision, "plan_sha256": plan["plan_sha256"]})
            return {"approval_id": approval_id, "decision": decision,
                    "receipt_signature": signature, "expires_at": expiry.isoformat()}
        return self._write(op)

    def check_authorization(self, principal: CasePrincipal, case_id: str, plan_id: str,
                            approval_id: str) -> dict[str, str]:
        """Validate a stored signed approval; NEVER execute an investigation."""
        with self._lock, self._connection() as db:
            self._authorized(db, principal, WRITERS | APPROVERS)
            case = self._assert_case(db, principal, case_id, WRITERS | APPROVERS)
            scope_row, scope = self._latest_scope(db, principal, case_id)
            plan = self._get_plan(db, principal, case_id, plan_id)
            row = db.execute(
                "SELECT * FROM case_approvals WHERE tenant_id=? AND case_id=? AND approval_id=? AND plan_id=?",
                (principal.tenant_id, case_id, approval_id, plan_id),
            ).fetchone()
            if row is None:
                raise CaseGateError("APPROVAL_REQUIRED")
            most_recent = db.execute(
                "SELECT approval_id FROM case_approvals WHERE tenant_id=? AND case_id=? AND plan_id=? ORDER BY rowid DESC LIMIT 1",
                (principal.tenant_id, case_id, plan_id),
            ).fetchone()
            if most_recent is None or most_recent["approval_id"] != approval_id:
                raise CaseGateError("APPROVAL_SUPERSEDED")
            receipt = {key: row[key] for key in (
                "tenant_id", "case_id", "approval_id", "plan_id", "scope_sha256",
                "plan_sha256", "revision", "actor_id", "decision", "expires_at")}
            if not hmac.compare_digest(self._receipt(receipt), row["receipt_signature"]):
                raise CaseGateError("APPROVAL_SIGNATURE_INVALID")
            if row["decision"] != "APPROVE":
                raise CaseGateError("APPROVAL_DENIED")
            if (_parse_utc(row["expires_at"]) <= self._now()
                or _parse_utc(scope["expires_at"]) <= self._now()):
                raise CaseGateError("APPROVAL_EXPIRED")
            if json.loads(plan["body_json"]).get("acl_revision") != case["acl_revision"]:
                raise CaseGateError("STALE_ASSIGNMENTS")
            if (row["scope_sha256"] != scope_row["scope_sha256"]
                or plan["scope_sha256"] != scope_row["scope_sha256"]
                or row["plan_sha256"] != plan["plan_sha256"]
                or row["revision"] != scope_row["revision"]):
                raise CaseGateError("STALE_APPROVAL")
            return {"gate": "APPROVED", "execution": "NOT_CONNECTED", "plan_sha256": plan["plan_sha256"],
                    "scope_sha256": scope_row["scope_sha256"]}

    def _sign_anchor(self, record: Mapping[str, object]) -> str:
        return hmac.new(self._secret, b"case-audit-anchor.v1:" + _canonical(record),
                        hashlib.sha256).hexdigest()

    def export_audit_anchor(self, principal: CasePrincipal) -> dict[str, object]:
        """Signed checkpoint MUST be stored OUTSIDE this database by a trusted operator."""
        with self._lock, self._connection() as db:
            self._authorized(db, principal, frozenset({"OWNER"}))
            row = db.execute(
                "SELECT seq,event_hash FROM case_audit WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                (principal.tenant_id,),
            ).fetchone()
            record: dict[str, object] = {
                "tenant_id": principal.tenant_id, "seq": int(row["seq"]) if row else 0,
                "head_hash": str(row["event_hash"]) if row else "0" * 64,
            }
            return {**record, "signature": self._sign_anchor(record)}

    def verify_audit(self, principal: CasePrincipal,
                     *, external_anchor: Mapping[str, object] | None = None) -> bool:
        """Local chain alone CANNOT detect truncation; signed external anchor can."""
        with self._lock, self._connection() as db:
            self._authorized(db, principal)
            expected_seq = None
            expected_head = None
            if external_anchor is not None:
                try:
                    if external_anchor["tenant_id"] != principal.tenant_id:
                        return False
                    record = {k: external_anchor[k] for k in ("tenant_id", "seq", "head_hash")}
                    if type(record["seq"]) is not int or record["seq"] < 0:
                        return False
                    if not isinstance(record["head_hash"], str) or len(record["head_hash"]) != 64:
                        return False
                    if not hmac.compare_digest(
                        self._sign_anchor(record), str(external_anchor["signature"])
                    ):
                        return False
                    expected_seq, expected_head = record["seq"], record["head_hash"]
                except (KeyError, ValueError, TypeError):
                    return False
            rows = db.execute(
                "SELECT * FROM case_audit WHERE tenant_id=? ORDER BY seq",
                (principal.tenant_id,),
            ).fetchall()
            prev = "0" * 64
            anchored = expected_seq == 0 and expected_head == prev
            for seq, row in enumerate(rows, start=1):
                payload = {name: row[name] for name in (
                    "tenant_id", "seq", "case_id", "actor_id", "action", "target_id",
                    "occurred_at", "payload_sha256", "prev_hash")}
                if row["seq"] != seq or row["prev_hash"] != prev or row["event_hash"] != _digest(payload):
                    return False
                prev = row["event_hash"]
                if expected_seq == seq and expected_head == prev:
                    anchored = True
            return anchored if external_anchor is not None else True
