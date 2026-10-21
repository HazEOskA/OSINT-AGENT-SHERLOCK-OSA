"""Offline Phase 1 tests: synthetic tenants/cases only; zero network/tool calls."""
from __future__ import annotations

import sqlite3
from contextlib import closing
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sherlock_osa.case_foundation import CaseFoundation, CaseGateError, CasePrincipal


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


class CaseFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / "cases.db"
        self.clock = Clock()
        self.svc = CaseFoundation(self.path, signing_secret=b"test-local-only-secret-that-is-over-32-bytes", clock=self.clock)
        self.svc.bootstrap_tenant_for_tests("tenant-a", {
            "alice": "OWNER", "bob": "INVESTIGATOR", "carol": "REVIEWER", "erin": "VIEWER"})
        self.svc.bootstrap_tenant_for_tests("tenant-b", {
            "alice": "OWNER", "bob": "INVESTIGATOR", "carol": "REVIEWER"})
        self.alice = CasePrincipal("tenant-a", "alice")
        self.bob = CasePrincipal("tenant-a", "bob")
        self.carol = CasePrincipal("tenant-a", "carol")
        self.erin = CasePrincipal("tenant-a", "erin")
        self.evil = CasePrincipal("tenant-b", "alice")
        self.deadline = (self.clock.now + timedelta(hours=2)).isoformat()
        self.scope = dict(allowed_capabilities=["case.evidence.analyze"],
                          allowed_sources=["synthetic-report"],
                          allowed_subjects=["synthetic-person-001"],
                          prohibited_actions=["external.http.probe", "osint.torrent.lookup"],
                          lawful_basis_reference="DEMO-SYNTHETIC-001", expires_at=self.deadline)
        self.case = self.svc.create_case(self.alice, title="Fixture Case", purpose="Synthetic investigation", **self.scope)
        self.case_id = self.case["case_id"]
        for actor, role in (("bob", "INVESTIGATOR"), ("carol", "REVIEWER"), ("erin", "VIEWER")):
            self.svc.assign_case_member(self.alice, self.case_id, actor_id=actor, role=role)

    def expect_denied(self, code: str, fn, *args, **kwargs):
        with self.assertRaises(CaseGateError) as error:
            fn(*args, **kwargs)
        self.assertEqual(error.exception.code, code)

    def test_created_case_scope_persisted_across_service_restart(self):
        reopened = CaseFoundation(self.path, signing_secret=b"test-local-only-secret-that-is-over-32-bytes", clock=self.clock)
        result = reopened.get_case(self.alice, self.case_id)
        self.assertEqual(result["scope"]["revision"], 1)
        self.assertEqual(result["scope_sha256"], self.case["scope_sha256"])
        self.assertTrue(reopened.verify_audit(self.alice))

    def test_cross_tenant_read_isolation(self):
        self.expect_denied("CASE_NOT_FOUND", self.svc.get_case, self.evil, self.case_id)
        self.expect_denied("CASE_NOT_FOUND", self.svc.propose_plan, self.evil, self.case_id,
                  capabilities=["case.evidence.analyze"], sources=["synthetic-report"],
                  subjects=["synthetic-person-001"], description="cross tenant")

    def test_cross_tenant_mutation_isolation(self):
        self.expect_denied("CASE_NOT_FOUND", self.svc.revise_scope, self.evil, self.case_id, **self.scope)
        self.expect_denied("CASE_NOT_FOUND", self.svc.decide_plan, self.evil, self.case_id, "any", decision="APPROVE")
        self.assertEqual(self.svc.get_case(self.alice, self.case_id)["scope"]["revision"], 1)

    def test_principal_membership_required(self):
        self.expect_denied("ACCESS_DENIED", self.svc.get_case, CasePrincipal("tenant-a", "not-member"), self.case_id)
        self.expect_denied("ACCESS_DENIED", self.svc.get_case, CasePrincipal("other", "alice"), self.case_id)
        self.expect_denied("AUTH_REQUIRED", self.svc.get_case, None, self.case_id)

    def test_viewer_cannot_write_and_investigator_cannot_revise_scope(self):
        self.expect_denied("ACCESS_DENIED", self.svc.create_case, self.erin,
                  title="not allowed", purpose="fixture", **self.scope)
        self.expect_denied("ACCESS_DENIED", self.svc.revise_scope, self.bob, self.case_id, **self.scope)

    def test_plan_outside_capability_source_or_subject_deny(self):
        for kind, name in [("capabilities", "external.http.probe"),
                           ("sources", "unknown-provider"), ("subjects", "other-person")]:
            values = dict(capabilities=["case.evidence.analyze"],
                          sources=["synthetic-report"], subjects=["synthetic-person-001"],
                          description="test")
            values[kind] = [name]
            self.expect_denied("PLAN_OUT_OF_SCOPE", self.svc.propose_plan, self.bob, self.case_id, **values)

    def test_execution_requires_approval_and_four_eyes(self):
        plan = self.plan()
        self.expect_denied("APPROVAL_REQUIRED", self.svc.check_authorization,
                  self.bob, self.case_id, plan["plan_id"], "missing")
        self.expect_denied("ACCESS_DENIED", self.svc.decide_plan,
                  self.bob, self.case_id, plan["plan_id"], decision="APPROVE")
        receipt = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE")
        verdict = self.svc.check_authorization(self.bob, self.case_id, plan["plan_id"], receipt["approval_id"])
        self.assertEqual(verdict["gate"], "APPROVED")
        self.assertEqual(verdict["execution"], "NOT_CONNECTED")
        self.assertEqual(verdict["plan_sha256"], plan["plan_sha256"])
        self.assertTrue(self.svc.verify_audit(self.alice))

    def test_four_eyes_owner_cannot_approve_own_plan(self):
        plan = self.svc.propose_plan(self.alice, self.case_id,
                                     capabilities=["case.evidence.analyze"],
                                     sources=["synthetic-report"],
                                     subjects=["synthetic-person-001"],
                                     description="owner plan")
        self.expect_denied("FOUR_EYES_REQUIRED", self.svc.decide_plan,
                           self.alice, self.case_id, plan["plan_id"], decision="APPROVE")

    def test_denied_approval_blocks_use(self):
        plan = self.plan()
        denied = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="DENY")
        self.expect_denied("APPROVAL_DENIED", self.svc.check_authorization,
                  self.bob, self.case_id, plan["plan_id"], denied["approval_id"])

    def test_latest_denial_supersedes_approval(self):
        plan = self.plan()
        approved = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE")
        self.svc.decide_plan(self.alice, self.case_id, plan["plan_id"], decision="DENY")
        self.expect_denied("APPROVAL_SUPERSEDED", self.svc.check_authorization,
                           self.bob, self.case_id, plan["plan_id"], approved["approval_id"])

    def test_expired_approval_rejected(self):
        plan = self.plan()
        approval = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE", ttl_seconds=2)
        self.clock.advance(3)
        self.expect_denied("APPROVAL_EXPIRED", self.svc.check_authorization,
                  self.bob, self.case_id, plan["plan_id"], approval["approval_id"])

    def test_scope_revision_revokes_old_plan_and_approval(self):
        plan = self.plan()
        approval = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE")
        revised = self.svc.revise_scope(self.alice, self.case_id, **self.scope)
        self.assertEqual(revised["revision"], 2)
        self.expect_denied("STALE_APPROVAL", self.svc.check_authorization,
                  self.bob, self.case_id, plan["plan_id"], approval["approval_id"])
        self.expect_denied("STALE_SCOPE", self.svc.decide_plan,
                  self.carol, self.case_id, plan["plan_id"], decision="APPROVE")

    def test_plan_integrity_cannot_be_modified(self):
        plan = self.plan()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE case_plans SET body_json='{}' WHERE plan_id=?", (plan["plan_id"],))
            db.commit()
        self.expect_denied("PLAN_INTEGRITY_FAILED", self.svc.decide_plan,
                  self.carol, self.case_id, plan["plan_id"], decision="APPROVE")

    def test_signed_approval_tamper_deny(self):
        plan = self.plan()
        approval = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE case_approvals SET plan_sha256=? WHERE approval_id=?", ("a" * 64, approval["approval_id"]))
            db.commit()
        self.expect_denied("APPROVAL_SIGNATURE_INVALID", self.svc.check_authorization,
                  self.bob, self.case_id, plan["plan_id"], approval["approval_id"])

    def test_audit_chain_tamper_detection(self):
        self.assertTrue(self.svc.verify_audit(self.alice))
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE case_audit SET target_id='tampered' WHERE tenant_id=? AND seq=1", ("tenant-a",))
            db.commit()
        self.assertFalse(self.svc.verify_audit(self.alice))

    def test_invalid_secret_and_invalid_scope_fail_closed(self):
        with self.assertRaises(CaseGateError):
            CaseFoundation(Path(self.root.name) / "bad.db", signing_secret=b"short")
        self.expect_denied("INVALID_EXPIRY", self.svc.create_case, self.alice,
                  title="bad", purpose="bad", **{**self.scope, "expires_at": "no date"})
        self.expect_denied("SCOPE_EXPIRED", self.svc.create_case, self.alice,
                  title="expired", purpose="bad", **{**self.scope,
                  "expires_at": (self.clock.now - timedelta(seconds=1)).isoformat()})

    def test_role_cannot_be_claimed_by_principal(self):
        self.expect_denied("ACCESS_DENIED", self.svc.decide_plan, self.erin, self.case_id, "made-up", decision="APPROVE")

    def test_same_tenant_different_case_requires_assignment(self):
        second = self.svc.create_case(self.alice, title="Private Case",
                                      purpose="Not assigned to others", **self.scope)
        self.expect_denied("CASE_NOT_FOUND", self.svc.get_case, self.bob, second["case_id"])
        self.expect_denied("CASE_NOT_FOUND", self.svc.get_case, self.carol, second["case_id"])
        self.expect_denied("CASE_NOT_FOUND", self.svc.get_case, self.erin, second["case_id"])
        self.assertEqual(self.svc.get_case(self.alice, second["case_id"])["title"], "Private Case")

    def test_revocation_immediately_blocks_access(self):
        self.svc.revoke_case_member(self.alice, self.case_id, actor_id="erin")
        self.expect_denied("CASE_NOT_FOUND", self.svc.get_case, self.erin, self.case_id)
        self.assertTrue(self.svc.verify_audit(self.alice))

    def test_access_change_revokes_previous_approvals(self):
        plan = self.plan()
        approved = self.svc.decide_plan(self.carol, self.case_id, plan["plan_id"], decision="APPROVE")
        self.svc.revoke_case_member(self.alice, self.case_id, actor_id="erin")
        self.expect_denied("STALE_ASSIGNMENTS", self.svc.check_authorization, self.bob,
                           self.case_id, plan["plan_id"], approved["approval_id"])

    def test_cross_tenant_assignment_and_privilege_escalation_denied(self):
        self.expect_denied("CASE_NOT_FOUND", self.svc.assign_case_member, self.evil,
                           self.case_id, actor_id="bob", role="INVESTIGATOR")
        self.expect_denied("MEMBER_ROLE_MISMATCH", self.svc.assign_case_member, self.alice,
                           self.case_id, actor_id="erin", role="OWNER")
        self.expect_denied("MEMBER_ROLE_MISMATCH", self.svc.assign_case_member, self.alice,
                           self.case_id, actor_id="ghost", role="INVESTIGATOR")
        self.expect_denied("ACCESS_DENIED", self.svc.assign_case_member, self.bob,
                           self.case_id, actor_id="erin", role="VIEWER")

    def test_anchored_audit_detects_tail_truncation(self):
        anchor = self.svc.export_audit_anchor(self.alice)
        self.assertTrue(self.svc.verify_audit(self.alice, external_anchor=anchor))
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM case_audit WHERE tenant_id='tenant-a' AND seq=(SELECT MAX(seq) FROM case_audit WHERE tenant_id='tenant-a')")
            db.commit()
        self.assertTrue(self.svc.verify_audit(self.alice))  # local chain alone cannot detect this
        self.assertFalse(self.svc.verify_audit(self.alice, external_anchor=anchor))

    def test_anchored_audit_detects_total_truncation(self):
        anchor = self.svc.export_audit_anchor(self.alice)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DELETE FROM case_audit WHERE tenant_id='tenant-a'")
            db.commit()
        self.assertFalse(self.svc.verify_audit(self.alice, external_anchor=anchor))

    def test_invalid_and_cross_tenant_anchor_are_rejected(self):
        anchor = self.svc.export_audit_anchor(self.alice)
        self.assertFalse(self.svc.verify_audit(self.alice,
                         external_anchor={**anchor, "head_hash": "a" * 64}))
        self.assertFalse(self.svc.verify_audit(self.evil, external_anchor=anchor))

    def test_anchor_remains_valid_after_new_audit_events(self):
        anchor = self.svc.export_audit_anchor(self.alice)
        self.svc.create_case(self.alice, title="Another case", purpose="Test", **self.scope)
        self.assertTrue(self.svc.verify_audit(self.alice, external_anchor=anchor))

    def plan(self):
        return self.svc.propose_plan(self.bob, self.case_id,
                                     capabilities=["case.evidence.analyze"],
                                     sources=["synthetic-report"],
                                     subjects=["synthetic-person-001"],
                                     description="Fixture-based analysis only")


if __name__ == "__main__":
    unittest.main()
