from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta

from sherlock_osa.contracts import CapabilityRequest, DecisionEffect, Target, TargetKind, parse_utc, utc_iso
from sherlock_osa.errors import SherlockError
from sherlock_osa.policy import validate_scope_definition
from tests.support import build_test_service, lab_payload


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        from tempfile import TemporaryDirectory

        self.temp = TemporaryDirectory()
        from pathlib import Path

        self.service, _ = build_test_service(Path(self.temp.name))
        created = self.service.create_mission(lab_payload())
        self.scope = self.service.store.get_mission(created["mission"]["mission_id"])[0]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def request(self, **changes: object) -> CapabilityRequest:
        data: dict[str, object] = {
            "mission_id": self.scope.mission_id,
            "capability": "lab.http.probe",
            "target": {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]},
            "route": "range-only",
            "port": 3000,
            "request_id": "policy-test",
        }
        data.update(changes)
        return CapabilityRequest.from_dict(data)

    def test_exact_scope_allows(self) -> None:
        decision = self.service.broker.evaluate(self.scope, self.request())
        self.assertEqual(decision.effect, DecisionEffect.ALLOW)
        self.assertEqual(decision.reason_code, "SCOPE_MATCH")

    def test_target_port_capability_and_route_escape_denied(self) -> None:
        cases = [
            ({"target": {"kind": "LAB_ASSET", "value": "lab://other", "ports": [3000]}}, "TARGET_OUT_OF_SCOPE"),
            ({"port": 22}, "PORT_OUT_OF_SCOPE"),
            ({"capability": "lab.network.scan"}, "CAPABILITY_OUT_OF_SCOPE"),
            ({"route": "external-allowlist"}, "ROUTE_DENIED"),
        ]
        for changes, code in cases:
            with self.subTest(code=code):
                decision = self.service.broker.evaluate(self.scope, self.request(**changes))
                self.assertEqual(decision.effect, DecisionEffect.DENY)
                self.assertEqual(decision.reason_code, code)

    def test_signature_tamper_denied(self) -> None:
        tampered = replace(self.scope, goal="Tampered goal")
        decision = self.service.broker.evaluate(tampered, self.request())
        self.assertEqual(decision.reason_code, "SIGNATURE_INVALID")

    def test_expired_scope_denied(self) -> None:
        after_expiry = parse_utc(self.scope.expires_at) + timedelta(seconds=1)
        decision = self.service.broker.evaluate(self.scope, self.request(), evaluated_at=after_expiry)
        self.assertEqual(decision.reason_code, "MISSION_EXPIRED")

    def test_lab_rejects_addressable_ip(self) -> None:
        with self.assertRaisesRegex(SherlockError, "LAB_RANGE"):
            validate_scope_definition(
                mode=self.scope.mode,
                targets=(Target(TargetKind.IP, "192.168.1.10", (22,)),),
                capabilities=("lab.network.scan",),
                ownership_proof=None,
            )

    def test_external_mode_is_fail_closed(self) -> None:
        payload = lab_payload() | {
            "mode": "AUTHORIZED_EXTERNAL",
            "targets": [{"kind": "DOMAIN", "value": "osatechgpt.dev", "ports": [443]}],
            "allowed_capabilities": ["external.http.probe"],
        }
        with self.assertRaisesRegex(SherlockError, "ownership verifier") as raised:
            self.service.create_mission(payload)
        self.assertEqual(raised.exception.code, "OWNERSHIP_VERIFIER_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
