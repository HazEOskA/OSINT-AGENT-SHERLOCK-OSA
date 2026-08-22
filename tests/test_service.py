from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from sherlock_osa.errors import EngineError, SherlockError
from tests.support import build_test_service, lab_payload


class ServiceTests(unittest.TestCase):
    def test_full_vertical_slice_and_replay(self) -> None:
        with TemporaryDirectory() as directory:
            service, engine = build_test_service(Path(directory))
            created = service.create_mission(lab_payload())
            mission = created["mission"]
            self.assertTrue(created["active"])
            self.assertEqual(len(engine.calls), 1)
            stored = service.get_mission(mission["mission_id"])
            self.assertTrue(stored["signature_valid"])
            # Sensitive nested Engine fields are redacted before persistence.
            self.assertEqual(stored["engine_receipt"]["evidence"][0]["token"], "[REDACTED]")

            decision = service.decide(
                {
                    "mission_id": mission["mission_id"],
                    "capability": "lab.http.probe",
                    "target": {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]},
                    "route": "range-only",
                    "port": 3000,
                    "request_id": "e2e-test",
                }
            )["decision"]
            self.assertEqual(decision["effect"], "ALLOW")
            execution = service.simulate({"decision_id": decision["decision_id"]})["receipt"]
            self.assertFalse(execution["network_effect_performed"])
            self.assertFalse(execution["shell_effect_performed"])
            self.assertEqual(execution["output"]["status"], "SIMULATED")
            replay = service.replay(mission["mission_id"])
            self.assertTrue(replay["valid"])
            self.assertEqual(replay["decisions_replayed"], 1)
            self.assertTrue(service.verify_evidence()["valid"])

    def test_non_completed_engine_receipt_blocks_broker(self) -> None:
        with TemporaryDirectory() as directory:
            service, _ = build_test_service(Path(directory), engine_state="WAITING_FOR_APPROVAL")
            created = service.create_mission(lab_payload())
            self.assertFalse(created["active"])
            decision = service.decide(
                {
                    "mission_id": created["mission"]["mission_id"],
                    "capability": "lab.http.probe",
                    "target": {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]},
                    "route": "range-only",
                    "port": 3000,
                    "request_id": "blocked-test",
                }
            )["decision"]
            self.assertEqual(decision["reason_code"], "ENGINE_MISSION_NOT_COMPLETED")
            with self.assertRaisesRegex(SherlockError, "DENY"):
                service.simulate({"decision_id": decision["decision_id"]})

    def test_reference_benchmark_has_twenty_unique_repos(self) -> None:
        with TemporaryDirectory() as directory:
            service, _ = build_test_service(Path(directory))
            repositories = service.reference_repositories()["repositories"]
            self.assertEqual(len(repositories), 20)
            self.assertEqual(len({repo["name"] for repo in repositories}), 20)

    def test_osint_adapters_are_blocked_until_engine_completes(self) -> None:
        with TemporaryDirectory() as directory:
            service, engine = build_test_service(
                Path(directory), engine_state="WAITING_FOR_APPROVAL"
            )
            with self.assertRaises(EngineError) as raised:
                service.osint_investigate(
                    {
                        "query": "target@example.com",
                        "kind": "EMAIL",
                        "purpose": "SELF_AUDIT",
                        "include_darkweb": True,
                        "consent": True,
                    }
                )
            self.assertEqual(raised.exception.code, "OSINT_ENGINE_NOT_COMPLETED")
            serialized_draft = str(engine.calls[0])
            self.assertNotIn("target@example.com", serialized_draft)
            self.assertIn("sha256:", serialized_draft)
            records = service.ledger.records()
            self.assertEqual(records[-1]["event_type"], "OSINT_ENGINE_RECEIPT_RECORDED")


if __name__ == "__main__":
    unittest.main()
