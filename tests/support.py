from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping
from uuid import uuid4

from sherlock_osa import ENGINE_PIN
from sherlock_osa.config import Settings
from sherlock_osa.engine import EngineMissionReceipt
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.policy import CapabilityBroker
from sherlock_osa.service import MissionService
from sherlock_osa.storage import MissionStore
from sherlock_osa.worker import SimulationWorker


class FakeEngine:
    commit_sha = ENGINE_PIN

    def __init__(self, state: str = "COMPLETED") -> None:
        self.state = state
        self.calls: list[Mapping[str, Any]] = []

    def run_mission(self, draft: Mapping[str, Any]) -> EngineMissionReceipt:
        self.calls.append(draft)
        mission_id = f"engine-{uuid4()}"
        execution_id = f"execution-{uuid4()}"
        body = {
            "state": self.state,
            "context": {
                "mission_id": mission_id,
                "execution_id": execution_id,
                "commit_sha": self.commit_sha,
                "completed_skills": ["tools.capability-broker"] if self.state == "COMPLETED" else [],
            },
            "evidence": [{"authority": "MECHANICALLY_VERIFIED", "token": "must-redact"}],
        }
        return EngineMissionReceipt(mission_id, execution_id, self.state, body)

    def probe(self) -> Mapping[str, Any]:
        return {"reachable": True, "title": "Fake OSA Engine", "version": "test", "commit_sha": self.commit_sha}


def settings_for(root: Path) -> Settings:
    return Settings(
        api_key="operator-key-that-is-long-enough",
        mission_signing_secret="mission-secret-that-is-definitely-long-enough",
        engine_url="http://127.0.0.1:8643",
        engine_api_key="engine-key-long-enough",
        engine_commit_sha=ENGINE_PIN,
        database_path=root / "missions.db",
        evidence_path=root / "evidence.jsonl",
        host="127.0.0.1",
        port=0,
        engine_timeout_seconds=2,
    )


def build_test_service(root: Path, *, engine_state: str = "COMPLETED") -> tuple[MissionService, FakeEngine]:
    settings = settings_for(root)
    engine = FakeEngine(engine_state)
    service = MissionService(
        settings=settings,
        store=MissionStore(settings.database_path),
        ledger=EvidenceLedger(settings.evidence_path),
        engine=engine,
        broker=CapabilityBroker(settings.mission_signing_secret),
        worker=SimulationWorker(),
    )
    return service, engine


def lab_payload() -> dict[str, object]:
    return {
        "goal": "Prove controlled policy and evidence flow for a local Juice Shop lab",
        "mode": "LAB_RANGE",
        "targets": [{"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]}],
        "allowed_capabilities": ["lab.http.probe"],
        "ttl_minutes": 30,
        "operator_id": "osa",
    }
