from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Any, Mapping
from uuid import uuid4

from sherlock_osa import __version__
from sherlock_osa.config import Settings
from sherlock_osa.contracts import (
    CapabilityRequest,
    Decision,
    DecisionEffect,
    MissionMode,
    MissionScope,
    OwnershipProof,
    Target,
    parse_utc,
    require_int,
    require_mapping,
    require_string,
    utc_iso,
    utc_now,
)
from sherlock_osa.engine import EngineGateway
from sherlock_osa.errors import EngineError, SherlockError
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.policy import CapabilityBroker, validate_scope_definition
from sherlock_osa.signing import redact, sha256_json, sign_scope, verify_scope
from sherlock_osa.storage import MissionStore
from sherlock_osa.worker import ADAPTERS, SimulationWorker


class MissionService:
    deployment_mode = "PRIVATE_CONTROL_PLANE"

    def __init__(
        self,
        *,
        settings: Settings,
        store: MissionStore,
        ledger: EvidenceLedger,
        engine: EngineGateway,
        broker: CapabilityBroker,
        worker: SimulationWorker,
    ) -> None:
        self.settings = settings
        self.store = store
        self.ledger = ledger
        self.engine = engine
        self.broker = broker
        self.worker = worker

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        ledger = self.ledger.verify()
        engine: Mapping[str, Any] = {
            "reachable": "UNKNOWN",
            "commit_sha": self.settings.engine_commit_sha,
        }
        if probe_engine:
            try:
                engine = self.engine.probe()
            except EngineError as exc:
                engine = {
                    "reachable": False,
                    "commit_sha": self.settings.engine_commit_sha,
                    "error_code": exc.code,
                }
        return {
            "service": "sherlock-osa",
            "version": __version__,
            "status": "OK" if ledger.valid else "DEGRADED",
            "deployment_mode": self.deployment_mode,
            "execution_backing": "SIMULATION_ONLY",
            "engine": dict(engine),
            "evidence": ledger.to_dict(),
        }

    def reference_repositories(self) -> dict[str, object]:
        resource = files("sherlock_osa").joinpath("reference_repos.json")
        return json.loads(resource.read_text(encoding="utf-8"))

    def capabilities(self) -> dict[str, object]:
        return {
            "default": "DENY",
            "adapters": [adapter.to_dict() for adapter in ADAPTERS],
        }

    def create_mission(self, raw: object) -> dict[str, object]:
        data = require_mapping(raw, field_name="mission")
        goal = require_string(data.get("goal"), field_name="goal", minimum=10, maximum=500)
        operator_id = require_string(
            data.get("operator_id", "operator"), field_name="operator_id", maximum=80
        )
        try:
            mode = MissionMode(require_string(data.get("mode"), field_name="mode", maximum=40))
        except ValueError as exc:
            raise SherlockError("INVALID_MODE", "Nieznany tryb misji.") from exc
        raw_targets = data.get("targets")
        raw_capabilities = data.get("allowed_capabilities")
        if not isinstance(raw_targets, list) or not isinstance(raw_capabilities, list):
            raise SherlockError(
                "INVALID_PAYLOAD", "targets i allowed_capabilities muszą być listami."
            )
        targets = tuple(Target.from_dict(item) for item in raw_targets)
        capabilities = tuple(
            sorted(
                {
                    require_string(item, field_name="allowed_capabilities[]", maximum=120)
                    for item in raw_capabilities
                }
            )
        )
        ttl = require_int(
            data.get("ttl_minutes", 30),
            field_name="ttl_minutes",
            minimum=1,
            maximum=self.settings.max_mission_ttl_minutes,
        )
        ownership_proof = OwnershipProof.from_dict(data.get("ownership_proof"))
        validate_scope_definition(
            mode=mode,
            targets=targets,
            capabilities=capabilities,
            ownership_proof=ownership_proof,
        )

        local_mission_id = str(uuid4())
        draft = {
            "mission_id": local_mission_id,
            "goal": goal,
            "mode": mode.value,
            "targets": [target.to_dict() for target in targets],
            "allowed_capabilities": list(capabilities),
            "operator_id": operator_id,
            "ttl_minutes": ttl,
        }
        try:
            engine_receipt = self.engine.run_mission(draft)
        except EngineError as exc:
            self.ledger.append(
                "ENGINE_CALL_FAILED",
                {
                    "mission_id": local_mission_id,
                    "engine_commit_sha": self.settings.engine_commit_sha,
                    "error_code": exc.code,
                },
            )
            raise

        safe_engine_body = redact(dict(engine_receipt.body))
        receipt_sha = sha256_json(safe_engine_body)
        created = utc_now()
        scope = MissionScope(
            mission_id=local_mission_id,
            goal=goal,
            mode=mode,
            targets=targets,
            allowed_capabilities=capabilities,
            operator_id=operator_id,
            created_at=utc_iso(created),
            expires_at=utc_iso(created + timedelta(minutes=ttl)),
            engine_commit_sha=self.settings.engine_commit_sha,
            engine_mission_id=engine_receipt.mission_id,
            engine_execution_id=engine_receipt.execution_id,
            engine_state=engine_receipt.state,
            engine_receipt_sha256=receipt_sha,
            ownership_proof=ownership_proof,
        )
        signed_scope = sign_scope(scope, self.settings.mission_signing_secret)
        self.store.create_mission(signed_scope, safe_engine_body)
        self.ledger.append(
            "MISSION_SCOPE_CREATED",
            {
                "mission_id": signed_scope.mission_id,
                "scope": signed_scope.to_dict(),
                "scope_sha256": sha256_json(signed_scope.to_dict()),
            },
        )
        self.ledger.append(
            "ENGINE_RECEIPT_RECORDED",
            {
                "mission_id": signed_scope.mission_id,
                "engine_mission_id": engine_receipt.mission_id,
                "engine_execution_id": engine_receipt.execution_id,
                "engine_state": engine_receipt.state,
                "engine_receipt_sha256": receipt_sha,
                "engine_commit_sha": self.settings.engine_commit_sha,
            },
        )
        return {
            "mission": signed_scope.to_dict(),
            "active": signed_scope.engine_state == "COMPLETED",
            "truth": (
                "Scope can authorize simulation only."
                if signed_scope.engine_state == "COMPLETED"
                else "Engine mission is not COMPLETED; broker will deny execution."
            ),
        }

    def get_mission(self, mission_id: str) -> dict[str, object]:
        scope, receipt = self.store.get_mission(mission_id)
        return {
            "mission": scope.to_dict(),
            "engine_receipt": receipt,
            "signature_valid": verify_scope(scope, self.settings.mission_signing_secret),
        }

    def list_missions(self) -> dict[str, object]:
        return {"missions": [scope.to_dict() for scope in self.store.list_missions()]}

    def decide(self, raw: object) -> dict[str, object]:
        request = CapabilityRequest.from_dict(raw)
        scope, _ = self.store.get_mission(request.mission_id)
        decision = self.broker.evaluate(scope, request)
        decision_dict = decision.to_dict()
        self.store.save_decision(
            decision_id=decision.decision_id,
            mission_id=request.mission_id,
            request=request.to_dict(),
            decision=decision_dict,
            created_at=decision.evaluated_at,
        )
        self.ledger.append(
            "CAPABILITY_DECISION",
            {
                "mission_id": request.mission_id,
                "request": request.to_dict(),
                "decision": decision_dict,
            },
        )
        return {"decision": decision_dict}

    def simulate(self, raw: object) -> dict[str, object]:
        data = require_mapping(raw, field_name="execution")
        decision_id = require_string(data.get("decision_id"), field_name="decision_id", maximum=100)
        request_raw, decision_raw = self.store.get_decision(decision_id)
        request = CapabilityRequest.from_dict(request_raw)
        scope, _ = self.store.get_mission(request.mission_id)
        try:
            effect = DecisionEffect(str(decision_raw["effect"]))
        except (KeyError, ValueError) as exc:
            raise SherlockError("INVALID_STORED_DECISION", "Zapisana decyzja jest niepoprawna.", status=500) from exc
        decision = Decision(
            decision_id=str(decision_raw["decision_id"]),
            effect=effect,
            reason_code=str(decision_raw["reason_code"]),
            reason=str(decision_raw["reason"]),
            evaluated_at=str(decision_raw["evaluated_at"]),
            request_sha256=str(decision_raw["request_sha256"]),
        )
        receipt = self.worker.execute(scope=scope, request=request, decision=decision)
        self.ledger.append(
            "EXECUTION_SIMULATED",
            {"mission_id": scope.mission_id, "receipt": receipt.to_dict()},
        )
        return {"receipt": receipt.to_dict()}

    def verify_evidence(self) -> dict[str, object]:
        return self.ledger.verify().to_dict()

    def replay(self, mission_id: str) -> dict[str, object]:
        scope, _ = self.store.get_mission(mission_id)
        ledger_result = self.ledger.verify()
        mismatches: list[dict[str, object]] = []
        replayed = 0
        for record in self.ledger.records(mission_id=mission_id):
            if record.get("event_type") != "CAPABILITY_DECISION":
                continue
            payload = record.get("payload", {})
            if not isinstance(payload, dict):
                mismatches.append({"sequence": record.get("sequence"), "error": "invalid payload"})
                continue
            request = CapabilityRequest.from_dict(payload.get("request"))
            original = require_mapping(payload.get("decision"), field_name="ledger.decision")
            evaluated_at = parse_utc(str(original.get("evaluated_at")))
            reproduced = self.broker.evaluate(scope, request, evaluated_at=evaluated_at)
            replayed += 1
            comparable_original = {
                key: original.get(key)
                for key in ("effect", "reason_code", "reason", "evaluated_at", "request_sha256")
            }
            comparable_reproduced = {
                key: reproduced.to_dict().get(key)
                for key in ("effect", "reason_code", "reason", "evaluated_at", "request_sha256")
            }
            if comparable_original != comparable_reproduced:
                mismatches.append(
                    {
                        "sequence": record.get("sequence"),
                        "original": comparable_original,
                        "reproduced": comparable_reproduced,
                    }
                )
        result = {
            "mission_id": mission_id,
            "valid": ledger_result.valid and verify_scope(scope, self.settings.mission_signing_secret) and not mismatches,
            "scope_signature_valid": verify_scope(scope, self.settings.mission_signing_secret),
            "ledger_valid": ledger_result.valid,
            "decisions_replayed": replayed,
            "mismatches": mismatches,
            "replayed_at": utc_iso(),
        }
        self.ledger.append("MISSION_REPLAYED", {"mission_id": mission_id, "result": result})
        return result
