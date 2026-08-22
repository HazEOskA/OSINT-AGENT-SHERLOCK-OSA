from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from importlib.resources import files
from tempfile import TemporaryDirectory
from uuid import uuid4

from sherlock_osa import ENGINE_PIN, __version__
from sherlock_osa.contracts import (
    CapabilityRequest,
    DecisionEffect,
    MissionMode,
    MissionScope,
    Target,
    parse_utc,
    require_int,
    require_mapping,
    require_string,
    utc_iso,
    utc_now,
)
from sherlock_osa.errors import SherlockError
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.osint import OsintAgent
from sherlock_osa.policy import CapabilityBroker, PORT_CAPABILITIES, validate_scope_definition
from sherlock_osa.signing import sha256_json, sign_scope, verify_scope
from sherlock_osa.worker import SimulationWorker


PUBLIC_DEMO_SIGNING_SECRET = (
    "sherlock-osa-public-replay-vector-only-not-a-production-secret-v0.1.1"
)
PUBLIC_DEMO_CAPABILITIES = frozenset(
    {
        "lab.http.probe",
        "lab.network.scan",
        "lab.attack.simulate",
        "blue.telemetry.replay",
    }
)


@dataclass(frozen=True, slots=True)
class PublicDemoSettings:
    """Only the small settings surface consumed by the shared HTTP handler."""

    api_key: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    max_body_bytes: int = 65_536


class PublicDemoService:
    """Stateless public passive-OSINT mode for Vercel.

    The public endpoint runs only fixed-egress, passive adapters and stores no
    investigation between requests. Direct .onion crawling, CLI enumerators and
    provider keys remain in the private Engine-connected research plane. The old
    replay endpoint stays available as a regression fixture, not as the product UI.
    """

    deployment_mode = "PUBLIC_PASSIVE_OSINT"
    public_osint_access = True

    def __init__(self) -> None:
        self.settings = PublicDemoSettings()
        self.osint_agent = OsintAgent()

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        return {
            "service": "sherlock-osa",
            "version": __version__,
            "status": "OK",
            "deployment_mode": self.deployment_mode,
            "execution_backing": "LIVE_PASSIVE_FIXED_EGRESS",
            "engine": {
                "reachable": "NOT_CALLED_IN_PUBLIC_OSINT",
                "commit_sha": ENGINE_PIN,
                "live_engine_required_for_new_missions": True,
            },
            "evidence": {
                "persistence": "PER_REQUEST",
                "verification": "SHA256_HASH_CHAIN",
            },
            "truth": {
                "live_engine_called": False,
                "network_effect_possible": True,
                "shell_effect_possible": False,
                "tor_crawl_possible": False,
                "raw_query_persisted": False,
                "probe_engine_ignored": bool(probe_engine),
            },
        }

    def osint_capabilities(self) -> dict[str, object]:
        return self.osint_agent.capabilities()

    def osint_investigate(self, raw: object) -> dict[str, object]:
        return self.osint_agent.investigate(raw)

    def reference_repositories(self) -> dict[str, object]:
        resource = files("sherlock_osa").joinpath("reference_repos.json")
        return json.loads(resource.read_text(encoding="utf-8"))

    def public_demo_replay(self, raw: object) -> dict[str, object]:
        data = require_mapping(raw, field_name="public_demo_mission")
        goal = require_string(data.get("goal"), field_name="goal", minimum=10, maximum=500)
        operator_id = require_string(
            data.get("operator_id", "public-demo"), field_name="operator_id", maximum=80
        )
        mode_value = require_string(data.get("mode"), field_name="mode", maximum=40)
        if mode_value != MissionMode.LAB_RANGE.value:
            raise SherlockError(
                "PUBLIC_DEMO_LAB_ONLY",
                "Publiczny replay obsługuje wyłącznie nieadresowalny LAB_RANGE.",
                status=409,
            )

        raw_targets = data.get("targets")
        raw_capabilities = data.get("allowed_capabilities")
        if not isinstance(raw_targets, list) or len(raw_targets) != 1:
            raise SherlockError(
                "PUBLIC_DEMO_ONE_TARGET",
                "Publiczny replay wymaga dokładnie jednego targetu lab://.",
            )
        if not isinstance(raw_capabilities, list) or len(raw_capabilities) != 1:
            raise SherlockError(
                "PUBLIC_DEMO_ONE_CAPABILITY",
                "Publiczny replay wymaga dokładnie jednej capability.",
            )

        target = Target.from_dict(raw_targets[0])
        capability = require_string(
            raw_capabilities[0], field_name="allowed_capabilities[]", maximum=120
        )
        if capability not in PUBLIC_DEMO_CAPABILITIES:
            raise SherlockError(
                "PUBLIC_DEMO_CAPABILITY_DENIED",
                "Capability nie jest dostępna w publicznym replayu.",
                status=409,
            )
        ttl = require_int(
            data.get("ttl_minutes", 15), field_name="ttl_minutes", minimum=1, maximum=60
        )
        validate_scope_definition(
            mode=MissionMode.LAB_RANGE,
            targets=(target,),
            capabilities=(capability,),
            ownership_proof=None,
        )

        created = utc_now()
        mission_id = str(uuid4())
        vector = {
            "receipt_kind": "BUNDLED_OSA_TEST_VECTOR",
            "contract": "mission-run-receipt-v2",
            "state": "COMPLETED",
            "engine_commit_sha": ENGINE_PIN,
            "live_engine_call": False,
        }
        unsigned_scope = MissionScope(
            mission_id=mission_id,
            goal=goal,
            mode=MissionMode.LAB_RANGE,
            targets=(target,),
            allowed_capabilities=(capability,),
            operator_id=operator_id,
            created_at=utc_iso(created),
            expires_at=utc_iso(created + timedelta(minutes=ttl)),
            engine_commit_sha=ENGINE_PIN,
            engine_mission_id=f"demo-vector-{mission_id}",
            engine_execution_id=f"demo-execution-{uuid4()}",
            engine_state="COMPLETED",
            engine_receipt_sha256=sha256_json(vector),
        )
        scope = sign_scope(unsigned_scope, PUBLIC_DEMO_SIGNING_SECRET)
        request = CapabilityRequest(
            mission_id=mission_id,
            capability=capability,
            target=target,
            route="range-only",
            port=target.ports[0] if capability in PORT_CAPABILITIES else None,
            request_id=str(uuid4()),
        )
        broker = CapabilityBroker(PUBLIC_DEMO_SIGNING_SECRET)
        decision = broker.evaluate(scope, request, evaluated_at=created)
        if decision.effect is not DecisionEffect.ALLOW:
            raise SherlockError(
                "PUBLIC_DEMO_VECTOR_REJECTED",
                f"Bundled replay vector został odrzucony: {decision.reason_code}.",
                status=500,
            )
        receipt = SimulationWorker().execute(scope=scope, request=request, decision=decision)

        with TemporaryDirectory(prefix="sherlock-osa-demo-") as temp_dir:
            ledger = EvidenceLedger(f"{temp_dir}/evidence.jsonl")
            ledger.append(
                "DEMO_ENGINE_RECEIPT_VECTOR_LOADED",
                {"mission_id": mission_id, "vector": vector, "vector_sha256": sha256_json(vector)},
            )
            ledger.append(
                "MISSION_SCOPE_SIGNED",
                {
                    "mission_id": mission_id,
                    "scope": scope.to_dict(),
                    "scope_sha256": sha256_json(scope.to_dict()),
                },
            )
            ledger.append(
                "CAPABILITY_DECISION",
                {
                    "mission_id": mission_id,
                    "request": request.to_dict(),
                    "decision": decision.to_dict(),
                },
            )
            ledger.append(
                "EXECUTION_SIMULATED",
                {"mission_id": mission_id, "receipt": receipt.to_dict()},
            )

            reproduced = broker.evaluate(scope, request, evaluated_at=parse_utc(decision.evaluated_at))
            comparable_fields = ("effect", "reason_code", "reason", "evaluated_at", "request_sha256")
            original_comparable = {
                key: decision.to_dict().get(key) for key in comparable_fields
            }
            reproduced_comparable = {
                key: reproduced.to_dict().get(key) for key in comparable_fields
            }
            replay_valid = original_comparable == reproduced_comparable
            replay = {
                "mission_id": mission_id,
                "valid": replay_valid,
                "scope_signature_valid": verify_scope(scope, PUBLIC_DEMO_SIGNING_SECRET),
                "decisions_replayed": 1,
                "mismatches": [] if replay_valid else [
                    {"original": original_comparable, "reproduced": reproduced_comparable}
                ],
                "replayed_at": utc_iso(),
            }
            ledger.append("MISSION_REPLAYED", {"mission_id": mission_id, "result": replay})
            verification = ledger.verify()
            records = ledger.records(mission_id=mission_id)

        replay["ledger_valid"] = verification.valid
        replay["valid"] = bool(
            replay["valid"] and replay["scope_signature_valid"] and verification.valid
        )
        return {
            "deployment_mode": self.deployment_mode,
            "mission": {
                "mission": scope.to_dict(),
                "active": True,
                "truth": "Bundled Engine receipt vector authorizes simulation only.",
            },
            "decision": {"decision": decision.to_dict()},
            "execution": {"receipt": receipt.to_dict()},
            "replay": replay,
            "evidence": {
                "verification": verification.to_dict(),
                "records": records,
                "persistence": "PER_REQUEST",
            },
            "truth": {
                "receipt_source": "BUNDLED_OSA_TEST_VECTOR",
                "live_engine_called": False,
                "network_effect_performed": False,
                "shell_effect_performed": False,
                "security_tool_invoked": False,
                "signature_assurance": "PUBLIC_DEMO_VECTOR_ONLY",
            },
        }
