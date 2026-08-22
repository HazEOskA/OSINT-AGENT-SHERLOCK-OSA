from __future__ import annotations

from typing import Any, Mapping

from sherlock_osa.contracts import (
    CapabilityRequest,
    DecisionEffect,
    MissionMode,
    require_mapping,
    require_string,
)
from sherlock_osa.errors import SherlockError
from sherlock_osa.research import BoundedResearchEngine, EventSink, ResearchIdentifier
from sherlock_osa.service import MissionService
from sherlock_osa.signing import sha256_json, verify_scope


class ResearchMissionService(MissionService):
    """MissionService extension: OSA Engine scope remains the gate; research core stays bounded."""

    def __init__(self, *args: Any, research_engine: BoundedResearchEngine | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.research_engine = research_engine or BoundedResearchEngine()

    def _prepare_research(self, raw: object) -> tuple[object, tuple[ResearchIdentifier, ...], bool]:
        data = require_mapping(raw, field_name="research")
        mission_id = require_string(data.get("mission_id"), field_name="mission_id", maximum=80)
        purge_after = data.get("purge_after", True)
        if not isinstance(purge_after, bool):
            raise SherlockError("INVALID_PAYLOAD", "purge_after musi być boolean.")

        scope, _ = self.store.get_mission(mission_id)
        if not verify_scope(scope, self.settings.mission_signing_secret):
            raise SherlockError("SIGNATURE_INVALID", "Podpis research scope jest niepoprawny.", status=409)
        if scope.mode is not MissionMode.RESEARCH_PASSIVE:
            raise SherlockError(
                "RESEARCH_MODE_REQUIRED",
                "Bounded research engine działa wyłącznie w RESEARCH_PASSIVE.",
                status=409,
            )
        if "osint.research.run" not in scope.allowed_capabilities:
            raise SherlockError(
                "RESEARCH_CAPABILITY_REQUIRED",
                "Scope nie zawiera osint.research.run.",
                status=409,
            )

        seeds: list[ResearchIdentifier] = []
        for target in scope.targets:
            request = CapabilityRequest(
                mission_id=scope.mission_id,
                capability="osint.research.run",
                target=target,
                route="research-passive",
                request_id="bounded-research-gate",
            )
            decision = self.broker.evaluate(scope, request)
            if decision.effect is not DecisionEffect.ALLOW:
                raise SherlockError(
                    decision.reason_code,
                    f"Research gate DENY: {decision.reason}",
                    status=409,
                )
            seeds.append(ResearchIdentifier.from_target(target))

        return scope, tuple(seeds), purge_after

    def research(self, raw: object, *, event_sink: EventSink | None = None) -> dict[str, object]:
        scope, seeds, purge_after = self._prepare_research(raw)
        result = self.research_engine.run(
            seeds,
            allowed_capabilities=scope.allowed_capabilities,
            event_sink=event_sink,
        )
        result_dict = result.to_dict()

        # Evidence ledger receives only aggregate/hash metadata here. Raw module payloads stay ephemeral.
        self.ledger.append(
            "RESEARCH_COMPLETED",
            {
                "mission_id": scope.mission_id,
                "research_id": result.research_id,
                "status": result.status,
                "stop_reason": result.stop_reason,
                "duration_ms": result.duration_ms,
                "identifiers_seen": result.identifiers_seen,
                "module_invocations": result.module_invocations,
                "evidence_count": len(result.evidence),
                "tainted_evidence": result.tainted_evidence,
                "result_sha256": result.result_sha256,
                "seed_set_sha256": sha256_json(
                    sorted(identifier.key for identifier in seeds)
                ),
            },
        )

        purge: Mapping[str, object] = {
            "requested": purge_after,
            "performed": False,
            "scope": "LOCAL_SQLITE_ONLY",
        }
        if purge_after:
            deleted = self.store.purge_mission(scope.mission_id)
            purge = {
                "requested": True,
                "performed": True,
                "scope": "LOCAL_SQLITE_ONLY",
                **deleted,
            }
            self.ledger.append(
                "RESEARCH_LOCAL_DB_PURGED",
                {
                    "mission_id": scope.mission_id,
                    "research_id": result.research_id,
                    "mission_deleted": bool(deleted["mission_deleted"]),
                    "decisions_deleted": int(deleted["decisions_deleted"]),
                },
            )
            if event_sink:
                event_sink("purge_done", dict(purge))

        result_dict["retention"] = {
            "mode": "EPHEMERAL",
            "raw_module_evidence_persisted": False,
            "local_database_purged": bool(purge.get("performed")),
            "external_deletion_performed": False,
        }
        return {
            "mission_id": scope.mission_id,
            "research": result_dict,
            "purge": dict(purge),
        }
