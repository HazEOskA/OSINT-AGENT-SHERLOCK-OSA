from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Sequence
from uuid import uuid4

from sherlock_osa.correlation import CorrelationEngine
from sherlock_osa.findings import (
    Conflict,
    Finding,
    FindingStatus,
    InvestigationSummary,
    Relation,
    SourceRun,
)
from sherlock_osa.research import (
    BoundedResearchEngine,
    EventSink,
    ResearchIdentifier,
    ResearchResult,
)


class InvestigationMode(StrEnum):
    QUICK = "quick"
    DEEP = "deep"
    MAX = "max"


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    investigation_id: str
    mode: InvestigationMode
    status: str
    research_id: str
    research_result_sha256: str
    findings: tuple[Finding, ...]
    relations: tuple[Relation, ...]
    conflicts: tuple[Conflict, ...]
    source_runs: tuple[SourceRun, ...]
    summary: InvestigationSummary
    result_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "investigation_id": self.investigation_id,
            "mode": self.mode.value,
            "status": self.status,
            "research_id": self.research_id,
            "research_result_sha256": self.research_result_sha256,
            "findings": [finding.to_dict() for finding in self.findings],
            "relations": [relation.to_dict() for relation in self.relations],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "source_runs": [source.to_dict() for source in self.source_runs],
            "summary": self.summary.to_dict(),
            "result_sha256": self.result_sha256,
        }


class DetectiveInvestigator:
    """High-level evidence/correlation orchestration over BoundedResearchEngine.

    V1 deliberately does not alter source budgets. QUICK/DEEP/MAX budget selection
    belongs to the API/source-registry layer; this core records the requested mode
    while preserving the exact research engine supplied by the caller.
    """

    def __init__(
        self,
        research_engine: BoundedResearchEngine,
        *,
        correlation_engine: CorrelationEngine | None = None,
    ) -> None:
        self.research_engine = research_engine
        self.correlation_engine = correlation_engine or CorrelationEngine()

    def investigate(
        self,
        seeds: Sequence[ResearchIdentifier],
        *,
        allowed_capabilities: Sequence[str],
        mode: InvestigationMode | str = InvestigationMode.DEEP,
        event_sink: EventSink | None = None,
    ) -> InvestigationResult:
        selected_mode = InvestigationMode(mode)
        investigation_id = str(uuid4())
        emit = event_sink or (lambda _event, _payload: None)
        source_errors: dict[str, str] = {}

        emit(
            "investigation_started",
            {
                "investigation_id": investigation_id,
                "mode": selected_mode.value,
                "seed_count": len(seeds),
            },
        )

        def research_events(event: str, payload: Mapping[str, object]) -> None:
            if event == "pivot_discovered":
                emit("pivot_discovered", payload)
            elif event == "identifier_result":
                emit("evidence_collected", payload)
            elif event == "poison_blocked":
                emit("evidence_blocked", payload)
            elif event == "module_error":
                module = str(payload.get("module", "unknown"))
                source_errors[module] = str(payload.get("error", "UNKNOWN"))
                emit("source_error", payload)
            elif event == "research_stopped":
                emit("investigation_research_stopped", payload)

        research = self.research_engine.run(
            seeds,
            allowed_capabilities=allowed_capabilities,
            event_sink=research_events,
        )
        correlated = self.correlation_engine.correlate(research.evidence)

        for finding in correlated.findings:
            emit("finding_discovered", finding.to_dict())
            if finding.status is FindingStatus.CONFIRMED:
                emit("finding_confirmed", finding.to_dict())
        for conflict in correlated.conflicts:
            emit("conflict_detected", conflict.to_dict())

        source_runs = self._source_runs(research, source_errors)
        summary = InvestigationSummary(
            sources_checked=len(source_runs),
            findings=len(correlated.findings),
            confirmed_findings=sum(
                1 for finding in correlated.findings if finding.status is FindingStatus.CONFIRMED
            ),
            evidence_links=sum(len(finding.sources) for finding in correlated.findings),
            conflicts=len(correlated.conflicts),
            identifiers_seen=research.identifiers_seen,
            module_invocations=research.module_invocations,
            duration_ms=research.duration_ms,
            stop_reason=research.stop_reason,
        )
        result_sha256 = self._digest(
            investigation_id=investigation_id,
            mode=selected_mode,
            research=research,
            findings=correlated.findings,
            relations=correlated.relations,
            conflicts=correlated.conflicts,
        )
        result = InvestigationResult(
            investigation_id=investigation_id,
            mode=selected_mode,
            status=research.status,
            research_id=research.research_id,
            research_result_sha256=research.result_sha256,
            findings=correlated.findings,
            relations=correlated.relations,
            conflicts=correlated.conflicts,
            source_runs=source_runs,
            summary=summary,
            result_sha256=result_sha256,
        )
        emit(
            "investigation_completed",
            {
                "investigation_id": investigation_id,
                "status": result.status,
                "summary": summary.to_dict(),
                "result_sha256": result_sha256,
            },
        )
        return result

    def _source_runs(
        self,
        research: ResearchResult,
        source_errors: Mapping[str, str],
    ) -> tuple[SourceRun, ...]:
        counts: dict[str, int] = {}
        for evidence in research.evidence:
            counts[evidence.module] = counts.get(evidence.module, 0) + 1

        source_names = sorted(set(counts) | set(source_errors))
        return tuple(
            SourceRun(
                source=source,
                source_family=source.split(".", 1)[0].casefold() if source else "unknown",
                status="ERROR" if source in source_errors else "COMPLETED",
                evidence_count=counts.get(source, 0),
                error=source_errors.get(source),
            )
            for source in source_names
        )

    def _digest(
        self,
        *,
        investigation_id: str,
        mode: InvestigationMode,
        research: ResearchResult,
        findings: Sequence[Finding],
        relations: Sequence[Relation],
        conflicts: Sequence[Conflict],
    ) -> str:
        payload = {
            "investigation_id": investigation_id,
            "mode": mode.value,
            "research_result_sha256": research.result_sha256,
            "finding_sha256": [finding.evidence_sha256 for finding in findings],
            "relations": [relation.to_dict() for relation in relations],
            "conflicts": [conflict.to_dict() for conflict in conflicts],
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
