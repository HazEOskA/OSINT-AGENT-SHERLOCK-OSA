from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence
from uuid import uuid4

from sherlock_osa.correlation import CorrelationEngine
from sherlock_osa.evidence_graph import (
    EvidenceGraph,
    TimelineEvent,
    build_evidence_graph,
    build_timeline,
)
from sherlock_osa.findings import (
    Conflict,
    Finding,
    FindingStatus,
    InvestigationSummary,
    Relation,
    SourceRun,
)
from sherlock_osa.identity import IdentityCluster, IdentityResolver
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
    identity_clusters: tuple[IdentityCluster, ...]
    graph: EvidenceGraph
    timeline: tuple[TimelineEvent, ...]
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
            "identity_clusters": [cluster.to_dict() for cluster in self.identity_clusters],
            "graph": self.graph.to_dict(),
            "timeline": [event.to_dict() for event in self.timeline],
            "source_runs": [source.to_dict() for source in self.source_runs],
            "summary": self.summary.to_dict(),
            "result_sha256": self.result_sha256,
        }


class DetectiveInvestigator:
    """High-level detective orchestration over the bounded recursive research engine."""

    def __init__(
        self,
        research_engine: BoundedResearchEngine,
        *,
        correlation_engine: CorrelationEngine | None = None,
        identity_resolver: IdentityResolver | None = None,
    ) -> None:
        self.research_engine = research_engine
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.identity_resolver = identity_resolver or IdentityResolver()

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
        source_states: dict[str, dict[str, Any]] = {}

        emit(
            "investigation_started",
            {
                "investigation_id": investigation_id,
                "mode": selected_mode.value,
                "seed_count": len(seeds),
            },
        )

        def state_for(module: str) -> dict[str, Any]:
            return source_states.setdefault(
                module,
                {
                    "status": "UNKNOWN",
                    "family": module.split(".", 1)[0].casefold() if module else "unknown",
                    "error": None,
                    "reason": None,
                    "duration_ms": 0,
                    "rate_limited": False,
                },
            )

        def research_events(event: str, payload: Mapping[str, object]) -> None:
            module = str(payload.get("module", ""))

            if event == "pivot_discovered":
                emit("pivot_discovered", payload)
                return
            if event == "identifier_result":
                emit("evidence_collected", payload)
                return
            if event == "poison_blocked":
                emit("evidence_blocked", payload)
                return
            if event == "research_stopped":
                emit("investigation_research_stopped", payload)
                return
            if event == "done":
                return

            if event == "source_started":
                state = state_for(module)
                state["status"] = "RUNNING"
                state["family"] = str(payload.get("family", state["family"]))
                emit(event, payload)
                return

            if event == "source_completed":
                state = state_for(module)
                state["status"] = "COMPLETED"
                state["family"] = str(payload.get("family", state["family"]))
                state["duration_ms"] = max(
                    int(state.get("duration_ms", 0)),
                    int(payload.get("duration_ms", 0) or 0),
                )
                emit(event, payload)
                return

            if event == "source_skipped":
                state = state_for(module)
                if state["status"] in {"UNKNOWN", "RUNNING"}:
                    state["status"] = "SKIPPED"
                state["reason"] = str(payload.get("reason", "SKIPPED"))
                emit(event, payload)
                return

            if event == "source_timeout":
                state = state_for(module)
                state["status"] = "TIMEOUT"
                state["error"] = str(payload.get("error", "TimeoutError"))
                state["duration_ms"] = max(
                    int(state.get("duration_ms", 0)),
                    int(payload.get("duration_ms", 0) or 0),
                )
                emit(event, payload)
                return

            if event == "source_error":
                state = state_for(module)
                state["status"] = "ERROR"
                state["error"] = str(payload.get("error", "UNKNOWN"))
                state["duration_ms"] = max(
                    int(state.get("duration_ms", 0)),
                    int(payload.get("duration_ms", 0) or 0),
                )
                emit(event, payload)
                return

            if event == "source_rate_limited":
                state = state_for(module)
                state["rate_limited"] = True
                emit(event, payload)
                return

            # Backward-compatible low-level error event. The engine emits a matching
            # source_error/source_timeout event immediately after it.
            if event == "module_error":
                return

            emit(event, payload)

        research = self.research_engine.run(
            seeds,
            allowed_capabilities=allowed_capabilities,
            event_sink=research_events,
        )
        correlated = self.correlation_engine.correlate(research.evidence)
        graph = build_evidence_graph(correlated.findings, correlated.relations)
        timeline = build_timeline(research.evidence)
        identity_clusters = self.identity_resolver.resolve(
            correlated.findings,
            correlated.relations,
        )

        for finding in correlated.findings:
            emit("finding_discovered", finding.to_dict())
            if finding.status is FindingStatus.CONFIRMED:
                emit("finding_confirmed", finding.to_dict())

        for relation in correlated.relations:
            emit("relation_discovered", relation.to_dict())

        for conflict in correlated.conflicts:
            emit("conflict_detected", conflict.to_dict())

        emit(
            "identity_resolution_completed",
            {
                "investigation_id": investigation_id,
                "cluster_count": len(identity_clusters),
            },
        )
        emit(
            "timeline_ready",
            {
                "investigation_id": investigation_id,
                "event_count": len(timeline),
            },
        )

        source_runs = self._source_runs(research, source_states)
        checked_statuses = {"COMPLETED", "ERROR", "TIMEOUT"}
        summary = InvestigationSummary(
            sources_checked=sum(1 for run in source_runs if run.status in checked_statuses),
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
            sources_considered=len(source_runs),
            sources_skipped=sum(1 for run in source_runs if run.status == "SKIPPED"),
            source_errors=sum(1 for run in source_runs if run.status in {"ERROR", "TIMEOUT"}),
            identity_clusters=len(identity_clusters),
            timeline_events=len(timeline),
            graph_nodes=len(graph.nodes),
            graph_edges=len(graph.edges),
        )

        result_sha256 = self._digest(
            investigation_id=investigation_id,
            mode=selected_mode,
            research=research,
            findings=correlated.findings,
            relations=correlated.relations,
            conflicts=correlated.conflicts,
            identity_clusters=identity_clusters,
            graph=graph,
            timeline=timeline,
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
            identity_clusters=identity_clusters,
            graph=graph,
            timeline=timeline,
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
        source_states: Mapping[str, Mapping[str, Any]],
    ) -> tuple[SourceRun, ...]:
        counts: dict[str, int] = {}
        for evidence in research.evidence:
            counts[evidence.module] = counts.get(evidence.module, 0) + 1

        source_names = sorted(set(counts) | set(source_states))
        runs: list[SourceRun] = []
        for source in source_names:
            state = dict(source_states.get(source, {}))
            status = str(state.get("status", "COMPLETED" if source in counts else "UNKNOWN"))
            if status == "RUNNING":
                status = "COMPLETED" if source in counts else "UNKNOWN"
            runs.append(
                SourceRun(
                    source=source,
                    source_family=str(
                        state.get(
                            "family",
                            source.split(".", 1)[0].casefold() if source else "unknown",
                        )
                    ),
                    status=status,
                    evidence_count=counts.get(source, 0),
                    error=(
                        str(state["error"])
                        if state.get("error") is not None
                        else None
                    ),
                    reason=(
                        str(state["reason"])
                        if state.get("reason") is not None
                        else None
                    ),
                    duration_ms=int(state.get("duration_ms", 0) or 0),
                    rate_limited=bool(state.get("rate_limited", False)),
                )
            )
        return tuple(runs)

    def _digest(
        self,
        *,
        investigation_id: str,
        mode: InvestigationMode,
        research: ResearchResult,
        findings: Sequence[Finding],
        relations: Sequence[Relation],
        conflicts: Sequence[Conflict],
        identity_clusters: Sequence[IdentityCluster],
        graph: EvidenceGraph,
        timeline: Sequence[TimelineEvent],
    ) -> str:
        payload = {
            "investigation_id": investigation_id,
            "mode": mode.value,
            "research_result_sha256": research.result_sha256,
            "finding_sha256": [finding.evidence_sha256 for finding in findings],
            "relations": [relation.to_dict() for relation in relations],
            "conflicts": [conflict.to_dict() for conflict in conflicts],
            "identity_clusters": [cluster.to_dict() for cluster in identity_clusters],
            "graph_node_count": len(graph.nodes),
            "graph_edge_count": len(graph.edges),
            "timeline_event_ids": [event.event_id for event in timeline],
        }
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
