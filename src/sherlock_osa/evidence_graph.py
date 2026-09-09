from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping, Sequence

from sherlock_osa.findings import Finding, Relation
from sherlock_osa.research import ResearchEvidence


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str
    kind: str
    status: str
    confidence: float
    source: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "confidence": self.confidence,
            "source": self.source,
            "url": self.url,
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    edge_id: str
    edge_type: str
    from_node_id: str
    to_node_id: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type,
            "from_node_id": self.from_node_id,
            "to_node_id": self.to_node_id,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    event_id: str
    timestamp: str
    event_type: str
    title: str
    source: str
    identifier_kind: str
    identifier_value: str
    url: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "title": self.title,
            "source": self.source,
            "identifier_kind": self.identifier_kind,
            "identifier_value": self.identifier_value,
            "url": self.url,
        }


def _edge_id(edge_type: str, left: str, right: str, evidence_ids: Sequence[str]) -> str:
    raw = "|".join((edge_type, left, right, *sorted(evidence_ids))).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def build_evidence_graph(
    findings: Sequence[Finding],
    relations: Sequence[Relation],
) -> EvidenceGraph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}

    for finding in findings:
        nodes[finding.finding_id] = GraphNode(
            node_id=finding.finding_id,
            node_type="FINDING",
            label=finding.title or finding.value,
            kind=finding.kind,
            status=finding.status.value,
            confidence=finding.confidence,
        )

        for source in finding.sources:
            evidence_node_id = f"evidence:{source.evidence_id}"
            if evidence_node_id not in nodes:
                nodes[evidence_node_id] = GraphNode(
                    node_id=evidence_node_id,
                    node_type="EVIDENCE",
                    label=source.source,
                    kind="EVIDENCE",
                    status="OBSERVED",
                    confidence=source.confidence,
                    source=source.source,
                    url=source.url,
                )
            edge = GraphEdge(
                edge_id=_edge_id(
                    "SUPPORTED_BY",
                    finding.finding_id,
                    evidence_node_id,
                    (source.evidence_id,),
                ),
                edge_type="SUPPORTED_BY",
                from_node_id=finding.finding_id,
                to_node_id=evidence_node_id,
                confidence=source.confidence,
                evidence_ids=(source.evidence_id,),
            )
            edges[edge.edge_id] = edge

    for relation in relations:
        if relation.from_finding_id not in nodes or relation.to_finding_id not in nodes:
            continue
        edge = GraphEdge(
            edge_id=_edge_id(
                relation.relation_type,
                relation.from_finding_id,
                relation.to_finding_id,
                relation.evidence_ids,
            ),
            edge_type=relation.relation_type,
            from_node_id=relation.from_finding_id,
            to_node_id=relation.to_finding_id,
            confidence=relation.confidence,
            evidence_ids=relation.evidence_ids,
        )
        edges[edge.edge_id] = edge

    return EvidenceGraph(
        nodes=tuple(nodes[key] for key in sorted(nodes)),
        edges=tuple(edges[key] for key in sorted(edges)),
    )


_DATE_KEYS = frozenset(
    {
        "timestamp",
        "date",
        "created_at",
        "updated_at",
        "first_seen",
        "last_seen",
        "breachdate",
        "breach_date",
        "addeddate",
        "added_date",
        "modifieddate",
        "modified_date",
        "eventdate",
        "event_date",
    }
)


def _normalize_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    if re.fullmatch(r"\d{14}", raw):
        try:
            parsed = datetime.strptime(raw, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            return None
        return parsed.isoformat().replace("+00:00", "Z")

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        try:
            parsed = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return None
        return parsed.isoformat().replace("+00:00", "Z")

    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _historical_dates(value: object, *, depth: int = 0) -> list[tuple[str, str]]:
    if depth > 5:
        return []
    found: list[tuple[str, str]] = []

    if isinstance(value, Mapping):
        action = value.get("eventAction") or value.get("event_action")
        for key, item in list(value.items())[:96]:
            key_text = str(key).casefold()
            if key_text in _DATE_KEYS:
                timestamp = _normalize_timestamp(item)
                if timestamp:
                    label = str(action)[:120] if action else str(key)[:120]
                    found.append((timestamp, label))
            if isinstance(item, (Mapping, list, tuple)):
                found.extend(_historical_dates(item, depth=depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in list(value)[:96]:
            found.extend(_historical_dates(item, depth=depth + 1))

    return found[:256]


def build_timeline(evidence: Sequence[ResearchEvidence]) -> tuple[TimelineEvent, ...]:
    events: dict[str, TimelineEvent] = {}

    for item in evidence:
        dates = _historical_dates(item.fields)
        if not dates and item.collected_at:
            dates = [(item.collected_at, "observed_at")]

        url = next((candidate for candidate in item.source_urls if candidate), "")
        for timestamp, label in dates[:64]:
            raw = "|".join(
                (
                    item.evidence_id,
                    timestamp,
                    label,
                    item.module,
                    item.identifier.kind.value,
                    item.identifier.value,
                )
            ).encode("utf-8")
            event_id = hashlib.sha256(raw).hexdigest()[:24]
            events[event_id] = TimelineEvent(
                event_id=event_id,
                timestamp=timestamp,
                event_type=label.upper().replace(" ", "_"),
                title=f"{item.module}: {label}",
                source=item.module,
                identifier_kind=item.identifier.kind.value,
                identifier_value=item.identifier.value,
                url=url,
            )

    return tuple(
        sorted(
            events.values(),
            key=lambda event: (event.timestamp, event.source, event.event_id),
        )[:500]
    )
