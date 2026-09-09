from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Sequence


class FindingStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNVERIFIED = "UNVERIFIED"
    CONFLICTED = "CONFLICTED"


class AssertionLevel(StrEnum):
    FACT = "FACT"
    CORRELATED = "CORRELATED"
    HYPOTHESIS = "HYPOTHESIS"


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    evidence_id: str
    source: str
    source_family: str
    url: str
    collected_at: str
    evidence_sha256: str
    confidence: float

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "source_family": self.source_family,
            "url": self.url,
            "collected_at": self.collected_at,
            "evidence_sha256": self.evidence_sha256,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class Relation:
    relation_type: str
    from_finding_id: str
    to_finding_id: str
    evidence_ids: tuple[str, ...] = ()
    confidence: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "relation_type": self.relation_type,
            "from_finding_id": self.from_finding_id,
            "to_finding_id": self.to_finding_id,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class Conflict:
    finding_id: str
    reason: str
    evidence_ids: tuple[str, ...]
    values: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "values": list(self.values),
        }


@dataclass(frozen=True, slots=True)
class SourceRun:
    source: str
    source_family: str
    status: str
    evidence_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "source_family": self.source_family,
            "status": self.status,
            "evidence_count": self.evidence_count,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    kind: str
    value: str
    title: str
    status: FindingStatus
    assertion: AssertionLevel
    confidence: float
    source_count: int
    sources: tuple[EvidenceLink, ...]
    relations: tuple[Relation, ...] = ()
    parent_finding_ids: tuple[str, ...] = ()
    evidence_sha256: str = ""
    first_seen_at: str = ""
    last_seen_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "value": self.value,
            "title": self.title,
            "status": self.status.value,
            "assertion": self.assertion.value,
            "confidence": self.confidence,
            "source_count": self.source_count,
            "sources": [source.to_dict() for source in self.sources],
            "relations": [relation.to_dict() for relation in self.relations],
            "parent_finding_ids": list(self.parent_finding_ids),
            "evidence_sha256": self.evidence_sha256,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        }


@dataclass(frozen=True, slots=True)
class InvestigationSummary:
    sources_checked: int
    findings: int
    confirmed_findings: int
    evidence_links: int
    conflicts: int
    identifiers_seen: int
    module_invocations: int
    duration_ms: int
    stop_reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "sources_checked": self.sources_checked,
            "findings": self.findings,
            "confirmed_findings": self.confirmed_findings,
            "evidence_links": self.evidence_links,
            "conflicts": self.conflicts,
            "identifiers_seen": self.identifiers_seen,
            "module_invocations": self.module_invocations,
            "duration_ms": self.duration_ms,
            "stop_reason": self.stop_reason,
        }


def stable_finding_id(kind: str, value: str) -> str:
    canonical = f"{kind.strip().upper()}:{value.strip().casefold()}".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:24]


def digest_payload(payload: Mapping[str, object] | Sequence[object]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
