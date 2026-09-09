from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.findings import (
    AssertionLevel,
    Conflict,
    EvidenceLink,
    Finding,
    FindingStatus,
    Relation,
    digest_payload,
    stable_finding_id,
)
from sherlock_osa.research import ResearchEvidence, TrustState


_KEY_KIND = {
    "email": "EMAIL",
    "emails": "EMAIL",
    "mail": "EMAIL",
    "mails": "EMAIL",
    "username": "USERNAME",
    "usernames": "USERNAME",
    "handle": "USERNAME",
    "handles": "USERNAME",
    "nickname": "USERNAME",
    "nick": "USERNAME",
    "domain": "DOMAIN",
    "domains": "DOMAIN",
    "host": "DOMAIN",
    "hostname": "DOMAIN",
    "url": "URL",
    "urls": "URL",
    "link": "URL",
    "links": "URL",
    "profile_url": "URL",
    "website": "URL",
    "websites": "URL",
}


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    findings: tuple[Finding, ...]
    relations: tuple[Relation, ...]
    conflicts: tuple[Conflict, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "relations": [relation.to_dict() for relation in self.relations],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
        }


@dataclass(frozen=True, slots=True)
class _Observation:
    kind: str
    value: str
    title: str
    evidence: ResearchEvidence
    direct: bool


class CorrelationEngine:
    """Deterministic evidence-first correlation.

    The engine never upgrades a hypothesis because of model prose. Confidence comes
    only from source evidence, independent source families and direct source URLs.
    """

    def correlate(self, evidence: Sequence[ResearchEvidence]) -> CorrelationResult:
        clean = tuple(item for item in evidence if item.trust is TrustState.CLEAN)
        observations: list[_Observation] = []
        base_by_evidence: dict[str, str] = {}

        for item in clean:
            base = self._base_observation(item)
            observations.append(base)
            base_by_evidence[item.evidence_id] = stable_finding_id(base.kind, base.value)
            observations.extend(self._field_observations(item))

        grouped: dict[tuple[str, str], list[_Observation]] = defaultdict(list)
        for observation in observations:
            normalized = self._normalize(observation.kind, observation.value)
            if normalized:
                grouped[(observation.kind, normalized)].append(observation)

        raw_relations = self._build_relations(clean, observations, base_by_evidence)
        conflicts = self._detect_conflicts(grouped)
        conflicted_ids = {conflict.finding_id for conflict in conflicts}

        findings: list[Finding] = []
        for (kind, normalized), items in sorted(grouped.items()):
            finding_id = stable_finding_id(kind, normalized)
            sources = self._evidence_links(items)
            source_families = {link.source_family for link in sources}
            source_count = len(source_families)
            confidence = self._score(items, source_count, sources)
            status = self._status(confidence, source_count)
            if finding_id in conflicted_ids:
                status = FindingStatus.CONFLICTED
            assertion = self._assertion(items, source_count, status)
            timestamps = sorted({item.evidence.collected_at for item in items if item.evidence.collected_at})
            parent_ids = sorted(
                {
                    base_by_evidence[item.evidence.identifier.parent_evidence_id]
                    for item in items
                    if item.evidence.identifier.parent_evidence_id in base_by_evidence
                }
            )
            relations = tuple(
                relation
                for relation in raw_relations
                if finding_id in {relation.from_finding_id, relation.to_finding_id}
            )
            digest = digest_payload(
                {
                    "finding_id": finding_id,
                    "kind": kind,
                    "value": normalized,
                    "status": status.value,
                    "assertion": assertion.value,
                    "confidence": confidence,
                    "evidence": sorted(link.evidence_sha256 for link in sources),
                }
            )
            title = next((item.title for item in items if item.title), f"{kind}: {normalized}")
            findings.append(
                Finding(
                    finding_id=finding_id,
                    kind=kind,
                    value=normalized,
                    title=title,
                    status=status,
                    assertion=assertion,
                    confidence=confidence,
                    source_count=source_count,
                    sources=sources,
                    relations=relations,
                    parent_finding_ids=tuple(parent_ids),
                    evidence_sha256=digest,
                    first_seen_at=timestamps[0] if timestamps else "",
                    last_seen_at=timestamps[-1] if timestamps else "",
                )
            )

        return CorrelationResult(tuple(findings), tuple(raw_relations), tuple(conflicts))

    def _base_observation(self, item: ResearchEvidence) -> _Observation:
        return _Observation(
            kind=item.identifier.kind.value,
            value=item.identifier.value,
            title=f"{item.identifier.kind.value}: {item.identifier.value}",
            evidence=item,
            direct=True,
        )

    def _field_observations(self, item: ResearchEvidence) -> list[_Observation]:
        found: list[_Observation] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, raw: object, title: str = "") -> None:
            if not isinstance(raw, str):
                return
            normalized = self._normalize(kind, raw)
            if not normalized:
                return
            key = (kind, normalized)
            if key in seen:
                return
            seen.add(key)
            found.append(
                _Observation(
                    kind=kind,
                    value=normalized,
                    title=title or f"{kind}: {normalized}",
                    evidence=item,
                    direct=False,
                )
            )

        def walk(value: object, depth: int = 0) -> None:
            if depth > 4:
                return
            if isinstance(value, Mapping):
                service = self._first_text(value, ("service", "platform", "site"))
                username = self._first_text(value, ("username", "handle", "nickname", "nick"))
                profile_url = self._first_text(value, ("profile_url", "url", "website", "link"))
                domain = self._first_text(value, ("domain", "host", "hostname"))
                if service and (username or profile_url or domain):
                    account_value = "|".join(
                        part for part in (service.casefold(), username or "", profile_url or "", domain or "") if part
                    )
                    add("ACCOUNT", account_value, service)

                for key, child in list(value.items())[:64]:
                    kind = _KEY_KIND.get(str(key).casefold())
                    if kind:
                        if isinstance(child, str):
                            add(kind, child)
                        elif isinstance(child, Sequence) and not isinstance(child, (str, bytes, bytearray)):
                            for member in list(child)[:64]:
                                add(kind, member)
                    if isinstance(child, (Mapping, list, tuple)):
                        walk(child, depth + 1)
            elif isinstance(value, (list, tuple)):
                for child in list(value)[:64]:
                    walk(child, depth + 1)

        walk(item.fields)
        return found

    def _build_relations(
        self,
        evidence: Sequence[ResearchEvidence],
        observations: Sequence[_Observation],
        base_by_evidence: Mapping[str, str],
    ) -> list[Relation]:
        relations: dict[tuple[str, str, str], Relation] = {}

        for item in evidence:
            current_id = base_by_evidence.get(item.evidence_id)
            parent_evidence_id = item.identifier.parent_evidence_id
            parent_id = base_by_evidence.get(parent_evidence_id or "")
            if current_id and parent_id and current_id != parent_id:
                key = ("PIVOT", parent_id, current_id)
                relations[key] = Relation(
                    relation_type="PIVOT",
                    from_finding_id=parent_id,
                    to_finding_id=current_id,
                    evidence_ids=tuple(sorted({parent_evidence_id, item.evidence_id} - {None})),
                    confidence=max(0.0, min(1.0, item.confidence)),
                )

        by_evidence: dict[str, list[_Observation]] = defaultdict(list)
        for observation in observations:
            by_evidence[observation.evidence.evidence_id].append(observation)

        for evidence_id, items in by_evidence.items():
            base = next((item for item in items if item.direct), None)
            if not base:
                continue
            base_id = stable_finding_id(base.kind, self._normalize(base.kind, base.value))
            for item in items:
                if item.direct:
                    continue
                target_id = stable_finding_id(item.kind, self._normalize(item.kind, item.value))
                if base_id == target_id:
                    continue
                key = ("OBSERVED_IN", base_id, target_id)
                relations[key] = Relation(
                    relation_type="OBSERVED_IN",
                    from_finding_id=base_id,
                    to_finding_id=target_id,
                    evidence_ids=(evidence_id,),
                    confidence=max(0.0, min(1.0, item.evidence.confidence)),
                )

        return [relations[key] for key in sorted(relations)]

    def _detect_conflicts(
        self,
        grouped: Mapping[tuple[str, str], Sequence[_Observation]],
    ) -> list[Conflict]:
        conflicts: list[Conflict] = []
        signal_keys = ("exists", "registered", "found", "active")

        for (kind, value), items in grouped.items():
            signals: list[tuple[bool, str]] = []
            for item in items:
                fields = item.evidence.fields
                if not isinstance(fields, Mapping):
                    continue
                for key in signal_keys:
                    signal = fields.get(key)
                    if isinstance(signal, bool):
                        signals.append((signal, item.evidence.evidence_id))
                        break
            values = {signal for signal, _ in signals}
            if values == {True, False}:
                finding_id = stable_finding_id(kind, value)
                conflicts.append(
                    Conflict(
                        finding_id=finding_id,
                        reason="CONTRADICTORY_PRESENCE_SIGNAL",
                        evidence_ids=tuple(sorted({evidence_id for _, evidence_id in signals})),
                        values=("false", "true"),
                    )
                )
        return sorted(conflicts, key=lambda item: item.finding_id)

    def _evidence_links(self, items: Iterable[_Observation]) -> tuple[EvidenceLink, ...]:
        links: dict[tuple[str, str], EvidenceLink] = {}
        for item in items:
            evidence = item.evidence
            family = self._source_family(evidence.module)
            urls = evidence.source_urls or ("",)
            for url in urls:
                key = (evidence.evidence_id, url)
                links[key] = EvidenceLink(
                    evidence_id=evidence.evidence_id,
                    source=evidence.module,
                    source_family=family,
                    url=url,
                    collected_at=evidence.collected_at,
                    evidence_sha256=evidence.evidence_sha256,
                    confidence=max(0.0, min(1.0, evidence.confidence)),
                )
        return tuple(links[key] for key in sorted(links))

    def _score(
        self,
        items: Sequence[_Observation],
        source_count: int,
        sources: Sequence[EvidenceLink],
    ) -> float:
        if not items:
            return 0.0
        max_conf = max(max(0.0, min(1.0, item.evidence.confidence)) for item in items)
        corroboration = min(0.24, max(0, source_count - 1) * 0.12)
        direct_bonus = 0.08 if any(item.direct for item in items) else 0.0
        url_bonus = 0.08 if any(link.url for link in sources) else 0.0
        score = 0.60 * max_conf + corroboration + direct_bonus + url_bonus
        return round(max(0.0, min(1.0, score)), 4)

    def _status(self, confidence: float, source_count: int) -> FindingStatus:
        if source_count >= 3 and confidence >= 0.80:
            return FindingStatus.CONFIRMED
        if source_count >= 2 and confidence >= 0.65:
            return FindingStatus.PROBABLE
        if confidence >= 0.45:
            return FindingStatus.POSSIBLE
        return FindingStatus.UNVERIFIED

    def _assertion(
        self,
        items: Sequence[_Observation],
        source_count: int,
        status: FindingStatus,
    ) -> AssertionLevel:
        if status is FindingStatus.CONFLICTED:
            return AssertionLevel.HYPOTHESIS
        direct_high = any(item.direct and item.evidence.confidence >= 0.9 for item in items)
        if direct_high and source_count >= 1:
            return AssertionLevel.FACT
        if source_count >= 2:
            return AssertionLevel.CORRELATED
        return AssertionLevel.HYPOTHESIS

    def _normalize(self, kind: str, value: str) -> str:
        candidate = str(value).strip()
        if not candidate:
            return ""
        kind = kind.upper()
        if kind == "EMAIL":
            if candidate.count("@") != 1 or len(candidate) > 320:
                return ""
            return candidate.casefold()
        if kind == "USERNAME":
            if len(candidate) > 64:
                return ""
            return candidate.casefold()
        if kind == "DOMAIN":
            candidate = candidate.rstrip(".").casefold()
            return candidate if candidate and len(candidate) <= 253 else ""
        if kind == "URL":
            try:
                parsed = urlsplit(candidate)
            except ValueError:
                return ""
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return ""
            return candidate
        return candidate[:2048]

    def _source_family(self, module: str) -> str:
        return module.split(".", 1)[0].casefold() if module else "unknown"

    def _first_text(self, mapping: Mapping[str, Any], names: Sequence[str]) -> str | None:
        for name in names:
            value = mapping.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None
