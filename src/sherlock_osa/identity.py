from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from sherlock_osa.findings import Finding, Relation


@dataclass(frozen=True, slots=True)
class IdentityCluster:
    cluster_id: str
    finding_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    confidence: float
    status: str
    source_families: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "cluster_id": self.cluster_id,
            "finding_ids": list(self.finding_ids),
            "reasons": list(self.reasons),
            "confidence": self.confidence,
            "status": self.status,
            "source_families": list(self.source_families),
        }


class IdentityResolver:
    """Conservative identity clustering.

    V2 never merges entities from name/username similarity alone. Clusters require
    explicit evidence relations or the same hard source URL. This keeps identity
    claims separate from mere source observations.
    """

    _linkable_relations = frozenset({"PIVOT", "OBSERVED_IN"})

    def resolve(
        self,
        findings: Sequence[Finding],
        relations: Sequence[Relation],
    ) -> tuple[IdentityCluster, ...]:
        by_id = {finding.finding_id: finding for finding in findings}
        parent = {finding_id: finding_id for finding_id in by_id}
        reasons_by_pair: dict[tuple[str, str], set[str]] = {}

        def find(value: str) -> str:
            root = value
            while parent[root] != root:
                root = parent[root]
            while parent[value] != value:
                nxt = parent[value]
                parent[value] = root
                value = nxt
            return root

        def union(left: str, right: str, reason: str) -> None:
            if left not in parent or right not in parent or left == right:
                return
            a, b = sorted((left, right))
            reasons_by_pair.setdefault((a, b), set()).add(reason)
            root_a, root_b = find(left), find(right)
            if root_a != root_b:
                parent[max(root_a, root_b)] = min(root_a, root_b)

        for relation in relations:
            if relation.relation_type not in self._linkable_relations:
                continue
            if relation.confidence < 0.75:
                continue
            union(
                relation.from_finding_id,
                relation.to_finding_id,
                f"{relation.relation_type}:{relation.confidence:.2f}",
            )

        url_to_findings: dict[str, set[str]] = {}
        for finding in findings:
            for source in finding.sources:
                if source.url:
                    url_to_findings.setdefault(source.url, set()).add(finding.finding_id)
        for url, finding_ids in url_to_findings.items():
            ordered = sorted(finding_ids)
            if len(ordered) < 2:
                continue
            anchor = ordered[0]
            for finding_id in ordered[1:]:
                union(anchor, finding_id, "SAME_HARD_SOURCE_URL")

        groups: dict[str, list[str]] = {}
        for finding_id in by_id:
            groups.setdefault(find(finding_id), []).append(finding_id)

        clusters: list[IdentityCluster] = []
        for finding_ids in groups.values():
            if len(finding_ids) < 2:
                continue
            members = tuple(sorted(finding_ids))
            member_set = set(members)
            reasons: set[str] = set()
            for (left, right), pair_reasons in reasons_by_pair.items():
                if left in member_set and right in member_set:
                    reasons.update(pair_reasons)

            families = sorted(
                {
                    source.source_family
                    for finding_id in members
                    for source in by_id[finding_id].sources
                    if source.source_family
                }
            )
            relation_bonus = min(0.25, 0.08 * len(reasons))
            family_bonus = min(0.15, 0.05 * max(0, len(families) - 1))
            confidence = round(min(0.95, 0.55 + relation_bonus + family_bonus), 4)
            if confidence >= 0.80 and len(families) >= 2:
                status = "STRONG"
            elif confidence >= 0.65:
                status = "SUPPORTED"
            else:
                status = "WEAK"

            cluster_seed = "|".join(members).encode("utf-8")
            clusters.append(
                IdentityCluster(
                    cluster_id=hashlib.sha256(cluster_seed).hexdigest()[:20],
                    finding_ids=members,
                    reasons=tuple(sorted(reasons)),
                    confidence=confidence,
                    status=status,
                    source_families=tuple(families),
                )
            )

        return tuple(sorted(clusters, key=lambda item: (-item.confidence, item.cluster_id)))
