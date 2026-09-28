from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from sherlock_osa.correlation import CorrelationEngine, CorrelationResult
from sherlock_osa.findings import AssertionLevel, Finding, FindingStatus, digest_payload
from sherlock_osa.research import ResearchEvidence, TrustState
from sherlock_osa.truth_engine import TruthVerdict, mechanism_key, presence_verdict


_DIRECT_FACT_PREFIXES = (
    "github.",
    "gitlab.",
    "gravatar.",
    "rdap.",
    "hibp.",
    "crtsh.",
)
_ARCHIVE_PREFIXES = ("wayback.", "commoncrawl.")


class TruthCorrelationEngine(CorrelationEngine):
    """Correlation that counts evidence mechanisms, not scraper names.

    Negative/unknown transport results are retained in the investigation source log,
    but they cannot manufacture positive findings. Multiple aggregators pointing at
    the same underlying host count as one mechanism.
    """

    def correlate(self, evidence: Sequence[ResearchEvidence]) -> CorrelationResult:
        positive = tuple(
            item
            for item in evidence
            if item.trust is TrustState.CLEAN
            and self._evidence_is_positive(item)
        )
        base = super().correlate(positive)
        findings = tuple(self._truth_adjust(finding) for finding in base.findings)
        return CorrelationResult(findings, base.relations, base.conflicts)

    def _evidence_is_positive(self, evidence: ResearchEvidence) -> bool:
        module = evidence.module
        if module == "seed-expansion.local" or module == "phone.metadata":
            return False
        verdict = presence_verdict(evidence.fields)
        if verdict is TruthVerdict.FOUND:
            return True
        # A clean archival/certificate source with a positive count is handled by
        # presence_verdict. No fallback from mere HTTP completion is allowed.
        return False

    def _truth_adjust(self, finding: Finding) -> Finding:
        mechanisms = {
            mechanism_key(source.source, source.url)
            for source in finding.sources
        }
        mechanism_count = len(mechanisms)
        max_conf = max((source.confidence for source in finding.sources), default=0.0)
        direct_fact = any(
            source.source.startswith(_DIRECT_FACT_PREFIXES)
            and source.confidence >= 0.9
            and bool(source.url)
            for source in finding.sources
        )
        archive_only = bool(finding.sources) and all(
            source.source.startswith(_ARCHIVE_PREFIXES)
            for source in finding.sources
        )

        if finding.status is FindingStatus.CONFLICTED:
            status = FindingStatus.CONFLICTED
            assertion = AssertionLevel.HYPOTHESIS
            confidence = min(max_conf, 0.49)
        elif mechanism_count >= 3 and max_conf >= 0.8:
            status = FindingStatus.CONFIRMED
            assertion = AssertionLevel.CORRELATED
            confidence = min(0.97, 0.78 + 0.05 * min(mechanism_count, 4))
        elif mechanism_count >= 2 and max_conf >= 0.65:
            status = FindingStatus.PROBABLE
            assertion = AssertionLevel.CORRELATED
            confidence = min(0.89, 0.68 + 0.05 * min(mechanism_count, 3))
        elif direct_fact and not archive_only:
            status = FindingStatus.PROBABLE
            assertion = AssertionLevel.FACT
            confidence = min(0.88, max(0.78, max_conf * 0.9))
        elif max_conf >= 0.45:
            status = FindingStatus.POSSIBLE
            assertion = AssertionLevel.HYPOTHESIS
            confidence = min(0.64, max_conf)
        else:
            status = FindingStatus.UNVERIFIED
            assertion = AssertionLevel.HYPOTHESIS
            confidence = min(0.44, max_conf)

        # Archives can prove historical presence of a URL, not identity ownership.
        if archive_only and status in {FindingStatus.CONFIRMED, FindingStatus.PROBABLE}:
            status = FindingStatus.POSSIBLE
            assertion = AssertionLevel.HYPOTHESIS
            confidence = min(confidence, 0.62)

        digest = digest_payload(
            {
                "finding_id": finding.finding_id,
                "kind": finding.kind,
                "value": finding.value,
                "status": status.value,
                "assertion": assertion.value,
                "confidence": round(confidence, 4),
                "mechanisms": sorted(mechanisms),
                "evidence": sorted(source.evidence_sha256 for source in finding.sources),
            }
        )
        return replace(
            finding,
            status=status,
            assertion=assertion,
            confidence=round(confidence, 4),
            source_count=mechanism_count,
            evidence_sha256=digest,
        )
