from __future__ import annotations

import hashlib
import unittest

from sherlock_osa.correlation import CorrelationEngine
from sherlock_osa.findings import AssertionLevel, FindingStatus, stable_finding_id
from sherlock_osa.investigation import DetectiveInvestigator, InvestigationMode
from sherlock_osa.research import (
    IdentifierKind,
    ResearchEvidence,
    ResearchIdentifier,
    ResearchResult,
    TrustState,
)


def evidence(
    evidence_id: str,
    module: str,
    *,
    kind: IdentifierKind = IdentifierKind.USERNAME,
    value: str = "HazEOskA",
    fields: dict[str, object] | None = None,
    confidence: float = 0.95,
    source_urls: tuple[str, ...] = (),
    parent_evidence_id: str | None = None,
) -> ResearchEvidence:
    digest = hashlib.sha256(evidence_id.encode("utf-8")).hexdigest()
    return ResearchEvidence(
        evidence_id=evidence_id,
        module=module,
        identifier=ResearchIdentifier(
            kind,
            value,
            parent_evidence_id=parent_evidence_id,
        ),
        fields=fields or {},
        confidence=confidence,
        source_urls=source_urls,
        trust=TrustState.CLEAN,
        poison_reasons=(),
        collected_at="2026-09-09T20:00:00Z",
        evidence_sha256=digest,
    )


class DetectiveCorrelationTests(unittest.TestCase):
    def test_three_independent_sources_confirm_finding_and_preserve_hard_links(self) -> None:
        result = CorrelationEngine().correlate(
            (
                evidence("e1", "maigret.username", source_urls=("https://example.com/a",)),
                evidence("e2", "github.profile", source_urls=("https://github.com/HazEOskA",)),
                evidence("e3", "wayback.url", source_urls=("https://web.archive.org/example",)),
            )
        )

        target = next(
            item
            for item in result.findings
            if item.finding_id == stable_finding_id("USERNAME", "hazeoska")
        )
        self.assertEqual(target.status, FindingStatus.CONFIRMED)
        self.assertEqual(target.assertion, AssertionLevel.FACT)
        self.assertEqual(target.source_count, 3)
        self.assertEqual(
            {link.url for link in target.sources},
            {
                "https://example.com/a",
                "https://github.com/HazEOskA",
                "https://web.archive.org/example",
            },
        )

    def test_extracted_profile_creates_relation_from_seed_to_hard_url(self) -> None:
        result = CorrelationEngine().correlate(
            (
                evidence(
                    "e1",
                    "holehe.email",
                    kind=IdentifierKind.EMAIL,
                    value="osa@example.com",
                    fields={
                        "service": "GitHub",
                        "username": "HazEOskA",
                        "profile_url": "https://github.com/HazEOskA",
                    },
                    source_urls=("https://github.com/HazEOskA",),
                ),
            )
        )

        url_id = stable_finding_id("URL", "https://github.com/HazEOskA")
        self.assertTrue(any(item.finding_id == url_id for item in result.findings))
        self.assertTrue(
            any(
                relation.relation_type == "OBSERVED_IN"
                and relation.to_finding_id == url_id
                for relation in result.relations
            )
        )

    def test_contradictory_presence_signals_mark_finding_conflicted(self) -> None:
        result = CorrelationEngine().correlate(
            (
                evidence("e1", "source-a.username", fields={"exists": True}),
                evidence("e2", "source-b.username", fields={"exists": False}),
            )
        )
        target = next(item for item in result.findings if item.kind == "USERNAME")
        self.assertEqual(target.status, FindingStatus.CONFLICTED)
        self.assertEqual(len(result.conflicts), 1)


class FakeResearchEngine:
    def __init__(self, result: ResearchResult) -> None:
        self.result = result

    def run(self, seeds, *, allowed_capabilities, event_sink=None):
        if event_sink:
            event_sink(
                "identifier_result",
                {
                    "module": self.result.evidence[0].module,
                    "evidence_id": self.result.evidence[0].evidence_id,
                },
            )
        return self.result


class DetectiveInvestigationTests(unittest.TestCase):
    def test_investigator_returns_case_summary_and_emits_detective_events(self) -> None:
        items = (
            evidence("e1", "maigret.username", source_urls=("https://example.com/a",)),
            evidence("e2", "github.profile", source_urls=("https://github.com/HazEOskA",)),
            evidence("e3", "wayback.url", source_urls=("https://web.archive.org/example",)),
        )
        research = ResearchResult(
            research_id="research-1",
            status="COMPLETED",
            stop_reason="NO_MORE_TRUSTED_PIVOTS",
            duration_ms=1234,
            identifiers_seen=4,
            module_invocations=9,
            evidence=items,
            tainted_evidence=0,
            result_sha256="a" * 64,
        )
        events: list[str] = []
        investigator = DetectiveInvestigator(FakeResearchEngine(research))
        result = investigator.investigate(
            [ResearchIdentifier(IdentifierKind.USERNAME, "HazEOskA")],
            allowed_capabilities=["osint.username.lookup"],
            mode=InvestigationMode.DEEP,
            event_sink=lambda event, payload: events.append(event),
        )

        self.assertEqual(result.summary.confirmed_findings, 1)
        self.assertEqual(result.summary.sources_checked, 3)
        self.assertIn("investigation_started", events)
        self.assertIn("evidence_collected", events)
        self.assertIn("finding_confirmed", events)
        self.assertIn("investigation_completed", events)
        self.assertEqual(len(result.result_sha256), 64)


if __name__ == "__main__":
    unittest.main()
