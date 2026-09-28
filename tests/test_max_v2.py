from __future__ import annotations

import hashlib
import os
import unittest
from unittest.mock import patch

from sherlock_osa.evidence_graph import build_evidence_graph, build_timeline
from sherlock_osa.findings import (
    AssertionLevel,
    EvidenceLink,
    Finding,
    FindingStatus,
    Relation,
)
from sherlock_osa.identity import IdentityResolver
from sherlock_osa.planner import AdaptiveSourcePlanner
from sherlock_osa.research import (
    IdentifierKind,
    ResearchEvidence,
    ResearchIdentifier,
    TrustState,
)
from sherlock_osa.research_service import normalize_phone, search_budget
from sherlock_osa.source_pack import (
    GITHUB_USERNAME,
    HIBP_ACCOUNT,
    WAYBACK_DOMAIN,
    IsolatedSourceModule,
    source_health,
)
from sherlock_osa.source_worker import (
    _parse_commoncrawl_lines,
    _rdap_base_for_domain,
    _valid_phone,
)
from sherlock_osa.investigation import InvestigationMode


def make_finding(
    finding_id: str,
    kind: str,
    value: str,
    *,
    url: str = "",
    source: str = "github.username",
    family: str = "github",
) -> Finding:
    links = ()
    if url:
        links = (
            EvidenceLink(
                evidence_id="e-" + finding_id,
                source=source,
                source_family=family,
                url=url,
                collected_at="2026-09-09T20:00:00Z",
                evidence_sha256=hashlib.sha256(finding_id.encode()).hexdigest(),
                confidence=0.95,
            ),
        )
    return Finding(
        finding_id=finding_id,
        kind=kind,
        value=value,
        title=f"{kind}: {value}",
        status=FindingStatus.PROBABLE,
        assertion=AssertionLevel.CORRELATED,
        confidence=0.8,
        source_count=1,
        sources=links,
    )


class MaxSourceRegistryTests(unittest.TestCase):
    def test_registry_v3_exposes_new_sources_and_truthful_key_gate(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            health = source_health()
        names = {item["name"] for item in health["sources"]}
        self.assertEqual(health["registry_version"], "v3")
        self.assertIn("gravatar.email", names)
        self.assertIn("github.username", names)
        self.assertIn("gitlab.username", names)
        self.assertIn("rdap.domain", names)
        self.assertIn("commoncrawl.domain", names)
        self.assertIn("hibp.account", names)
        self.assertIn("socialmesh.username", names)
        hibp = next(item for item in health["sources"] if item["name"] == "hibp.account")
        self.assertTrue(hibp["requires_key"])

    def test_planner_skips_hibp_without_key_and_quick_skips_archive(self) -> None:
        phone = ResearchIdentifier(IdentifierKind.PHONE, "+31612345678")
        domain = ResearchIdentifier(IdentifierKind.DOMAIN, "example.com")
        with patch.dict(os.environ, {"HIBP_API_KEY": ""}, clear=False):
            _, phone_decisions = AdaptiveSourcePlanner("MAX").plan(
                (IsolatedSourceModule(HIBP_ACCOUNT),), phone
            )
        self.assertEqual(phone_decisions[0].reason, "MISSING_CREDENTIAL")
        self.assertFalse(phone_decisions[0].run)

        _, archive_decisions = AdaptiveSourcePlanner("QUICK").plan(
            (IsolatedSourceModule(WAYBACK_DOMAIN),), domain
        )
        self.assertFalse(archive_decisions[0].run)

        modules, direct_decisions = AdaptiveSourcePlanner("QUICK").plan(
            (IsolatedSourceModule(GITHUB_USERNAME),),
            ResearchIdentifier(IdentifierKind.USERNAME, "HazEOskA"),
        )
        self.assertEqual(len(modules), 1)
        self.assertTrue(direct_decisions[0].run)

    def test_phone_normalization_is_international_and_deterministic(self) -> None:
        self.assertEqual(normalize_phone("+31 6 12345678"), "+31612345678")
        self.assertEqual(normalize_phone("0031 6 12345678"), "+31612345678")
        self.assertEqual(_valid_phone("+31 (6) 123-45678"), "+31612345678")
        with self.assertRaises(Exception):
            normalize_phone("0612345678")

    def test_mode_budgets_are_ordered_and_remain_inside_governance_cap(self) -> None:
        quick = search_budget(InvestigationMode.QUICK)
        deep = search_budget(InvestigationMode.DEEP)
        maximum = search_budget(InvestigationMode.MAX)
        self.assertLess(quick.hard_timeout_seconds, deep.hard_timeout_seconds)
        self.assertLess(deep.hard_timeout_seconds, maximum.hard_timeout_seconds)
        self.assertLess(quick.max_identifiers, deep.max_identifiers)
        self.assertLess(deep.max_identifiers, maximum.max_identifiers)
        self.assertEqual(maximum.hard_timeout_seconds, 300.0)


class MaxSourceParserTests(unittest.TestCase):
    def test_rdap_bootstrap_selects_authoritative_tld_service(self) -> None:
        payload = {
            "services": [
                [["com", "net"], ["https://rdap.example.test/"]],
                [["org"], ["https://rdap.org.test/"]],
            ]
        }
        self.assertEqual(
            _rdap_base_for_domain(payload, "example.com"),
            "https://rdap.example.test/",
        )

    def test_commoncrawl_parser_keeps_only_target_domain_urls(self) -> None:
        body = "\n".join(
            [
                '{"url":"https://example.com/a","timestamp":"20250101010101","status":"200"}',
                '{"url":"https://sub.example.com/b","timestamp":"20250102020202","status":"200"}',
                '{"url":"https://evil.test/x","timestamp":"20250103030303","status":"200"}',
            ]
        )
        rows = _parse_commoncrawl_lines(body, "example.com", "DOMAIN")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all("example.com" in row["url"] for row in rows))


class MaxIdentityAndGraphTests(unittest.TestCase):
    def test_identity_resolver_does_not_merge_username_similarity_alone(self) -> None:
        findings = (
            make_finding("a", "USERNAME", "bartosz.osinski"),
            make_finding("b", "USERNAME", "bartoszosinski"),
        )
        self.assertEqual(IdentityResolver().resolve(findings, ()), ())

    def test_identity_resolver_can_merge_explicit_high_confidence_relation(self) -> None:
        findings = (
            make_finding("a", "USERNAME", "HazEOskA", url="https://github.com/HazEOskA"),
            make_finding("b", "URL", "https://github.com/HazEOskA", url="https://github.com/HazEOskA", source="maigret.username", family="maigret"),
        )
        relation = Relation(
            relation_type="PIVOT",
            from_finding_id="a",
            to_finding_id="b",
            evidence_ids=("e-a", "e-b"),
            confidence=0.95,
        )
        clusters = IdentityResolver().resolve(findings, (relation,))
        self.assertEqual(len(clusters), 1)
        self.assertIn(clusters[0].status, {"SUPPORTED", "STRONG"})

    def test_graph_separates_findings_from_evidence_nodes(self) -> None:
        finding = make_finding(
            "a", "USERNAME", "HazEOskA", url="https://github.com/HazEOskA"
        )
        graph = build_evidence_graph((finding,), ())
        self.assertEqual(len(graph.nodes), 2)
        self.assertTrue(any(node.node_type == "FINDING" for node in graph.nodes))
        self.assertTrue(any(node.node_type == "EVIDENCE" for node in graph.nodes))
        self.assertTrue(any(edge.edge_type == "SUPPORTED_BY" for edge in graph.edges))

    def test_timeline_extracts_historical_source_date(self) -> None:
        evidence = ResearchEvidence(
            evidence_id="e1",
            module="wayback.domain",
            identifier=ResearchIdentifier(IdentifierKind.DOMAIN, "example.com"),
            fields={
                "captures": [
                    {"timestamp": "20250102030405", "original": "https://example.com"}
                ]
            },
            confidence=0.95,
            source_urls=("https://web.archive.org/web/20250102030405/https://example.com",),
            trust=TrustState.CLEAN,
            poison_reasons=(),
            collected_at="2026-09-09T20:00:00Z",
            evidence_sha256="a" * 64,
        )
        timeline = build_timeline((evidence,))
        self.assertTrue(any(item.timestamp.startswith("2025-01-02T03:04:05") for item in timeline))


if __name__ == "__main__":
    unittest.main()
