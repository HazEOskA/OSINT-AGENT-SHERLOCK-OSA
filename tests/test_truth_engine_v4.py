from __future__ import annotations

import unittest

from sherlock_osa.emailosint_module import EmailOsintResearchModule
from sherlock_osa.findings import AssertionLevel, FindingStatus
from sherlock_osa.research import (
    IdentifierKind,
    ModuleContext,
    ResearchEvidence,
    ResearchIdentifier,
    TrustState,
)
from sherlock_osa.site_probe import ProbeVerdict, SiteDefinition
from sherlock_osa.site_probe_guarded import _truth_evaluate
from sherlock_osa.truth_correlation import TruthCorrelationEngine
from sherlock_osa.truth_engine import (
    TruthVerdict,
    detect_interstitial,
    mechanism_key,
    presence_verdict,
)


class TruthEnginePrimitiveTests(unittest.TestCase):
    def test_transport_success_is_not_presence(self) -> None:
        self.assertEqual(
            presence_verdict({"provider": "example", "http_status": 200}),
            TruthVerdict.OBSERVED,
        )
        self.assertEqual(presence_verdict({"found": True}), TruthVerdict.FOUND)
        self.assertEqual(presence_verdict({"found": False}), TruthVerdict.NOT_FOUND)

    def test_explicit_truth_verdict_wins(self) -> None:
        self.assertEqual(
            presence_verdict({"found": True, "truth_verdict": "UNRELIABLE"}),
            TruthVerdict.UNRELIABLE,
        )

    def test_aggregators_on_same_service_are_one_mechanism(self) -> None:
        url = "https://github.com/example"
        self.assertEqual(
            mechanism_key("maigret.username", url),
            mechanism_key("socialmesh.username", url),
        )

    def test_waf_interstitial_is_detected(self) -> None:
        self.assertEqual(
            detect_interstitial("<title>Just a moment</title> cf-chl-bypass challenge-platform"),
            "CLOUDFLARE",
        )
        definition = SiteDefinition(
            name="Example",
            source="test",
            category="SOCIAL",
            url_check="https://example.test/{account}",
            url_pretty="https://example.test/{account}",
            exists_code=200,
            missing_code=404,
        )
        verdict, reason = _truth_evaluate(
            definition,
            200,
            "https://example.test/alice",
            "Making sure you're not a bot - Anubis proof-of-work",
        )
        self.assertEqual(verdict, ProbeVerdict.BLOCKED)
        self.assertIn("ANUBIS", reason)


class TruthCorrelationTests(unittest.TestCase):
    @staticmethod
    def _evidence(
        module: str,
        fields: dict[str, object],
        *,
        url: str = "",
        confidence: float = 0.95,
    ) -> ResearchEvidence:
        return ResearchEvidence(
            evidence_id=f"e-{module}-{abs(hash(str(fields))) % 100000}",
            module=module,
            identifier=ResearchIdentifier(IdentifierKind.USERNAME, "alice"),
            fields=fields,
            confidence=confidence,
            source_urls=(url,) if url else (),
            trust=TrustState.CLEAN,
            poison_reasons=(),
            collected_at="2026-09-11T00:00:00Z",
            evidence_sha256=f"sha-{module}-{abs(hash(str(fields))) % 100000}",
        )

    def test_negative_source_does_not_create_positive_finding(self) -> None:
        evidence = self._evidence(
            "github.username",
            {"provider": "github", "found": False, "username": "alice"},
            url="https://github.com/alice",
        )
        result = TruthCorrelationEngine().correlate((evidence,))
        self.assertEqual(result.findings, ())

    def test_two_aggregators_same_profile_do_not_fake_independence(self) -> None:
        fields = {
            "found": True,
            "service": "GitHub",
            "username": "alice",
            "profile_url": "https://github.com/alice",
        }
        evidence = (
            self._evidence("maigret.username", fields, url="https://github.com/alice", confidence=0.9),
            self._evidence("socialmesh.username", fields, url="https://github.com/alice", confidence=0.95),
        )
        result = TruthCorrelationEngine().correlate(evidence)
        username = next(item for item in result.findings if item.kind == "USERNAME")
        self.assertEqual(username.source_count, 1)
        self.assertIn(username.status, {FindingStatus.POSSIBLE, FindingStatus.UNVERIFIED})
        self.assertEqual(username.assertion, AssertionLevel.HYPOTHESIS)

    def test_direct_exact_profile_can_be_fact_without_becoming_confirmed(self) -> None:
        evidence = self._evidence(
            "github.username",
            {
                "provider": "github",
                "found": True,
                "profile": {
                    "login": "alice",
                    "username": "alice",
                    "html_url": "https://github.com/alice",
                },
            },
            url="https://github.com/alice",
            confidence=0.98,
        )
        result = TruthCorrelationEngine().correlate((evidence,))
        username = next(item for item in result.findings if item.kind == "USERNAME")
        self.assertEqual(username.status, FindingStatus.PROBABLE)
        self.assertEqual(username.assertion, AssertionLevel.FACT)
        self.assertEqual(username.source_count, 1)


class _FakeEmailClient:
    def __init__(self, bundle: dict[str, object]) -> None:
        self.bundle = bundle

    def lookup(self, _raw: object) -> dict[str, object]:
        return self.bundle


class EmailOsintTruthTests(unittest.IsolatedAsyncioTestCase):
    async def test_observed_email_signal_does_not_become_found_or_pivot(self) -> None:
        bundle = {
            "identity": {
                "signals": [
                    {
                        "source": "github",
                        "status": "OBSERVED",
                        "fields": {"username": "alice"},
                        "provider_payload": {"username": "alice"},
                    }
                ]
            },
            "parity": {},
        }
        module = EmailOsintResearchModule(_FakeEmailClient(bundle))  # type: ignore[arg-type]
        result = await module.lookup(
            ResearchIdentifier(IdentifierKind.EMAIL, "alice@example.com"),
            ModuleContext(deadline_monotonic=10**12, allowed_capabilities=frozenset()),
        )
        self.assertFalse(result.fields["found"])
        self.assertEqual(result.fields["truth_verdict"], "OBSERVED")
        self.assertEqual(result.pivots, ())


if __name__ == "__main__":
    unittest.main()
