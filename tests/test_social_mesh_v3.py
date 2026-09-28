from __future__ import annotations

import asyncio
import time
import unittest

from sherlock_osa.phone_metadata import PhoneMetadataModule
from sherlock_osa.research import IdentifierKind, ModuleContext, ResearchIdentifier
from sherlock_osa.site_probe import (
    ProbeVerdict,
    SiteDefinition,
    _evaluate,
    merge_definitions,
    parse_sherlock,
    parse_wmn,
)
from sherlock_osa.social_graph import build_social_graph
from sherlock_osa.social_taxonomy import classify_service


class SocialTaxonomyTests(unittest.TestCase):
    def test_high_value_categories_are_explicit(self) -> None:
        self.assertEqual(classify_service("Google Account"), "GOOGLE")
        self.assertEqual(classify_service("YouTube"), "GOOGLE")
        self.assertEqual(classify_service("Tinder"), "DATING")
        self.assertEqual(classify_service("Bumble"), "DATING")
        self.assertEqual(classify_service("Instagram"), "SOCIAL")
        self.assertEqual(classify_service("Telegram"), "MESSAGING")
        self.assertEqual(classify_service("GitHub"), "DEVELOPER")

    def test_explicit_service_beats_generic_hint(self) -> None:
        self.assertEqual(
            classify_service("YouTube", category_hint="social"),
            "GOOGLE",
        )
        self.assertEqual(
            classify_service("Tinder", category_hint="social"),
            "DATING",
        )


class DatasetProbeTests(unittest.TestCase):
    def test_wmn_parser_preserves_dating_category_and_side_effect_guard(self) -> None:
        data = {
            "sites": [
                {
                    "name": "Dating.example",
                    "uri_check": "https://dating.example/{account}",
                    "uri_pretty": "https://dating.example/{account}",
                    "e_code": 200,
                    "e_string": "profile found",
                    "m_code": 404,
                    "m_string": "not found",
                    "known": ["known-user"],
                    "cat": "dating",
                },
                {
                    "name": "UnsafePost",
                    "uri_check": "https://example.test/check/{account}",
                    "post_body": '{"username":"{account}"}',
                    "headers": {"Content-Type": "application/json"},
                    "e_code": 200,
                    "e_string": "taken",
                    "m_code": 200,
                    "m_string": "available",
                    "known": ["known-user"],
                    "cat": "social",
                },
            ]
        }
        definitions = parse_wmn(data)
        self.assertEqual(len(definitions), 2)
        dating = next(item for item in definitions if item.name == "Dating.example")
        unsafe = next(item for item in definitions if item.name == "UnsafePost")
        self.assertEqual(dating.category, "DATING")
        self.assertTrue(dating.public_get_safe)
        self.assertFalse(unsafe.public_get_safe)
        self.assertEqual(unsafe.method, "POST")

    def test_sherlock_parser_and_merge_deduplicate_same_host(self) -> None:
        wmn = parse_wmn(
            {
                "sites": [
                    {
                        "name": "ExampleSocial",
                        "uri_check": "https://social.example/u/{account}",
                        "uri_pretty": "https://social.example/u/{account}",
                        "e_code": 200,
                        "e_string": "",
                        "m_code": 404,
                        "m_string": "not found",
                        "known": ["known"],
                        "cat": "social",
                    }
                ]
            }
        )
        sherlock = parse_sherlock(
            {
                "Example Social": {
                    "errorType": "status_code",
                    "regexCheck": "^[A-Za-z0-9_-]+$",
                    "url": "https://social.example/u/{}/",
                    "urlMain": "https://social.example/",
                    "username_claimed": "known",
                    "username_unclaimed": "definitely_missing_osa",
                }
            }
        )
        merged = merge_definitions(wmn, sherlock)
        self.assertEqual(len(merged), 1)
        self.assertIn("WhatsMyName", merged[0].source)
        self.assertIn("Sherlock Project", merged[0].source)
        self.assertIsNotNone(merged[0].username_regex)

    def test_probe_evaluator_never_equates_plain_200_with_found_when_signal_is_ambiguous(self) -> None:
        ambiguous = SiteDefinition(
            name="Ambiguous",
            source="fixture",
            category="SOCIAL",
            url_check="https://example.test/{}",
            url_pretty="https://example.test/{}",
            error_type="response_url",
        )
        verdict, _ = _evaluate(
            ambiguous,
            200,
            "https://example.test/someone",
            "same body for everybody",
        )
        self.assertEqual(verdict, ProbeVerdict.UNKNOWN)

    def test_positive_and_negative_signatures_take_precedence(self) -> None:
        definition = SiteDefinition(
            name="Strong",
            source="fixture",
            category="SOCIAL",
            url_check="https://example.test/{}",
            url_pretty="https://example.test/{}",
            exists_code=200,
            missing_code=200,
            exists_text="PROFILE_FOUND",
            missing_text="NO_SUCH_USER",
        )
        found, _ = _evaluate(definition, 200, "https://example.test/a", "PROFILE_FOUND")
        missing, _ = _evaluate(definition, 200, "https://example.test/b", "NO_SUCH_USER")
        self.assertEqual(found, ProbeVerdict.FOUND)
        self.assertEqual(missing, ProbeVerdict.NOT_FOUND)


class SocialGraphCatchAllTests(unittest.TestCase):
    def test_unknown_emailosint_event_names_still_surface_google_and_dating(self) -> None:
        emailosint = {
            "identity": {"signals": []},
            "provider": {
                "events": [
                    {
                        "event": "provider_module_payload",
                        "data": {
                            "module": "google-account-check",
                            "service": "Google Account",
                            "found": True,
                            "username": "osa",
                            "profile_url": "https://profiles.google.com/osa",
                        },
                    },
                    {
                        "event": "totally_new_event_name",
                        "data": {
                            "source": "dating-sensor",
                            "platform": "Tinder",
                            "registered": True,
                            "username": "osa",
                            "profile_url": "https://example.test/tinder/osa",
                        },
                    },
                ],
                "raw": {
                    "extra_modules": {
                        "Instagram": {
                            "service": "Instagram",
                            "exists": True,
                            "username": "osa",
                            "profile_url": "https://instagram.com/osa",
                        }
                    }
                },
            },
        }
        graph = build_social_graph(emailosint=emailosint, sensor_payloads={})
        self.assertGreaterEqual(graph["summary"]["google_found"], 1)
        self.assertGreaterEqual(graph["summary"]["dating_found"], 1)
        self.assertGreaterEqual(graph["summary"]["social_found"], 1)
        services = {item["service"] for item in graph["accounts"] if item["status"] == "FOUND"}
        self.assertIn("Google Account", services)
        self.assertIn("Tinder", services)
        self.assertIn("Instagram", services)

    def test_socialmesh_batch_is_merged_into_same_graph(self) -> None:
        graph = build_social_graph(
            emailosint=None,
            sensor_payloads={
                "social_mesh": {
                    "batches": [
                        {
                            "username": "HazEOskA",
                            "found": [
                                {
                                    "site": "GitHub",
                                    "category": "DEVELOPER",
                                    "verdict": "FOUND",
                                    "profile_url": "https://github.com/HazEOskA",
                                    "probe_url": "https://github.com/HazEOskA",
                                    "reliability": 0.96,
                                },
                                {
                                    "site": "Dating.ru",
                                    "category": "DATING",
                                    "verdict": "FOUND",
                                    "profile_url": "https://dating.ru/HazEOskA/",
                                    "probe_url": "https://dating.ru/HazEOskA/",
                                    "reliability": 0.94,
                                },
                            ],
                        }
                    ]
                }
            },
        )
        self.assertEqual(graph["summary"]["found_total"], 2)
        self.assertEqual(graph["summary"]["dating_found"], 1)
        self.assertEqual(graph["category_counts"]["DEVELOPER"], 1)
        self.assertGreaterEqual(graph["graph"]["edge_count"], 2)


class PhoneMetadataTests(unittest.TestCase):
    def test_phone_metadata_is_offline_and_does_not_claim_owner_or_precise_location(self) -> None:
        module = PhoneMetadataModule()
        result = asyncio.run(
            module.lookup(
                ResearchIdentifier(IdentifierKind.PHONE, "+31612345678"),
                ModuleContext(time.monotonic() + 5, frozenset({"osint.phone.metadata"})),
            )
        )
        self.assertTrue(result.fields["possible"])
        self.assertEqual(result.fields["region"], "NL")
        self.assertFalse(result.fields["owner_identified"])
        self.assertFalse(result.fields["precise_location_available"])
        self.assertFalse(result.fields["network_lookup_performed"])
        self.assertEqual(module.results[-1]["e164"], "+31612345678")


if __name__ == "__main__":
    unittest.main()
