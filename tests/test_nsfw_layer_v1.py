from __future__ import annotations

import unittest
from pathlib import Path

from sherlock_osa.social_graph import build_social_graph
from sherlock_osa.social_taxonomy import classify_sensitive_bucket, classify_service


ROOT = Path(__file__).resolve().parents[1]


class SensitiveTaxonomyTests(unittest.TestCase):
    def test_adult_services_are_sensitive_but_normal_dating_stays_dating(self) -> None:
        self.assertEqual(classify_service("OnlyFans"), "ADULT")
        self.assertEqual(classify_service("Fansly"), "ADULT")
        self.assertEqual(classify_service("Feeld"), "DATING")
        self.assertEqual(classify_service("Tinder"), "DATING")

    def test_sensitive_bucket_classification_is_explicit(self) -> None:
        self.assertEqual(classify_sensitive_bucket("OnlyFans"), "CREATOR_PLATFORMS")
        self.assertEqual(classify_sensitive_bucket("Pornhub"), "ADULT_COMMUNITIES")
        self.assertEqual(
            classify_sensitive_bucket("unknown", origin="wayback.archive.org historical"),
            "HISTORICAL_ARCHIVE",
        )


class SensitiveGraphTests(unittest.TestCase):
    def test_sensitive_layer_is_separate_collapsed_and_evidence_first(self) -> None:
        emailosint = {
            "identity": {"signals": []},
            "provider": {
                "events": [
                    {
                        "event": "creator_probe",
                        "data": {
                            "service": "OnlyFans",
                            "found": True,
                            "username": "osa",
                            "profile_url": "https://onlyfans.example/osa",
                        },
                    },
                    {
                        "event": "adult_probe",
                        "data": {
                            "service": "Pornhub",
                            "status": "blocked",
                            "username": "osa",
                            "profile_url": "https://pornhub.example/users/osa",
                        },
                    },
                    {
                        "event": "negative_probe",
                        "data": {
                            "service": "Fansly",
                            "not_found": True,
                            "username": "missing-osa",
                            "profile_url": "https://fansly.example/missing-osa",
                        },
                    },
                ],
                "raw": {},
            },
        }

        graph = build_social_graph(emailosint=emailosint, sensor_payloads={})
        sensitive = graph["sensitive_intelligence"]

        self.assertEqual(graph["version"], "v3.2")
        self.assertEqual(sensitive["version"], "v1")
        self.assertTrue(sensitive["default_collapsed"])
        self.assertEqual(sensitive["placement"], "CASE_REPORT_BOTTOM")
        self.assertFalse(sensitive["media_autoload"])
        self.assertTrue(sensitive["truth"]["same_username_is_not_same_person"])
        self.assertTrue(sensitive["truth"]["found_requires_source_signal"])
        self.assertFalse(sensitive["truth"]["explicit_media_autoload"])

        accounts = sensitive["accounts"]
        services = {item["service"] for item in accounts}
        self.assertIn("OnlyFans", services)
        self.assertIn("Pornhub", services)
        self.assertNotIn("Fansly", services)

        onlyfans = next(item for item in accounts if item["service"] == "OnlyFans")
        self.assertEqual(onlyfans["sensitive_bucket"], "CREATOR_PLATFORMS")
        self.assertEqual(onlyfans["evidence_tier"], "DIRECT_PUBLIC_SIGNAL")
        self.assertFalse(onlyfans["media_autoload"])

        self.assertEqual(sensitive["summary"]["found_total"], 1)
        self.assertEqual(sensitive["summary"]["direct_public_profiles"], 1)
        self.assertEqual(sensitive["summary"]["blocked_total"], 1)

    def test_same_username_does_not_create_sensitive_identity_claim(self) -> None:
        graph = build_social_graph(
            emailosint=None,
            sensor_payloads={
                "social_mesh": {
                    "batches": [
                        {
                            "username": "samehandle",
                            "found": [
                                {
                                    "site": "OnlyFans",
                                    "category": "ADULT",
                                    "profile_url": "https://onlyfans.example/samehandle",
                                    "probe_url": "https://onlyfans.example/samehandle",
                                    "reliability": 0.9,
                                },
                                {
                                    "site": "GitHub",
                                    "category": "DEVELOPER",
                                    "profile_url": "https://github.com/samehandle",
                                    "probe_url": "https://github.com/samehandle",
                                    "reliability": 0.95,
                                },
                            ],
                        }
                    ]
                }
            },
        )
        self.assertTrue(graph["truth"]["same_username_is_not_same_person"])
        self.assertEqual(graph["sensitive_intelligence"]["summary"]["signals_total"], 1)
        self.assertEqual(graph["category_counts"]["DEVELOPER"], 1)


class SensitiveUiContractTests(unittest.TestCase):
    def test_sensitive_ui_is_bottom_collapsed_and_does_not_create_images(self) -> None:
        js = (ROOT / "src/sherlock_osa/web/parity.js").read_text(encoding="utf-8")
        css = (ROOT / "src/sherlock_osa/web/parity.css").read_text(encoding="utf-8")

        self.assertIn('section.id = "sensitive-intelligence-section"', js)
        self.assertIn('shell.id = "sensitive-intelligence-shell"', js)
        self.assertIn('result.insertBefore(section, raw)', js)
        self.assertIn('NSFW / ADULT — CLICK TO REVEAL', js)
        self.assertIn('SENSITIVE_BUCKET_ORDER', js)
        self.assertNotIn('document.createElement("img")', js)
        self.assertIn('.sensitive-intelligence-shell', css)
        self.assertIn('.sensitive-bucket', css)

        social_order = js.split("const SOCIAL_CATEGORY_ORDER = [", 1)[1].split("];", 1)[0]
        self.assertNotIn('"ADULT"', social_order)


if __name__ == "__main__":
    unittest.main()
