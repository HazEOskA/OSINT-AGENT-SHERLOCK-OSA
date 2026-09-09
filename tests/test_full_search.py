from __future__ import annotations

import unittest

from sherlock_osa.research_service import detect_search_kind, person_username_candidates


class FullSearchHelpersTests(unittest.TestCase):
    def test_auto_detects_primary_search_types(self) -> None:
        self.assertEqual(detect_search_kind("name@example.com"), "EMAIL")
        self.assertEqual(detect_search_kind("https://example.com/u/osa"), "URL")
        self.assertEqual(detect_search_kind("example.com"), "DOMAIN")
        self.assertEqual(detect_search_kind("Bartosz Osiński"), "PERSON")
        self.assertEqual(detect_search_kind("HazEOskA"), "USERNAME")
        self.assertEqual(detect_search_kind("+31 6 12345678"), "PHONE")

    def test_person_generates_deterministic_username_candidates(self) -> None:
        candidates = person_username_candidates("Bartosz Osiński")
        self.assertIn("bartoszosinski", candidates)
        self.assertIn("bartosz.osinski", candidates)
        self.assertIn("bosinski", candidates)
        self.assertEqual(len(candidates), len(set(candidates)))


if __name__ == "__main__":
    unittest.main()
