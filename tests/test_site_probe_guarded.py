from __future__ import annotations

import unittest

from sherlock_osa.site_probe import SiteDefinition, ProbeVerdict, _evaluate
from sherlock_osa.site_probe_guarded import _sanitize_definition


class GuardedProbeTests(unittest.TestCase):
    def test_multi_message_repr_is_quarantined_before_probe_evaluation(self) -> None:
        definition = SiteDefinition(
            name="Fixture",
            source="Sherlock Project",
            category="SOCIAL",
            url_check="https://example.test/{}",
            url_pretty="https://example.test/{}",
            missing_text="['not found', 'missing']",
            error_type="message",
        )
        guarded = _sanitize_definition(definition)
        self.assertEqual(guarded.missing_text, "")
        self.assertEqual(
            guarded.error_type,
            "message_list_requires_site_specific_parser",
        )
        verdict, _ = _evaluate(
            guarded,
            200,
            "https://example.test/osa",
            "generic success page",
        )
        self.assertEqual(verdict, ProbeVerdict.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
