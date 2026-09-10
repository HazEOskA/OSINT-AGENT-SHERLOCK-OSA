from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from sherlock_osa.emailosint import EmailOsintClient
from sherlock_osa.errors import SherlockError


class FakeResponse:
    def __init__(self, payload: bytes, content_type: str = "application/json") -> None:
        self.payload = payload
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int = -1) -> bytes:
        return self.payload[:limit] if limit >= 0 else self.payload


class EmailOsintClientTests(unittest.TestCase):
    def test_json_lookup_normalises_and_redacts(self) -> None:
        provider = {
            "linked_accounts": [
                {
                    "platform": "GitHub",
                    "username": "osa",
                    "profile_url": "https://github.com/osa",
                    "custom_safe_field": "preserve-me",
                }
            ],
            "data_breaches": [{"title": "Example Breach", "password_hash": "secret-hash"}],
            "infostealer_logs": [
                {
                    "origin_url": "https://example.test",
                    "capture_date": "2026-01-02T03:04:05Z",
                    "credential": "user:secret",
                }
            ],
            "ai_summary": {
                "headline": "Likely test profile",
                "summary": "One linked account and exposed breach data.",
                "risk": "high",
                "reasoning": "Breach and infostealer exposure.",
            },
            "meta": {
                "first_seen": "2013-10-04T00:00:00Z",
                "last_seen": "2026-08-30T00:00:00Z",
                "custom_meta": "keep-this-too",
            },
        }
        response = FakeResponse(json.dumps(provider).encode("utf-8"))
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        with patch("urllib.request.urlopen", return_value=response):
            result = client.lookup({"email": "name@example.com"})

        self.assertEqual(result["engine"], "EMAILOSINT")
        self.assertEqual(result["exposure"]["counts"]["linked_accounts"], 1)
        self.assertEqual(result["exposure"]["counts"]["breaches"], 1)
        self.assertEqual(result["exposure"]["counts"]["infostealer"], 1)
        self.assertEqual(
            result["provider"]["raw"]["infostealer_logs"][0]["credential"],
            "[REDACTED]",
        )
        self.assertEqual(
            result["provider"]["raw"]["data_breaches"][0]["password_hash"],
            "[REDACTED]",
        )
        self.assertEqual(
            result["provider"]["raw"]["linked_accounts"][0]["custom_safe_field"],
            "preserve-me",
        )
        self.assertEqual(result["risk"]["level"], "high")
        self.assertEqual(result["identity"]["ai_profile"]["headline"], "Likely test profile")
        self.assertEqual(
            result["identity"]["ai_profile"]["reason"],
            "Breach and infostealer exposure.",
        )
        self.assertEqual(result["timeline"]["first_seen"], "2013-10-04T00:00:00Z")
        self.assertEqual(result["timeline"]["meta"]["custom_meta"], "keep-this-too")
        self.assertTrue(result["parity"]["safe_provider_payload_preserved"])

    def test_sse_lookup_collects_provider_events(self) -> None:
        stream = (
            b"event: identifier_result\n"
            b'data: {"platform":"GitHub","username":"osa"}\n\n'
            b"event: data_breaches\n"
            b'data: [{"title":"Example"}]\n\n'
            b"event: ai_summary\n"
            b'data: {"summary":"Profile summary"}\n\n'
        )
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(stream, "text/event-stream"),
        ):
            result = client.lookup({"email": "name@example.com"})

        self.assertEqual(result["exposure"]["counts"]["linked_accounts"], 1)
        self.assertEqual(result["exposure"]["counts"]["breaches"], 1)
        self.assertEqual(result["identity"]["summary"], "Profile summary")
        self.assertEqual(result["parity"]["events_total"], 3)
        self.assertEqual(result["parity"]["event_counts"]["identifier_result"], 1)

    def test_official_sse_shape_preserves_full_safe_intelligence(self) -> None:
        stream = (
            b"event: identifier_result\n"
            b'data: {"module":{"name":"github"},"data":{"fields":{"found":true,"username":"osa","profile_url":"https://github.com/osa","followers":42,"safe_extra":"kept"}}}\n\n'
            b"event: identifier_result\n"
            b'data: {"module":{"name":"spotify"},"data":{"fields":{"registered":true,"display_name":"Osa"}}}\n\n'
            b"event: data_breaches\n"
            b'data: {"amount":6,"sources":3,"results":[{"title":"Example Breach","breach_date":"2024-05-06","password":"must-not-leak","data_classes":["Email addresses","Usernames"]}]}\n\n'
            b"event: infostealer\n"
            b'data: {"amount":1,"sources":1,"results":[{"origin_url":"https://portal.example.test/login","capture_date":"2024-10-01T00:00:00Z","credential":"must-not-leak","browser":"Chrome"}]}\n\n'
            b"event: ai_summary\n"
            b'data: {"headline":"Likely Alex Morgan","summary":"Software engineer with linked developer profiles.","risk":"high","reason":"Six breach hits and one infostealer capture.","city":"Austin"}\n\n'
            b"event: done\n"
            b'data: {"meta":{"first_seen":"2013-10-04T00:00:00Z","last_seen":"2026-08-31T00:00:00Z","sources":104,"lookup_id":"lookup-123"}}\n\n'
        )
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(stream, "text/event-stream"),
        ):
            result = client.lookup({"email": "alex.morgan@example.com"})

        self.assertEqual(result["parity"]["events_total"], 6)
        self.assertEqual(result["parity"]["identity_signal_count"], 2)
        self.assertEqual(result["parity"]["provider_source_count"], 2)
        self.assertEqual(result["provenance"]["sources"], ["github", "spotify"])
        self.assertEqual(result["identity"]["signals"][0]["source"], "github")
        self.assertEqual(
            result["identity"]["signals"][0]["fields"]["safe_extra"],
            "kept",
        )
        self.assertEqual(result["exposure"]["breach_summary"]["amount"], 6)
        self.assertEqual(result["exposure"]["breach_summary"]["sources"], 3)
        self.assertEqual(result["exposure"]["infostealer_summary"]["amount"], 1)
        self.assertEqual(result["exposure"]["breaches"][0]["password"], "[REDACTED]")
        self.assertEqual(
            result["exposure"]["infostealer"][0]["credential"],
            "[REDACTED]",
        )
        self.assertEqual(result["identity"]["ai_profile"]["headline"], "Likely Alex Morgan")
        self.assertEqual(result["identity"]["ai_profile"]["risk"], "high")
        self.assertEqual(
            result["identity"]["ai_profile"]["reason"],
            "Six breach hits and one infostealer capture.",
        )
        self.assertEqual(result["identity"]["ai_profile"]["payload"]["city"], "Austin")
        self.assertEqual(result["timeline"]["first_seen"], "2013-10-04T00:00:00Z")
        self.assertEqual(result["timeline"]["last_seen"], "2026-08-31T00:00:00Z")
        self.assertEqual(result["timeline"]["meta"]["sources"], 104)
        self.assertEqual(result["provider"]["raw"]["transport"], "sse")
        self.assertEqual(len(result["provider"]["events"]), 6)

    def test_duplicate_provider_records_are_deduplicated_without_losing_raw_events(self) -> None:
        event = (
            b"event: identifier_result\n"
            b'data: {"module":{"name":"github"},"data":{"fields":{"found":true,"username":"osa"}}}\n\n'
        )
        stream = event + event
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        with patch(
            "urllib.request.urlopen",
            return_value=FakeResponse(stream, "text/event-stream"),
        ):
            result = client.lookup({"email": "name@example.com"})

        self.assertEqual(len(result["provider"]["events"]), 2)
        self.assertEqual(result["parity"]["events_total"], 2)
        self.assertEqual(result["parity"]["identity_signal_count"], 1)

    def test_client_requests_streaming_parity_transport(self) -> None:
        response = FakeResponse(b'{"linked_accounts": []}')
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        captured = []

        def fake_urlopen(request, timeout):
            captured.append(request)
            return response

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            client.lookup({"email": "name@example.com"})

        self.assertIn("text/event-stream", captured[0].headers["Accept"])

    def test_invalid_email_fails_closed(self) -> None:
        with self.assertRaises(SherlockError) as caught:
            EmailOsintClient().lookup({"email": "not-an-email"})
        self.assertEqual(caught.exception.code, "INVALID_EMAIL")


if __name__ == "__main__":
    unittest.main()
