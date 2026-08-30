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
            "linked_accounts": [{"platform": "GitHub", "username": "osa"}],
            "data_breaches": [{"title": "Example Breach"}],
            "infostealer_logs": [{"origin_url": "https://example.test", "password": "secret"}],
            "ai_summary": {"summary": "One linked account and exposed breach data."},
            "risk": {"level": "high", "reason": "Breach exposure"},
        }
        response = FakeResponse(json.dumps(provider).encode("utf-8"))
        client = EmailOsintClient(endpoint="https://provider.test/v1/lookup/email")

        with patch("urllib.request.urlopen", return_value=response):
            result = client.lookup({"email": "name@example.com"})

        self.assertEqual(result["engine"], "EMAILOSINT")
        self.assertEqual(result["exposure"]["counts"]["linked_accounts"], 1)
        self.assertEqual(result["exposure"]["counts"]["breaches"], 1)
        self.assertEqual(result["exposure"]["counts"]["infostealer"], 1)
        self.assertEqual(result["provider"]["raw"]["infostealer_logs"][0]["password"], "[REDACTED]")
        self.assertEqual(result["risk"]["level"], "high")

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

    def test_invalid_email_fails_closed(self) -> None:
        with self.assertRaises(SherlockError) as caught:
            EmailOsintClient().lookup({"email": "not-an-email"})
        self.assertEqual(caught.exception.code, "INVALID_EMAIL")


if __name__ == "__main__":
    unittest.main()
