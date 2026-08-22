from __future__ import annotations

import hashlib
import unittest

from sherlock_osa.errors import SherlockError
from sherlock_osa.research_worker import TorCurlFetcher, TorResearchWorker


ONION_HOST = "a" * 56 + ".onion"
ONION_URL = f"http://{ONION_HOST}/record"


class FakeFetcher:
    def __init__(self, routes: dict[str, bytes]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def fetch(self, url: str) -> bytes:
        self.calls.append(url)
        for marker, body in self.routes.items():
            if marker in url:
                return body
        raise SherlockError("TOR_FETCH_FAILED", "test route missing")


def payload() -> dict[str, object]:
    return {
        "query": "target@example.com",
        "kind": "EMAIL",
        "max_results": 5,
        "mission": {
            "engine_state": "COMPLETED",
            "engine_mission_id": "mission-test",
            "engine_execution_id": "execution-test",
            "engine_receipt_sha256": "b" * 64,
        },
    }


class TorResearchWorkerTests(unittest.TestCase):
    def test_requires_completed_engine_receipt(self) -> None:
        raw = payload()
        raw["mission"] = {"engine_state": "RUNNING", "engine_receipt_sha256": "b" * 64}
        with self.assertRaises(SherlockError) as raised:
            TorResearchWorker(FakeFetcher({})).search(raw)
        self.assertEqual(raised.exception.code, "ENGINE_RECEIPT_REQUIRED")

    def test_fetches_only_indexed_onion_and_returns_hash_not_body(self) -> None:
        index = (
            '<a href="/search/redirect?redirect_url='
            + ONION_URL.replace(":", "%3A").replace("/", "%2F")
            + '">Indexed self-audit result</a>'
        ).encode()
        content = b"<html><title>Exposure record</title>target@example.com and private raw text</html>"
        fetcher = FakeFetcher({"ahmia.fi/search": index, ONION_HOST: content})
        result = TorResearchWorker(fetcher).search(payload())
        self.assertEqual(result["transport"], "TOR_SOCKS5H")
        self.assertFalse(result["direct_egress"])
        self.assertEqual(result["pages_fetched"], 1)
        self.assertEqual(len(result["matches"]), 1)
        match = result["matches"][0]
        self.assertEqual(match["content_sha256"], hashlib.sha256(content).hexdigest())
        self.assertNotIn("private raw text", str(result))
        self.assertEqual(fetcher.calls[1], ONION_URL)

    def test_curl_transport_denies_arbitrary_clearnet(self) -> None:
        with self.assertRaises(SherlockError) as raised:
            TorCurlFetcher._validate_url("https://example.com/")
        self.assertEqual(raised.exception.code, "WORKER_TARGET_DENIED")


if __name__ == "__main__":
    unittest.main()
