"""P0.3 read-only capability registry: deterministic offline security contracts."""
from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from sherlock_osa.api import handler_factory
from sherlock_osa.capability_registry import (
    REGISTRY_VERSION,
    build_capability_registry,
)
from sherlock_osa.source_registry import SOURCE_DESCRIPTORS


def sample_catalog():
    return [
        {
            "name": "Example",
            "url": "https://example.org/tool/",
            "sources": ["OSINT4ALL"],
            "execution_class": "CATALOG_ONLY",
        },
        {
            "name": "Example 2",
            "url": "https://example.org/tool#fragment",
            "sources": ["Awesome OSINT"],
            "execution_class": "CATALOG_ONLY_RESTRICTED",
        },
    ]


class CapabilityRegistryTests(unittest.TestCase):
    def test_native_adapters_match_existing_registry_and_never_grant_authority(self):
        payload = build_capability_registry()
        adapters = [
            row for row in payload["capabilities"]
            if row["type"] == "NATIVE_ADAPTER"
        ]
        self.assertEqual(payload["version"], REGISTRY_VERSION)
        self.assertEqual(len(adapters), len(SOURCE_DESCRIPTORS))
        self.assertEqual(payload["default_policy"], "DENY")
        self.assertFalse(payload["catalog_only_execution_allowed"])
        self.assertTrue(all(not row["authorization_granted"] for row in adapters))
        self.assertTrue(all(row["adapter_bound"] for row in adapters))
        self.assertTrue(all(row["requires_authorization"] for row in adapters))
        self.assertTrue(
            all(row["status"] in ("ADAPTER_READY", "UNAVAILABLE") for row in adapters)
        )

    def test_catalog_duplicate_url_is_one_restricted_record_with_provenance(self):
        payload = build_capability_registry(catalog_tools=sample_catalog(), source_descriptors=())
        self.assertEqual(payload["total_count"], 1)
        self.assertEqual(payload["catalog_count"], 1)
        item = payload["capabilities"][0]
        self.assertEqual(item["status"], "RESTRICTED")
        self.assertEqual(item["execution_class"], "CATALOG_ONLY_RESTRICTED")
        self.assertEqual(item["sources"], ["Awesome OSINT", "OSINT4ALL"])
        self.assertFalse(item["adapter_ready"])
        self.assertFalse(item["adapter_bound"])
        self.assertFalse(item["authorization_granted"])
        self.assertEqual(item["authorized_modes"], [])

    def test_unknown_class_fail_closed_not_execution_ready(self):
        data = [{"url": "https://example.org/unknown", "execution_class": "EXECUTE"}]
        result = build_capability_registry(catalog_tools=data, source_descriptors=())
        self.assertEqual(result["capabilities"][0]["status"], "RESTRICTED")
        self.assertFalse(result["capabilities"][0]["authorization_granted"])

    def test_invalid_scheme_credentials_and_oversize_are_excluded(self):
        entries = [
            {"url": "javascript:alert(1)"},
            {"url": "https://user:pass@example.org/path"},
            {"url": "https://example.org/" + ("a" * 3000)},
            {"url": "https://example.org/ok", "execution_class": "CATALOG_ONLY"},
        ]
        result = build_capability_registry(catalog_tools=entries, source_descriptors=())
        self.assertEqual(result["catalog_count"], 1)
        self.assertEqual(result["capabilities"][0]["status"], "CATALOG_ONLY")

    def test_stable_order_and_id_when_input_order_changes(self):
        sample = [
            {"name": "Z", "url": "https://z.example/"},
            {"name": "A", "url": "https://a.example/"},
        ]
        one = build_capability_registry(catalog_tools=sample, source_descriptors=())
        two = build_capability_registry(catalog_tools=list(reversed(sample)), source_descriptors=())
        self.assertEqual(one, two)

    def test_size_limit_and_invalid_entry_fail_closed(self):
        with self.assertRaises(ValueError):
            build_capability_registry(catalog_tools=[{}] * 6001, source_descriptors=())
        with self.assertRaises(ValueError):
            build_capability_registry(catalog_tools=["invalid"], source_descriptors=())

    def test_http_endpoint_bearer_required_and_catalog_not_executed(self):
        settings = SimpleNamespace(api_key="test-token")
        service = SimpleNamespace(settings=settings)
        with patch(
            "sherlock_osa.api.atlas_catalog",
            return_value={"tools": sample_catalog()},
        ) as mock_catalog:
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(service))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            path = "/api/v1/agent/capabilities"
            try:
                with self.assertRaises(urllib.error.HTTPError) as missing:
                    urllib.request.urlopen(base + path, timeout=3)
                self.assertEqual(missing.exception.code, 401)
                self.assertEqual(mock_catalog.call_count, 0)
                request = urllib.request.Request(
                    base + path,
                    headers={"Authorization": "Bearer test-token"},
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    payload = json.load(response)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(mock_catalog.call_count, 1)
                self.assertEqual(payload["version"], REGISTRY_VERSION)
                self.assertEqual(payload["catalog_count"], 1)
                self.assertFalse(payload["catalog_only_execution_allowed"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
