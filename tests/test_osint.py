from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sherlock_osa.errors import SherlockError
from sherlock_osa.osint import (
    FixedEgressHttpClient,
    HttpResponse,
    OsintAgent,
    QueryKind,
    SkillRegistry,
    classify_query,
)


class FakeHttp(FixedEgressHttpClient):
    def __init__(self, routes: dict[str, tuple[int, object | str]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, *, headers=None) -> HttpResponse:  # type: ignore[override]
        safe_headers = dict(headers or {})
        self.calls.append((url, safe_headers))
        for marker, (status, payload) in self.routes.items():
            if marker in url:
                if isinstance(payload, str):
                    return HttpResponse(status, payload.encode(), "text/html")
                return HttpResponse(status, json.dumps(payload).encode(), "application/json")
        return HttpResponse(404, b'{"Error":"Not found"}', "application/json")


class QueryClassificationTests(unittest.TestCase):
    def test_auto_detects_supported_identifiers(self) -> None:
        cases = [
            ("test@example.com", QueryKind.EMAIL, "test@example.com"),
            ("+48 500 600 700", QueryKind.PHONE, "+48500600700"),
            ("Jan Kowalski", QueryKind.PERSON, "Jan Kowalski"),
            ("sherlock_osa", QueryKind.USERNAME, "sherlock_osa"),
            ("Example.COM.", QueryKind.DOMAIN, "example.com"),
            ("203.0.113.7", QueryKind.IP, "203.0.113.7"),
        ]
        for raw, kind, normalized in cases:
            with self.subTest(raw=raw):
                result = classify_query(raw, QueryKind.AUTO, "PL")
                self.assertEqual(result.kind, kind)
                self.assertEqual(result.normalized, normalized)

    def test_local_phone_uses_default_region(self) -> None:
        query = classify_query("500 600 700", QueryKind.PHONE, "PL")
        self.assertEqual(query.normalized, "+48500600700")
        self.assertIn("***", query.masked)
        self.assertEqual(
            classify_query("202 555 0147", QueryKind.PHONE, "US").normalized,
            "+12025550147",
        )

    def test_ambiguous_or_invalid_values_are_rejected(self) -> None:
        with self.assertRaises(SherlockError):
            classify_query("not/a/target", QueryKind.AUTO, "PL")
        with self.assertRaises(SherlockError):
            classify_query("12", QueryKind.PHONE, "PL")


class SkillRegistryTests(unittest.TestCase):
    def test_registry_has_real_typed_osint_skills(self) -> None:
        registry = SkillRegistry.load()
        skills = registry.all()
        self.assertEqual(len(skills), 10)
        self.assertEqual(len({skill.skill_id for skill in skills}), 10)
        phone = registry.resolve(QueryKind.PHONE, include_darkweb=True)
        self.assertEqual(phone[0].skill_id, "osint.query-classification")
        self.assertIn("osint.phone-intelligence", {skill.skill_id for skill in phone})
        self.assertIn("osint.darkweb-index-search", {skill.skill_id for skill in phone})


class OsintAgentTests(unittest.TestCase):
    def test_email_breach_lookup_is_live_and_evidence_does_not_store_raw_query(self) -> None:
        http = FakeHttp(
            {
                "api.xposedornot.com": (
                    200,
                    {"status": "success", "breaches": [["Adobe", "LinkedIn"]]},
                )
            }
        )
        agent = OsintAgent(http=http, environment={"SHERLOCK_ENABLE_AHMIA": "false"})
        result = agent.investigate(
            {
                "query": "target@example.com",
                "kind": "EMAIL",
                "default_region": "PL",
                "purpose": "SELF_AUDIT",
                "include_darkweb": False,
                "consent": True,
            }
        )
        self.assertEqual(result["summary"]["breach_source_count"], 2)
        self.assertEqual(result["summary"]["risk"], "HIGH")
        self.assertTrue(result["evidence"]["verification"]["valid"])
        self.assertIn("xposedornot.community", result["truth"]["live_network_sources_called"])
        evidence_text = json.dumps(result["evidence"]["records"])
        self.assertNotIn("target@example.com", evidence_text)
        self.assertFalse(result["truth"]["raw_breach_records_returned"])

    def test_phone_uses_leakcheck_but_strips_raw_credentials(self) -> None:
        http = FakeHttp(
            {
                "leakcheck.io": (
                    200,
                    {
                        "success": True,
                        "found": 2,
                        "result": [
                            {
                                "source": {"name": "Example breach"},
                                "fields": ["phone", "email", "password"],
                                "password": "must-never-leave-adapter",
                            },
                            {"source": {"name": "Second source"}, "password": "secret"},
                        ],
                    },
                )
            }
        )
        agent = OsintAgent(
            http=http,
            environment={"LEAKCHECK_API_KEY": "test-provider-key", "SHERLOCK_ENABLE_AHMIA": "false"},
        )
        result = agent.investigate(
            {
                "query": "+48 500 600 700",
                "kind": "PHONE",
                "default_region": "PL",
                "purpose": "SELF_AUDIT",
                "include_darkweb": False,
                "consent": True,
            }
        )
        serialized = json.dumps(result)
        self.assertEqual(result["query"]["value"], "+48500600700")
        self.assertEqual(result["summary"]["breach_source_count"], 2)
        self.assertNotIn("must-never-leave-adapter", serialized)
        self.assertNotIn('"password": "secret"', serialized)
        leak_call = next(call for call in http.calls if "leakcheck.io" in call[0])
        self.assertEqual(leak_call[1]["X-API-Key"], "test-provider-key")

    def test_person_search_runs_wikidata_and_keeps_candidates_unconfirmed(self) -> None:
        http = FakeHttp(
            {
                "wikidata.org": (
                    200,
                    {
                        "search": [
                            {"id": "Q42", "label": "Douglas Adams", "description": "pisarz"}
                        ]
                    },
                )
            }
        )
        result = OsintAgent(http=http, environment={}).investigate(
            {
                "query": "Douglas Adams",
                "kind": "PERSON",
                "default_region": "PL",
                "purpose": "JOURNALISM_PUBLIC_INTEREST",
                "include_darkweb": False,
                "consent": True,
            }
        )
        candidate = result["findings"][0]
        self.assertEqual(candidate["category"], "PERSON_CANDIDATE")
        self.assertEqual(candidate["verification"], "CANDIDATE_REQUIRES_CORRELATION")
        self.assertGreaterEqual(len(result["pivots"]), 5)

    def test_ahmia_result_is_index_match_not_claimed_crawl(self) -> None:
        html = """
        <html><body>
          <a href="/search/redirect?redirect_url=http%3A%2F%2Fexampleonion.onion%2F">Indexed result</a>
        </body></html>
        """
        http = FakeHttp({"ahmia.fi": (200, html), "api.github.com": (404, {})})
        result = OsintAgent(http=http, environment={"SHERLOCK_ENABLE_AHMIA": "true"}).investigate(
            {
                "query": "sherlock_osa",
                "kind": "USERNAME",
                "default_region": "PL",
                "purpose": "SELF_AUDIT",
                "include_darkweb": True,
                "consent": True,
            }
        )
        matches = [item for item in result["findings"] if item["category"] == "DARKWEB_INDEX_MATCH"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["verification"], "INDEX_MATCH_NOT_CONTENT_VERIFIED")
        self.assertTrue(result["truth"]["deepweb_index_queried"])
        self.assertFalse(result["truth"]["tor_crawl_performed"])

    def test_completed_engine_context_can_delegate_to_private_tor_worker(self) -> None:
        onion_url = f"http://{'a' * 56}.onion/exposure"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                self.server.payload = json.loads(self.rfile.read(length))  # type: ignore[attr-defined]
                self.server.authorization = self.headers.get("Authorization")  # type: ignore[attr-defined]
                body = json.dumps(
                    {
                        "transport": "TOR_SOCKS5H",
                        "pages_fetched": 1,
                        "matches": [
                            {
                                "url": onion_url,
                                "title": "Exposure record",
                                "content_sha256": "c" * 64,
                                "content_bytes": 1200,
                            }
                        ],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            result = OsintAgent(
                http=FakeHttp({}),
                environment={
                    "SHERLOCK_ENABLE_AHMIA": "false",
                    "OSA_RESEARCH_WORKER_URL": f"http://{host}:{port}",
                    "OSA_RESEARCH_WORKER_TOKEN": "worker-token-that-is-long-enough",
                },
            ).investigate(
                {
                    "query": "target@example.com",
                    "kind": "EMAIL",
                    "purpose": "SELF_AUDIT",
                    "include_darkweb": True,
                    "consent": True,
                },
                execution_context={
                    "engine_state": "COMPLETED",
                    "engine_mission_id": "engine-mission",
                    "engine_execution_id": "engine-execution",
                    "engine_receipt_sha256": "b" * 64,
                },
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertTrue(result["truth"]["tor_crawl_performed"])
        self.assertFalse(result["truth"]["private_worker_required_for_onion_crawl"])
        self.assertEqual(result["summary"]["darkweb_content_match_count"], 1)
        self.assertEqual(server.authorization, "Bearer worker-token-that-is-long-enough")  # type: ignore[attr-defined]
        self.assertEqual(server.payload["mission"]["engine_state"], "COMPLETED")  # type: ignore[attr-defined]

    def test_consent_is_required(self) -> None:
        with self.assertRaises(SherlockError) as raised:
            OsintAgent(http=FakeHttp({}), environment={}).investigate(
                {
                    "query": "test@example.com",
                    "kind": "EMAIL",
                    "purpose": "SELF_AUDIT",
                    "consent": False,
                }
            )
        self.assertEqual(raised.exception.code, "CONSENT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
