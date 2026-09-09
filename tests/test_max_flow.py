from __future__ import annotations

import json
import threading
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from sherlock_osa.api import create_server
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.policy import CapabilityBroker
from sherlock_osa.research import (
    BoundedResearchEngine,
    IdentifierKind,
    ModuleContext,
    ModuleResult,
    ResearchBudget,
    ResearchIdentifier,
)
from sherlock_osa.research_service import ResearchMissionService
from sherlock_osa.storage import MissionStore
from sherlock_osa.worker import SimulationWorker
from tests.support import FakeEngine, settings_for


class StaticUsernameModule:
    name = "fixture.username"
    family = "FIXTURE_IDENTITY"
    required_capability = "osint.username.lookup"
    supported_kinds = frozenset({IdentifierKind.USERNAME})

    async def lookup(
        self,
        identifier: ResearchIdentifier,
        context: ModuleContext,
    ) -> ModuleResult:
        return ModuleResult(
            fields={
                "provider": "fixture",
                "found": True,
                "profile": {
                    "username": identifier.value,
                    "profile_url": "https://example.test/" + identifier.value,
                    "created_at": "2024-01-02T03:04:05Z",
                },
            },
            confidence=0.95,
            source_urls=("https://example.test/" + identifier.value,),
        )


def build_service(root: Path) -> ResearchMissionService:
    settings = settings_for(root)
    return ResearchMissionService(
        settings=settings,
        store=MissionStore(settings.database_path),
        ledger=EvidenceLedger(settings.evidence_path),
        engine=FakeEngine(),
        broker=CapabilityBroker(settings.mission_signing_secret),
        worker=SimulationWorker(),
    )


def fixture_engine() -> BoundedResearchEngine:
    return BoundedResearchEngine(
        modules=(StaticUsernameModule(),),
        budget=ResearchBudget(
            hard_timeout_seconds=5.0,
            per_module_timeout_seconds=2.0,
            max_depth=1,
            max_identifiers=16,
            max_evidence=32,
            max_module_invocations=32,
            max_parallel=4,
            no_progress_rounds=1,
        ),
    )


class MaxFullSearchFlowTests(unittest.TestCase):
    def test_full_search_builds_human_report_graph_and_timeline(self) -> None:
        with TemporaryDirectory() as tmp:
            service = build_service(Path(tmp))
            with patch.object(service, "_build_search_engine", return_value=fixture_engine()):
                result = service.full_search(
                    {"kind": "USERNAME", "mode": "MAX", "query": "HazEOskA"}
                )

        self.assertEqual(result["mode"], "MAX")
        self.assertIn("headline", result["report"])
        self.assertGreaterEqual(result["report"]["hard_links"], 1)
        detective = result["detective"]
        self.assertGreaterEqual(detective["graph"]["node_count"], 2)
        self.assertGreaterEqual(len(detective["timeline"]), 1)
        self.assertEqual(detective["source_runs"][0]["status"], "COMPLETED")

    def test_stream_endpoint_emits_live_events_and_case_result(self) -> None:
        with TemporaryDirectory() as tmp:
            service = build_service(Path(tmp))
            server = create_server(service, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            url = f"http://{host}:{port}/api/v1/search/stream"
            payload = json.dumps(
                {"kind": "USERNAME", "mode": "MAX", "query": "HazEOskA"}
            ).encode("utf-8")
            request = urllib.request.Request(
                url,
                method="POST",
                data=payload,
                headers={
                    "Authorization": f"Bearer {service.settings.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
            )
            try:
                with patch.object(service, "_build_search_engine", return_value=fixture_engine()):
                    with urllib.request.urlopen(request, timeout=5) as response:
                        self.assertIn("text/event-stream", response.headers["Content-Type"])
                        body = response.read().decode("utf-8")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertIn("event: search_started", body)
        self.assertIn("event: source_started", body)
        self.assertIn("event: source_completed", body)
        self.assertIn("event: case_report_ready", body)
        self.assertIn("event: case_result", body)


if __name__ == "__main__":
    unittest.main()
