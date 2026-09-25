from __future__ import annotations

from typing import Any

from sherlock_osa import ENGINE_PIN, __version__
from sherlock_osa.contracts import require_mapping
from sherlock_osa.demo import PublicDemoService
from sherlock_osa.investigation import InvestigationMode
from sherlock_osa.phone_metadata import PhoneMetadataModule
from sherlock_osa.planner import AdaptiveSourcePlanner
from sherlock_osa.research import BoundedResearchEngine, EventSink, SeedExpansionModule
from sherlock_osa.research_service import ResearchMissionService, search_budget
from sherlock_osa.source_pack import build_source_modules


class VercelSearchService(PublicDemoService):
    """Public Vercel runtime exposing passive Sherlock Full Search only.

    Mission/control-plane methods stay absent because this service inherits the
    intentionally narrow PublicDemoService surface and delegates only the
    passive search methods from ResearchMissionService.
    """

    deployment_mode = "PUBLIC_SEARCH_ONLY"

    def __init__(self) -> None:
        super().__init__()
        self.research_engine = BoundedResearchEngine(
            modules=(
                SeedExpansionModule(),
                PhoneMetadataModule(),
                *build_source_modules("DEEP"),
            ),
            budget=search_budget(InvestigationMode.DEEP),
            planner=AdaptiveSourcePlanner("DEEP"),
        )

    def _build_search_engine(self, mode: InvestigationMode) -> BoundedResearchEngine:
        return ResearchMissionService._build_search_engine(self, mode)

    def research_sources(self) -> dict[str, object]:
        return ResearchMissionService.research_sources(self)

    def full_search(
        self,
        raw: object,
        *,
        event_sink: EventSink | None = None,
    ) -> dict[str, object]:
        return ResearchMissionService.full_search(self, raw, event_sink=event_sink)

    def research(
        self,
        raw: object,
        *,
        event_sink: EventSink | None = None,
    ) -> dict[str, object]:
        data = require_mapping(raw, field_name="research")
        if "query" not in data:
            from sherlock_osa.errors import SherlockError

            raise SherlockError(
                "PUBLIC_RESEARCH_QUERY_REQUIRED",
                "Publiczny Full Research wymaga pola query; mission-based research należy do prywatnego control-plane.",
                status=422,
            )
        search_payload = {
            "query": data.get("query"),
            "kind": data.get("kind", "AUTO"),
            "mode": data.get("mode", "MAX"),
        }
        result = self.full_search(search_payload, event_sink=event_sink)
        return {
            "mission_id": None,
            "research": result,
            "purge": {
                "requested": False,
                "performed": False,
                "scope": "PUBLIC_STATELESS_REQUEST",
            },
            "sources": self.research_sources(),
            "truth": {
                "public_query_research": True,
                "mission_control_plane_exposed": False,
                "persistence": "PER_REQUEST",
            },
        }

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        research = self.research_sources()
        full_pack = bool(research["all_dependencies_available"]) and bool(
            research["all_versions_pinned"]
        )
        return {
            "service": "sherlock-osa",
            "version": __version__,
            "status": "OK",
            "deployment_mode": self.deployment_mode,
            "execution_backing": (
                "SHERLOCK_TRUTH_ENGINE_V4"
                if full_pack
                else "PARTIAL_SHERLOCK_TRUTH_ENGINE_V4"
            ),
            "engine": {
                "reachable": "NOT_CONNECTED_IN_SEARCH_ONLY_RUNTIME",
                "commit_sha": ENGINE_PIN,
                "live_engine_required_for_new_missions": True,
                "probe_engine_ignored": bool(probe_engine),
            },
            "evidence": {
                "persistence": "PER_REQUEST",
                "verification": "SEARCH_RESULT_PROVENANCE",
            },
            "research": research,
            "search": {
                "supported": [
                    "AUTO",
                    "EMAIL",
                    "PHONE",
                    "USERNAME",
                    "PERSON",
                    "DOMAIN",
                    "URL",
                ],
                "default_mode": "MAX",
                "modes": ["QUICK", "DEEP", "MAX"],
                "truth_engine": "V4",
                "full_search_attached": True,
                "full_research_attached": True,
            },
            "truth": {
                "live_engine_called": False,
                "network_effect_possible": True,
                "shell_effect_possible": False,
                "mission_control_plane_exposed": False,
            },
        }
