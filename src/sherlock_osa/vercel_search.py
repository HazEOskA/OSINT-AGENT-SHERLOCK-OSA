from __future__ import annotations

from sherlock_osa import __version__
from sherlock_osa.demo import PublicDemoService
from sherlock_osa.investigation import InvestigationMode
from sherlock_osa.phone_metadata import PhoneMetadataModule
from sherlock_osa.planner import AdaptiveSourcePlanner
from sherlock_osa.research import BoundedResearchEngine, EventSink, SeedExpansionModule
from sherlock_osa.research_service import ResearchMissionService, search_budget
from sherlock_osa.source_pack import build_source_modules


class VercelSearchService(PublicDemoService):
    """Vercel adapter for the known-good MAX + NSFW V1 research runtime."""

    deployment_mode = "PUBLIC_MAX_NSFW_V1"

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

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        research = self.research_sources()
        return {
            "service": "sherlock-osa",
            "version": __version__,
            "status": "OK",
            "deployment_mode": self.deployment_mode,
            "execution_backing": "SHERLOCK_MAX_NSFW_V1",
            "engine": {
                "kind": "SHERLOCK_LOCAL",
                "external_control_plane": False,
                "probe_ignored": bool(probe_engine),
            },
            "research": research,
            "search": {
                "default_mode": "MAX",
                "modes": ["QUICK", "DEEP", "MAX"],
                "full_search_attached": True,
                "social_graph": True,
                "nsfw_intelligence": True,
            },
            "truth": {
                "operator_auth_required": False,
                "postcrossing_blocked": True,
                "same_username_is_same_person": False,
            },
        }


__all__ = ["VercelSearchService"]
