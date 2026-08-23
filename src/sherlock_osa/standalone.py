from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from importlib.resources import files

from sherlock_osa import __version__
from sherlock_osa.contracts import MissionMode, Target
from sherlock_osa.errors import SherlockError
from sherlock_osa.policy import validate_target_for_mode
from sherlock_osa.research import (
    BoundedResearchEngine,
    ResearchBudget,
    ResearchIdentifier,
    SeedExpansionModule,
)
from sherlock_osa.source_pack import build_source_modules, source_health


RESEARCH_CAPABILITIES = (
    "osint.research.run",
    "osint.correlation.expand",
    "osint.email.lookup",
    "osint.username.lookup",
    "osint.url.trace",
    "osint.domain.passive",
    "intel.indicator.enrich",
)


@dataclass(frozen=True, slots=True)
class StandaloneSettings:
    """Small HTTP settings surface used by the shared handler."""

    api_key: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    max_body_bytes: int = 65_536


class StandaloneResearchService:
    """Sherlock's own bounded OSINT engine with no external control plane."""

    deployment_mode = "STANDALONE_RESEARCH"

    def __init__(self) -> None:
        self.settings = StandaloneSettings()
        self.research_engine = BoundedResearchEngine(
            modules=(SeedExpansionModule(), *build_source_modules()),
            budget=ResearchBudget(
                hard_timeout_seconds=55.0,
                per_module_timeout_seconds=25.0,
                max_depth=3,
                max_identifiers=128,
                max_evidence=500,
                max_module_invocations=500,
                max_parallel=16,
                no_progress_rounds=2,
            ),
        )

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        sources = source_health()
        return {
            "service": "sherlock-osa",
            "version": __version__,
            "status": "OK",
            "deployment_mode": self.deployment_mode,
            "execution_backing": "LOCAL_BOUNDED_PASSIVE_RESEARCH",
            "engine": {
                "kind": "SHERLOCK_LOCAL",
                "external_control_plane": False,
                "probe_ignored": bool(probe_engine),
            },
            "research": {
                **sources,
                "hard_timeout_seconds": self.research_engine.budget.hard_timeout_seconds,
                "max_depth": self.research_engine.budget.max_depth,
                "max_identifiers": self.research_engine.budget.max_identifiers,
            },
        }

    def reference_repositories(self) -> dict[str, object]:
        resource = files("sherlock_osa").joinpath("reference_repos.json")
        return json.loads(resource.read_text(encoding="utf-8"))

    @staticmethod
    def _person_targets(value: str) -> list[Target]:
        normalized = value.strip().casefold()
        normalized = "".join(
            char for char in normalized
            if char.isascii() and (char.isalnum() or char in " -_.'")
        )
        parts = [part for part in re.split(r"[\s_.\-']+", normalized) if part]
        if len(parts) < 2:
            raise SherlockError(
                "PERSON_NAME_REQUIRED",
                "Dla IMIĘ + NAZWISKO podaj co najmniej dwa człony.",
            )
        first, last = parts[0], parts[-1]
        values = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{last}_{first}",
        ]
        seen: set[str] = set()
        targets: list[Target] = []
        for candidate in values:
            if candidate in seen:
                continue
            seen.add(candidate)
            target = Target.from_dict({"kind": "USERNAME", "value": candidate, "ports": []})
            validate_target_for_mode(MissionMode.RESEARCH_PASSIVE, target)
            targets.append(target)
        return targets

    def search(self, raw: object) -> dict[str, object]:
        if not isinstance(raw, dict):
            raise SherlockError("INVALID_PAYLOAD", "Search body musi być obiektem JSON.")
        kind = str(raw.get("kind", "")).strip().upper()
        query = str(raw.get("query", "")).strip()
        if not query:
            raise SherlockError("SEARCH_QUERY_REQUIRED", "Wpisz wartość do wyszukania.")

        if kind == "PERSON":
            targets = self._person_targets(query)
        elif kind in {"EMAIL", "USERNAME", "URL", "DOMAIN"}:
            target = Target.from_dict({"kind": kind, "value": query, "ports": []})
            validate_target_for_mode(MissionMode.RESEARCH_PASSIVE, target)
            targets = [target]
        else:
            raise SherlockError(
                "INVALID_SEARCH_KIND",
                "Obsługiwane typy: EMAIL, USERNAME, PERSON, URL, DOMAIN.",
            )

        seeds = tuple(ResearchIdentifier.from_target(target) for target in targets)
        result = self.research_engine.run(
            seeds,
            allowed_capabilities=RESEARCH_CAPABILITIES,
        )
        return {
            "deployment_mode": self.deployment_mode,
            "query": {"kind": kind, "value": query, "seed_count": len(seeds)},
            "research": result.to_dict(),
            "sources": source_health(),
            "truth": {
                "external_execution_force_used": False,
                "external_engine_called": False,
                "raw_evidence_persisted": False,
            },
        }
