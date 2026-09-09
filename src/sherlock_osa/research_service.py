from __future__ import annotations

import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Mapping

from sherlock_osa.contracts import (
    CapabilityRequest,
    DecisionEffect,
    MissionMode,
    require_mapping,
    require_string,
)
from sherlock_osa.emailosint import EmailOsintClient
from sherlock_osa.errors import SherlockError
from sherlock_osa.investigation import DetectiveInvestigator, InvestigationMode
from sherlock_osa.research import (
    BoundedResearchEngine,
    EventSink,
    IdentifierKind,
    ResearchBudget,
    ResearchIdentifier,
    SeedExpansionModule,
)
from sherlock_osa.service import MissionService
from sherlock_osa.signing import sha256_json, verify_scope
from sherlock_osa.source_pack import build_source_modules, source_health


SEARCH_KINDS = frozenset({"AUTO", "EMAIL", "USERNAME", "PERSON", "DOMAIN", "URL", "PHONE"})


def _fold_ascii(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).casefold()


def person_username_candidates(value: str) -> tuple[str, ...]:
    words = re.findall(r"[a-z0-9]+", _fold_ascii(value))
    if len(words) < 2:
        raise SherlockError(
            "PERSON_NAME_REQUIRED",
            "Dla wyszukiwania osoby podaj co najmniej imię i nazwisko.",
            status=422,
        )
    first, last = words[0], words[-1]
    raw = (
        "".join(words),
        ".".join(words),
        "_".join(words),
        "-".join(words),
        first + last,
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        first[:1] + last,
        f"{first[:1]}.{last}",
        last + first,
        f"{last}.{first}",
    )
    unique: list[str] = []
    for candidate in raw:
        if candidate and len(candidate) <= 64 and candidate not in unique:
            unique.append(candidate)
    return tuple(unique)


def detect_search_kind(value: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
        return "EMAIL"
    if re.fullmatch(r"\+?[0-9][0-9\s().-]{6,24}", candidate):
        return "PHONE"
    if candidate.startswith(("http://", "https://")):
        return "URL"
    if re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
        candidate,
    ):
        return "DOMAIN"
    if len(candidate.split()) >= 2:
        return "PERSON"
    return "USERNAME"


class ResearchMissionService(MissionService):
    """MissionService extension: passive research stays bounded and evidence-first."""

    def __init__(self, *args: Any, research_engine: BoundedResearchEngine | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.research_engine = research_engine or BoundedResearchEngine(
            modules=(SeedExpansionModule(), *build_source_modules()),
            budget=ResearchBudget(
                hard_timeout_seconds=300.0,
                per_module_timeout_seconds=60.0,
                max_depth=4,
                max_identifiers=256,
                max_evidence=1000,
                max_module_invocations=1200,
                max_parallel=24,
                no_progress_rounds=2,
            ),
        )

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        base = super().health(probe_engine=probe_engine)
        research = self.research_sources()
        full_pack = bool(research["all_dependencies_available"]) and bool(research["all_versions_pinned"])
        return {
            **base,
            "execution_backing": (
                "SIMULATION_PLUS_FULL_BOUNDED_PASSIVE_RESEARCH"
                if full_pack
                else "SIMULATION_PLUS_PARTIAL_BOUNDED_PASSIVE_RESEARCH"
            ),
            "research": research,
            "search": {
                "supported": ["AUTO", "EMAIL", "USERNAME", "PERSON", "DOMAIN", "URL"],
                "phone": "UNBACKED",
                "presentation": "HUMAN_REPORT_WITH_SOURCE_LINKS",
            },
        }

    def research_sources(self) -> dict[str, object]:
        health = source_health()
        return {
            **health,
            "engine": {
                "hard_timeout_seconds": self.research_engine.budget.hard_timeout_seconds,
                "per_module_timeout_seconds": self.research_engine.budget.per_module_timeout_seconds,
                "max_depth": self.research_engine.budget.max_depth,
                "max_identifiers": self.research_engine.budget.max_identifiers,
            },
            "truth": (
                "DEPENDENCIES_VERIFIED; live source reachability is evaluated per lookup."
                if health["all_dependencies_available"] and health["all_versions_pinned"]
                else "SOURCE_PACK_DEGRADED; one or more pinned dependencies are unavailable or drifted."
            ),
        }

    def full_search(self, raw: object) -> dict[str, object]:
        data = require_mapping(raw, field_name="search")
        query = require_string(data.get("query"), field_name="query", maximum=2048)
        requested_kind = require_string(
            data.get("kind", "AUTO"),
            field_name="kind",
            maximum=20,
        ).upper()
        if requested_kind not in SEARCH_KINDS:
            raise SherlockError(
                "INVALID_SEARCH_KIND",
                "Obsługiwane typy: AUTO, EMAIL, USERNAME, PERSON, DOMAIN, URL.",
                status=422,
            )

        kind = detect_search_kind(query) if requested_kind == "AUTO" else requested_kind
        if kind == "PHONE":
            raise SherlockError(
                "PHONE_SOURCE_UNAVAILABLE",
                "Numer telefonu został rozpoznany, ale Sherlock nie ma jeszcze zweryfikowanego źródła PHONE. Nie zwracam udawanego wyniku.",
                status=422,
            )

        if kind == "PERSON":
            derived_queries = person_username_candidates(query)
            seeds = tuple(
                ResearchIdentifier(IdentifierKind.USERNAME, candidate)
                for candidate in derived_queries
            )
        else:
            derived_queries = ()
            kind_map = {
                "EMAIL": IdentifierKind.EMAIL,
                "USERNAME": IdentifierKind.USERNAME,
                "DOMAIN": IdentifierKind.DOMAIN,
                "URL": IdentifierKind.URL,
            }
            try:
                identifier_kind = kind_map[kind]
            except KeyError as exc:
                raise SherlockError(
                    "INVALID_SEARCH_KIND",
                    "Nieobsługiwany typ wyszukiwania.",
                    status=422,
                ) from exc
            seeds = (ResearchIdentifier(identifier_kind, query),)

        allowed_capabilities = sorted(
            {
                module.required_capability
                for module in self.research_engine.modules
                if getattr(module, "required_capability", "")
            }
        )
        investigator = DetectiveInvestigator(self.research_engine)

        def run_detective():
            return investigator.investigate(
                seeds,
                allowed_capabilities=allowed_capabilities,
                mode=InvestigationMode.DEEP,
            )

        email_result: dict[str, object] | None = None
        email_error: dict[str, object] | None = None

        with ThreadPoolExecutor(max_workers=2) as pool:
            detective_future = pool.submit(run_detective)
            email_future = None
            if kind == "EMAIL":
                client = EmailOsintClient.from_settings(self.settings)
                email_future = pool.submit(client.lookup, {"email": query})

            detective = detective_future.result()

            if email_future is not None:
                try:
                    email_result = email_future.result()
                except SherlockError as exc:
                    email_error = exc.as_dict()["error"]

        return {
            "query": {
                "requested_kind": requested_kind,
                "kind": kind,
                "value": query,
                "derived_queries": list(derived_queries),
            },
            "emailosint": email_result,
            "emailosint_error": email_error,
            "detective": detective.to_dict(),
            "sources": self.research_sources(),
            "truth": {
                "mode": "BOUNDED_PASSIVE",
                "operator_auth_required": True,
                "fabricated_results": False,
                "phone_backing": False,
            },
        }

    def _prepare_research(self, raw: object) -> tuple[object, tuple[ResearchIdentifier, ...], bool]:
        data = require_mapping(raw, field_name="research")
        mission_id = require_string(data.get("mission_id"), field_name="mission_id", maximum=80)
        purge_after = data.get("purge_after", True)
        if not isinstance(purge_after, bool):
            raise SherlockError("INVALID_PAYLOAD", "purge_after musi być boolean.")

        scope, _ = self.store.get_mission(mission_id)
        if not verify_scope(scope, self.settings.mission_signing_secret):
            raise SherlockError("SIGNATURE_INVALID", "Podpis research scope jest niepoprawny.", status=409)
        if scope.mode is not MissionMode.RESEARCH_PASSIVE:
            raise SherlockError(
                "RESEARCH_MODE_REQUIRED",
                "Bounded research engine działa wyłącznie w RESEARCH_PASSIVE.",
                status=409,
            )
        if "osint.research.run" not in scope.allowed_capabilities:
            raise SherlockError(
                "RESEARCH_CAPABILITY_REQUIRED",
                "Scope nie zawiera osint.research.run.",
                status=409,
            )

        seeds: list[ResearchIdentifier] = []
        for target in scope.targets:
            request = CapabilityRequest(
                mission_id=scope.mission_id,
                capability="osint.research.run",
                target=target,
                route="research-passive",
                request_id="bounded-research-gate",
            )
            decision = self.broker.evaluate(scope, request)
            if decision.effect is not DecisionEffect.ALLOW:
                raise SherlockError(
                    decision.reason_code,
                    f"Research gate DENY: {decision.reason}",
                    status=409,
                )
            seeds.append(ResearchIdentifier.from_target(target))

        return scope, tuple(seeds), purge_after

    def research(self, raw: object, *, event_sink: EventSink | None = None) -> dict[str, object]:
        scope, seeds, purge_after = self._prepare_research(raw)
        result = self.research_engine.run(
            seeds,
            allowed_capabilities=scope.allowed_capabilities,
            event_sink=event_sink,
        )
        result_dict = result.to_dict()

        self.ledger.append(
            "RESEARCH_COMPLETED",
            {
                "mission_id": scope.mission_id,
                "research_id": result.research_id,
                "status": result.status,
                "stop_reason": result.stop_reason,
                "duration_ms": result.duration_ms,
                "identifiers_seen": result.identifiers_seen,
                "module_invocations": result.module_invocations,
                "evidence_count": len(result.evidence),
                "tainted_evidence": result.tainted_evidence,
                "result_sha256": result.result_sha256,
                "seed_set_sha256": sha256_json(sorted(identifier.key for identifier in seeds)),
            },
        )

        purge: Mapping[str, object] = {
            "requested": purge_after,
            "performed": False,
            "scope": "LOCAL_SQLITE_ONLY",
        }
        if purge_after:
            deleted = self.store.purge_mission(scope.mission_id)
            purge = {
                "requested": True,
                "performed": True,
                "scope": "LOCAL_SQLITE_ONLY",
                **deleted,
            }
            self.ledger.append(
                "RESEARCH_LOCAL_DB_PURGED",
                {
                    "mission_id": scope.mission_id,
                    "research_id": result.research_id,
                    "mission_deleted": bool(deleted["mission_deleted"]),
                    "decisions_deleted": int(deleted["decisions_deleted"]),
                },
            )
            if event_sink:
                event_sink("purge_done", dict(purge))

        result_dict["retention"] = {
            "mode": "EPHEMERAL",
            "raw_module_evidence_persisted": False,
            "local_database_purged": bool(purge.get("performed")),
            "external_deletion_performed": False,
        }
        return {
            "mission_id": scope.mission_id,
            "research": result_dict,
            "purge": dict(purge),
            "sources": self.research_sources(),
        }
