from __future__ import annotations

import re
import unicodedata
from typing import Any, Mapping

from sherlock_osa.contracts import (
    CapabilityRequest,
    DecisionEffect,
    MissionMode,
    require_mapping,
    require_string,
)
from sherlock_osa.emailosint import EmailOsintClient
from sherlock_osa.emailosint_module import EmailOsintResearchModule
from sherlock_osa.errors import SherlockError
from sherlock_osa.investigation import DetectiveInvestigator, InvestigationMode
from sherlock_osa.phone_metadata import PhoneMetadataModule
from sherlock_osa.planner import AdaptiveSourcePlanner
from sherlock_osa.reporting import build_human_report
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
from sherlock_osa.social_graph import build_social_graph
from sherlock_osa.social_mesh import SocialMeshUsernameModule
from sherlock_osa.source_pack import IsolatedSourceModule, build_source_modules, source_health


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


def normalize_phone(value: str) -> str:
    raw = value.strip()
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    if not raw.startswith("+"):
        raise SherlockError(
            "PHONE_E164_REQUIRED",
            "Dla numeru telefonu użyj formatu międzynarodowego, np. +31612345678.",
            status=422,
        )
    digits = re.sub(r"\D", "", raw)
    if not 8 <= len(digits) <= 15 or digits.startswith("0"):
        raise SherlockError(
            "INVALID_PHONE",
            "Niepoprawny numer telefonu.",
            status=422,
        )
    return "+" + digits


def detect_search_kind(value: str) -> str:
    candidate = value.strip()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
        return "EMAIL"
    if re.fullmatch(r"(?:\+|00)[0-9][0-9\s().-]{6,24}", candidate):
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


def search_budget(mode: InvestigationMode) -> ResearchBudget:
    if mode is InvestigationMode.QUICK:
        return ResearchBudget(
            hard_timeout_seconds=45.0,
            per_module_timeout_seconds=12.0,
            max_depth=2,
            max_identifiers=64,
            max_evidence=300,
            max_module_invocations=300,
            max_parallel=16,
            no_progress_rounds=1,
        )
    if mode is InvestigationMode.DEEP:
        return ResearchBudget(
            hard_timeout_seconds=180.0,
            per_module_timeout_seconds=40.0,
            max_depth=4,
            max_identifiers=256,
            max_evidence=1200,
            max_module_invocations=1800,
            max_parallel=24,
            no_progress_rounds=2,
        )
    return ResearchBudget(
        hard_timeout_seconds=300.0,
        per_module_timeout_seconds=55.0,
        max_depth=6,
        max_identifiers=768,
        max_evidence=3000,
        max_module_invocations=5000,
        max_parallel=32,
        no_progress_rounds=3,
    )


class ResearchMissionService(MissionService):
    """MissionService extension with bounded passive investigation."""

    def __init__(
        self,
        *args: Any,
        research_engine: BoundedResearchEngine | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.research_engine = research_engine or BoundedResearchEngine(
            modules=(
                SeedExpansionModule(),
                PhoneMetadataModule(),
                *build_source_modules("DEEP"),
            ),
            budget=search_budget(InvestigationMode.DEEP),
            planner=AdaptiveSourcePlanner("DEEP"),
        )

    def _build_search_engine(self, mode: InvestigationMode) -> BoundedResearchEngine:
        modules = (
            SeedExpansionModule(),
            PhoneMetadataModule(),
            EmailOsintResearchModule(EmailOsintClient.from_settings(self.settings)),
            *build_source_modules(mode.name),
        )
        return BoundedResearchEngine(
            modules=modules,
            budget=search_budget(mode),
            planner=AdaptiveSourcePlanner(mode.value.upper()),
        )

    def health(self, *, probe_engine: bool = False) -> dict[str, object]:
        base = super().health(probe_engine=probe_engine)
        research = self.research_sources()
        full_pack = bool(research["all_dependencies_available"]) and bool(
            research["all_versions_pinned"]
        )
        hibp = next(
            (
                source
                for source in research.get("sources", [])
                if isinstance(source, Mapping) and source.get("name") == "hibp.account"
            ),
            {},
        )
        phone_exposure_ready = bool(hibp.get("ready"))
        return {
            **base,
            "execution_backing": (
                "SIMULATION_PLUS_SOCIAL_MESH_ULTRA_V3"
                if full_pack
                else "SIMULATION_PLUS_PARTIAL_SOCIAL_MESH_ULTRA_V3"
            ),
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
                "phone": (
                    "OFFLINE_METADATA_PLUS_HIBP_EXPOSURE"
                    if phone_exposure_ready
                    else "OFFLINE_METADATA; HIBP_REQUIRES_API_KEY"
                ),
                "default_mode": "MAX",
                "modes": ["QUICK", "DEEP", "MAX"],
                "presentation": "HUMAN_REPORT_WITH_SOCIAL_GRAPH_AND_SOURCE_LINKS",
                "social_mesh": "V3_RUNTIME_PINNED_DATASETS",
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
            "local_sources": [
                {
                    "name": "phone.metadata",
                    "family": "PHONE_METADATA",
                    "package": "phonenumbers",
                    "expected_version": "9.0.38",
                    "network_effect": False,
                    "owner_identification": False,
                    "precise_location": False,
                }
            ],
            "search_modes": {
                mode.name: {
                    "hard_timeout_seconds": search_budget(mode).hard_timeout_seconds,
                    "per_module_timeout_seconds": search_budget(mode).per_module_timeout_seconds,
                    "max_depth": search_budget(mode).max_depth,
                    "max_identifiers": search_budget(mode).max_identifiers,
                    "max_evidence": search_budget(mode).max_evidence,
                    "max_module_invocations": search_budget(mode).max_module_invocations,
                    "max_parallel": search_budget(mode).max_parallel,
                    "planner": AdaptiveSourcePlanner(mode.value.upper()).describe(),
                }
                for mode in InvestigationMode
            },
            "truth": (
                "DEPENDENCIES_VERIFIED; live source reachability is evaluated per lookup."
                if health["all_dependencies_available"] and health["all_versions_pinned"]
                else "SOURCE_PACK_DEGRADED; one or more pinned dependencies are unavailable or drifted."
            ),
        }

    def full_search(
        self,
        raw: object,
        *,
        event_sink: EventSink | None = None,
    ) -> dict[str, object]:
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
                "Obsługiwane typy: AUTO, EMAIL, PHONE, USERNAME, PERSON, DOMAIN, URL.",
                status=422,
            )

        raw_mode = require_string(
            data.get("mode", "MAX"),
            field_name="mode",
            maximum=10,
        ).upper()
        try:
            mode = InvestigationMode(raw_mode.casefold())
        except ValueError as exc:
            raise SherlockError(
                "INVALID_SEARCH_MODE",
                "Tryb musi być QUICK, DEEP albo MAX.",
                status=422,
            ) from exc

        kind = detect_search_kind(query) if requested_kind == "AUTO" else requested_kind

        if kind == "PERSON":
            candidates = person_username_candidates(query)
            candidate_limit = {
                InvestigationMode.QUICK: 4,
                InvestigationMode.DEEP: 8,
                InvestigationMode.MAX: len(candidates),
            }[mode]
            derived_queries = candidates[:candidate_limit]
            seeds = tuple(
                ResearchIdentifier(
                    IdentifierKind.USERNAME,
                    candidate,
                    depth=0 if index == 0 else 2,
                )
                for index, candidate in enumerate(derived_queries)
            )
        elif kind == "PHONE":
            normalized_phone = normalize_phone(query)
            derived_queries = ()
            seeds = (ResearchIdentifier(IdentifierKind.PHONE, normalized_phone),)
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

        engine = self._build_search_engine(mode)
        allowed_capabilities = sorted(
            {
                module.required_capability
                for module in engine.modules
                if getattr(module, "required_capability", "")
            }
        )
        investigator = DetectiveInvestigator(engine)

        if event_sink:
            event_sink(
                "search_started",
                {
                    "kind": kind,
                    "mode": mode.name,
                    "seed_count": len(seeds),
                    "social_mesh": True,
                },
            )

        investigation = investigator.investigate(
            seeds,
            allowed_capabilities=allowed_capabilities,
            mode=mode,
            event_sink=event_sink,
        )

        emailosint = investigation.sensor_payloads.get("emailosint")
        emailosint_error: dict[str, object] | None = None
        for run in investigation.source_runs:
            if run.source == "emailosint.email" and run.status in {"ERROR", "TIMEOUT"}:
                emailosint_error = {
                    "code": "EMAILOSINT_SOURCE_ERROR",
                    "message": (
                        "EmailOSINT nie odpowiedział w tym przebiegu. "
                        "Pozostałe źródła zostały przetworzone niezależnie."
                    ),
                }
                break

        social_batches: list[dict[str, object]] = []
        source_records: list[dict[str, object]] = []
        phone_results: list[dict[str, object]] = []
        for module in engine.modules:
            if isinstance(module, SocialMeshUsernameModule):
                social_batches.extend(module.batches)
            elif isinstance(module, PhoneMetadataModule):
                phone_results.extend(module.results)
            elif isinstance(module, IsolatedSourceModule):
                source_records.extend(module.results)

        social_graph = build_social_graph(
            emailosint=emailosint,
            sensor_payloads={
                "social_mesh": {"batches": social_batches},
                "source_records": source_records,
            },
        )

        sources = self.research_sources()
        hibp = next(
            (
                source
                for source in sources.get("sources", [])
                if isinstance(source, Mapping) and source.get("name") == "hibp.account"
            ),
            {},
        )

        report = build_human_report(
            query=query,
            kind=kind,
            investigation=investigation,
        )

        result = {
            "query": {
                "requested_kind": requested_kind,
                "kind": kind,
                "value": query,
                "derived_queries": list(derived_queries),
            },
            "mode": mode.name,
            "report": report,
            "emailosint": emailosint,
            "emailosint_error": emailosint_error,
            "social_graph": social_graph,
            "social_mesh": {
                "version": "v3.1",
                "batches": social_batches,
                "batch_count": len(social_batches),
                "direct_source_record_count": len(source_records),
                "datasets": sources.get("social_mesh", {}).get("datasets", [])
                if isinstance(sources.get("social_mesh"), Mapping)
                else [],
            },
            "phone_intelligence": {
                "metadata": phone_results,
                "exposure_source": (
                    "HIBP_ACCOUNT" if bool(hibp.get("ready")) else "UNAVAILABLE_NO_HIBP_KEY"
                ),
                "owner_identified": False,
                "precise_location_available": False,
            }
            if kind == "PHONE"
            else None,
            "detective": investigation.to_dict(),
            "sources": sources,
            "truth": {
                "mode": "BOUNDED_PASSIVE",
                "search_mode": mode.name,
                "operator_auth_required": True,
                "fabricated_results": False,
                "phone_backing": bool(phone_results) or bool(hibp.get("ready")),
                "phone_exposure_source": (
                    "HIBP_ACCOUNT" if bool(hibp.get("ready")) else "UNAVAILABLE_NO_HIBP_KEY"
                ),
                "phone_metadata_source": "LIBPHONENUMBER_OFFLINE",
                "social_mesh": "RUNTIME_PINNED_WMN_PLUS_SHERLOCK",
                "social_graph_direct_sources": ["HOLEHE", "MAIGRET", "GITHUB", "GITLAB", "GRAVATAR"],
                "social_probe_post_requests": False,
                "social_probe_authenticated_sessions": False,
                "social_probe_proxy_rotation": False,
                "social_probe_captcha_bypass": False,
                "hard_timeout_seconds": engine.budget.hard_timeout_seconds,
            },
        }

        if event_sink:
            event_sink(
                "social_graph_ready",
                {
                    "signals_total": social_graph["summary"]["signals_total"],
                    "found_total": social_graph["summary"]["found_total"],
                    "google_found": social_graph["summary"]["google_found"],
                    "social_found": social_graph["summary"]["social_found"],
                    "dating_found": social_graph["summary"]["dating_found"],
                },
            )
            event_sink(
                "case_report_ready",
                {
                    "headline": report["headline"],
                    "summary": report["summary"],
                    "mode": mode.name,
                },
            )
        return result

    def _prepare_research(
        self,
        raw: object,
    ) -> tuple[object, tuple[ResearchIdentifier, ...], bool]:
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

    def research(
        self,
        raw: object,
        *,
        event_sink: EventSink | None = None,
    ) -> dict[str, object]:
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
                "seed_set_sha256": sha256_json(
                    sorted(identifier.key for identifier in seeds)
                ),
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
