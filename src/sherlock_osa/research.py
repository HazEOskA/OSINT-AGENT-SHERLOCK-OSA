from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit
from uuid import uuid4

from sherlock_osa.contracts import Target, TargetKind, utc_iso
from sherlock_osa.errors import SherlockError


class IdentifierKind(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    USERNAME = "USERNAME"
    URL = "URL"
    DOMAIN = "DOMAIN"
    INDICATOR = "INDICATOR"


class TrustState(StrEnum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"


@dataclass(frozen=True, slots=True)
class ResearchIdentifier:
    kind: IdentifierKind
    value: str
    depth: int = 0
    parent_evidence_id: str | None = None

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.value.casefold()}"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "depth": self.depth,
            "parent_evidence_id": self.parent_evidence_id,
        }

    @classmethod
    def from_target(cls, target: Target) -> "ResearchIdentifier":
        mapping = {
            TargetKind.EMAIL: IdentifierKind.EMAIL,
            TargetKind.USERNAME: IdentifierKind.USERNAME,
            TargetKind.URL: IdentifierKind.URL,
            TargetKind.DOMAIN: IdentifierKind.DOMAIN,
            TargetKind.INDICATOR: IdentifierKind.INDICATOR,
        }
        try:
            kind = mapping[target.kind]
        except KeyError as exc:
            raise SherlockError(
                "UNSUPPORTED_RESEARCH_TARGET",
                f"Target {target.kind.value} nie jest obsługiwany przez research engine.",
            ) from exc
        return cls(kind=kind, value=target.value)


@dataclass(frozen=True, slots=True)
class ResearchBudget:
    hard_timeout_seconds: float = 300.0
    per_module_timeout_seconds: float = 20.0
    max_depth: int = 4
    max_identifiers: int = 256
    max_evidence: int = 1000
    max_module_invocations: int = 1200
    max_parallel: int = 24
    no_progress_rounds: int = 2

    def __post_init__(self) -> None:
        if not 0 < self.hard_timeout_seconds <= 300:
            raise ValueError("hard_timeout_seconds must be in (0, 300]")
        if not 0 < self.per_module_timeout_seconds <= self.hard_timeout_seconds:
            raise ValueError("per_module_timeout_seconds must fit hard timeout")
        if not 0 <= self.max_depth <= 8:
            raise ValueError("max_depth must be in 0..8")
        if not 1 <= self.max_identifiers <= 4096:
            raise ValueError("max_identifiers out of bounds")
        if not 1 <= self.max_evidence <= 10000:
            raise ValueError("max_evidence out of bounds")
        if not 1 <= self.max_module_invocations <= 20000:
            raise ValueError("max_module_invocations out of bounds")
        if not 1 <= self.max_parallel <= 128:
            raise ValueError("max_parallel out of bounds")


@dataclass(frozen=True, slots=True)
class ModuleContext:
    deadline_monotonic: float
    allowed_capabilities: frozenset[str]

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline_monotonic - time.monotonic())


@dataclass(frozen=True, slots=True)
class ModuleResult:
    fields: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    pivots: tuple[ResearchIdentifier, ...] = ()
    source_urls: tuple[str, ...] = ()


class ResearchModule(Protocol):
    name: str
    supported_kinds: frozenset[IdentifierKind]
    required_capability: str

    async def lookup(self, identifier: ResearchIdentifier, context: ModuleContext) -> ModuleResult: ...


EventSink = Callable[[str, Mapping[str, Any]], None]


@dataclass(frozen=True, slots=True)
class ResearchEvidence:
    evidence_id: str
    module: str
    identifier: ResearchIdentifier
    fields: Mapping[str, Any]
    confidence: float
    source_urls: tuple[str, ...]
    trust: TrustState
    poison_reasons: tuple[str, ...]
    collected_at: str
    evidence_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "module": self.module,
            "identifier": self.identifier.to_dict(),
            "fields": dict(self.fields),
            "confidence": self.confidence,
            "source_urls": list(self.source_urls),
            "trust": self.trust.value,
            "poison_reasons": list(self.poison_reasons),
            "collected_at": self.collected_at,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True, slots=True)
class ResearchResult:
    research_id: str
    status: str
    stop_reason: str
    duration_ms: int
    identifiers_seen: int
    module_invocations: int
    evidence: tuple[ResearchEvidence, ...]
    tainted_evidence: int
    result_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "research_id": self.research_id,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "duration_ms": self.duration_ms,
            "identifiers_seen": self.identifiers_seen,
            "module_invocations": self.module_invocations,
            "evidence": [item.to_dict() for item in self.evidence],
            "tainted_evidence": self.tainted_evidence,
            "retention": {
                "mode": "EPHEMERAL",
                "raw_evidence_persisted": False,
                "database_cleanup_required": False,
            },
            "result_sha256": self.result_sha256,
        }


class PoisonChecker:
    """Treat every remote/source payload as untrusted data, never as instructions."""

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("ignore_previous", re.compile(r"\bignore\s+(all\s+)?previous\b", re.I)),
        ("system_prompt", re.compile(r"\b(system|developer)\s+(prompt|message|instructions?)\b", re.I)),
        ("role_override", re.compile(r"\b(you are now|act as|new instructions?)\b", re.I)),
        ("tool_instruction", re.compile(r"\b(execute|run|invoke)\s+(this\s+)?(command|tool|shell|code)\b", re.I)),
        ("jailbreak", re.compile(r"\b(jailbreak|prompt injection|bypass safety)\b", re.I)),
    )

    def inspect(self, value: object) -> tuple[str, ...]:
        text = self._flatten(value)
        reasons = [name for name, pattern in self._patterns if pattern.search(text)]
        return tuple(sorted(set(reasons)))

    def sanitize(self, value: object, *, depth: int = 0) -> Any:
        if depth > 4:
            return "[TRUNCATED_DEPTH]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            cleaned = "".join(ch for ch in value if ch >= " " or ch in "\n\t")
            return html.escape(cleaned[:2000], quote=False)
        if isinstance(value, Mapping):
            items = list(value.items())[:64]
            return {
                str(key)[:120]: self.sanitize(item, depth=depth + 1)
                for key, item in items
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self.sanitize(item, depth=depth + 1) for item in list(value)[:64]]
        return self.sanitize(str(value), depth=depth + 1)

    def _flatten(self, value: object) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, default=str)[:20000]
        except (TypeError, ValueError):
            return str(value)[:20000]


class SeedExpansionModule:
    """Local deterministic pivots. No network. Useful as the first correlation layer."""

    name = "seed-expansion.local"
    required_capability = "osint.correlation.expand"
    supported_kinds = frozenset({IdentifierKind.EMAIL, IdentifierKind.URL})

    async def lookup(self, identifier: ResearchIdentifier, context: ModuleContext) -> ModuleResult:
        if identifier.kind is IdentifierKind.EMAIL:
            local, sep, domain = identifier.value.partition("@")
            if not sep:
                return ModuleResult(fields={"valid_shape": False}, confidence=0.0)
            pivots: list[ResearchIdentifier] = []
            if local:
                pivots.append(ResearchIdentifier(IdentifierKind.USERNAME, local))
            if domain:
                pivots.append(ResearchIdentifier(IdentifierKind.DOMAIN, domain.lower()))
            return ModuleResult(
                fields={"local_part": local, "domain": domain.lower(), "valid_shape": True},
                confidence=1.0,
                pivots=tuple(pivots),
            )

        parsed = urlsplit(identifier.value)
        host = (parsed.hostname or "").lower()
        pivots = []
        if host:
            pivots.append(ResearchIdentifier(IdentifierKind.DOMAIN, host))
        path_parts = [part for part in parsed.path.split("/") if part]
        if path_parts:
            candidate = path_parts[-1]
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}", candidate):
                pivots.append(ResearchIdentifier(IdentifierKind.USERNAME, candidate))
        return ModuleResult(
            fields={"host": host, "path": parsed.path, "scheme": parsed.scheme},
            confidence=0.9 if host else 0.2,
            pivots=tuple(pivots),
            source_urls=(identifier.value,),
        )


class BoundedResearchEngine:
    def __init__(
        self,
        modules: Sequence[ResearchModule] | None = None,
        *,
        budget: ResearchBudget | None = None,
        poison_checker: PoisonChecker | None = None,
        planner: object | None = None,
    ) -> None:
        self.modules = tuple(modules or (SeedExpansionModule(),))
        self.budget = budget or ResearchBudget()
        self.poison_checker = poison_checker or PoisonChecker()
        self.planner = planner

    def run(
        self,
        seeds: Sequence[ResearchIdentifier],
        *,
        allowed_capabilities: Sequence[str],
        event_sink: EventSink | None = None,
    ) -> ResearchResult:
        return asyncio.run(
            self.run_async(
                seeds,
                allowed_capabilities=allowed_capabilities,
                event_sink=event_sink,
            )
        )

    async def run_async(
        self,
        seeds: Sequence[ResearchIdentifier],
        *,
        allowed_capabilities: Sequence[str],
        event_sink: EventSink | None = None,
    ) -> ResearchResult:
        research_id = str(uuid4())
        started = time.monotonic()
        deadline = started + self.budget.hard_timeout_seconds
        context = ModuleContext(deadline, frozenset(allowed_capabilities))
        emit = event_sink or (lambda _event, _payload: None)
        emit("research_started", {"research_id": research_id, "seed_count": len(seeds)})

        try:
            result = await asyncio.wait_for(
                self._run_loop(research_id, seeds, context, emit, started),
                timeout=self.budget.hard_timeout_seconds,
            )
        except TimeoutError:
            duration_ms = int((time.monotonic() - started) * 1000)
            result = self._finalize(
                research_id=research_id,
                status="STOPPED",
                stop_reason="HARD_DEADLINE_300S",
                duration_ms=duration_ms,
                identifiers_seen=0,
                module_invocations=0,
                evidence=(),
            )
            emit("research_stopped", {"research_id": research_id, "reason": result.stop_reason})
        emit("done", result.to_dict())
        return result

    async def _run_loop(
        self,
        research_id: str,
        seeds: Sequence[ResearchIdentifier],
        context: ModuleContext,
        emit: EventSink,
        started: float,
    ) -> ResearchResult:
        frontier: deque[ResearchIdentifier] = deque()
        seen: set[str] = set()
        for seed in seeds:
            normalized = self._normalize_identifier(seed)
            if normalized.key not in seen:
                seen.add(normalized.key)
                frontier.append(normalized)

        evidence: list[ResearchEvidence] = []
        invocations = 0
        empty_rounds = 0
        semaphore = asyncio.Semaphore(self.budget.max_parallel)

        while frontier:
            if time.monotonic() >= context.deadline_monotonic:
                return self._finalize(
                    research_id, "STOPPED", "HARD_DEADLINE_300S",
                    int((time.monotonic() - started) * 1000), len(seen), invocations, evidence,
                )
            if len(seen) >= self.budget.max_identifiers:
                return self._finalize(
                    research_id, "STOPPED", "IDENTIFIER_BUDGET_EXHAUSTED",
                    int((time.monotonic() - started) * 1000), len(seen), invocations, evidence,
                )
            if len(evidence) >= self.budget.max_evidence:
                return self._finalize(
                    research_id, "STOPPED", "EVIDENCE_BUDGET_EXHAUSTED",
                    int((time.monotonic() - started) * 1000), len(seen), invocations, evidence,
                )
            if invocations >= self.budget.max_module_invocations:
                return self._finalize(
                    research_id, "STOPPED", "INVOCATION_BUDGET_EXHAUSTED",
                    int((time.monotonic() - started) * 1000), len(seen), invocations, evidence,
                )

            current_depth = frontier[0].depth
            batch: list[ResearchIdentifier] = []
            while frontier and frontier[0].depth == current_depth:
                batch.append(frontier.popleft())
            if current_depth > self.budget.max_depth:
                continue

            scheduled: list[
                Awaitable[
                    tuple[
                        ResearchModule,
                        ResearchIdentifier,
                        ModuleResult | Exception,
                        int,
                    ]
                ]
            ] = []
            for identifier in batch:
                compatible = [
                    module
                    for module in self.modules
                    if identifier.kind in module.supported_kinds
                    and module.required_capability in context.allowed_capabilities
                ]

                planned = tuple(compatible)
                if self.planner is not None:
                    planned, decisions = self.planner.plan(compatible, identifier)
                    for decision in decisions:
                        if decision.run:
                            continue
                        emit(
                            "source_skipped",
                            {
                                "research_id": research_id,
                                "module": decision.source,
                                "identifier_kind": identifier.kind.value,
                                "identifier_depth": identifier.depth,
                                "reason": decision.reason,
                                "priority": decision.priority,
                            },
                        )

                for module in planned:
                    if invocations >= self.budget.max_module_invocations:
                        break
                    invocations += 1
                    descriptor = getattr(module, "descriptor", None)
                    emit(
                        "source_started",
                        {
                            "research_id": research_id,
                            "module": module.name,
                            "family": getattr(descriptor, "family", getattr(module, "family", "LOCAL")),
                            "identifier_kind": identifier.kind.value,
                            "identifier_depth": identifier.depth,
                        },
                    )
                    scheduled.append(self._invoke(module, identifier, context, semaphore))

            if not scheduled:
                empty_rounds += 1
                if empty_rounds >= self.budget.no_progress_rounds:
                    break
                continue

            new_pivots = 0
            for completed in asyncio.as_completed(scheduled):
                module, identifier, outcome, duration_ms = await completed
                descriptor = getattr(module, "descriptor", None)
                if isinstance(outcome, Exception):
                    payload = {
                        "research_id": research_id,
                        "module": module.name,
                        "family": getattr(descriptor, "family", getattr(module, "family", "LOCAL")),
                        "identifier_kind": identifier.kind.value,
                        "identifier_depth": identifier.depth,
                        "error": type(outcome).__name__,
                        "duration_ms": duration_ms,
                    }
                    emit("module_error", payload)
                    emit(
                        "source_timeout" if isinstance(outcome, TimeoutError) else "source_error",
                        payload,
                    )
                    continue

                item = self._evidence_from_result(module, identifier, outcome)
                evidence.append(item)
                emit("identifier_result", item.to_dict())
                emit(
                    "source_completed",
                    {
                        "research_id": research_id,
                        "module": module.name,
                        "family": getattr(descriptor, "family", getattr(module, "family", "LOCAL")),
                        "identifier_kind": identifier.kind.value,
                        "identifier_depth": identifier.depth,
                        "duration_ms": duration_ms,
                        "source_url_count": len(outcome.source_urls),
                        "pivot_count": len(outcome.pivots),
                        "confidence": item.confidence,
                    },
                )
                rate_limited_count = item.fields.get("rate_limited_count", 0)
                if isinstance(rate_limited_count, int) and rate_limited_count > 0:
                    emit(
                        "source_rate_limited",
                        {
                            "research_id": research_id,
                            "module": module.name,
                            "family": getattr(descriptor, "family", getattr(module, "family", "LOCAL")),
                            "count": rate_limited_count,
                        },
                    )

                if item.trust is TrustState.TAINTED:
                    emit(
                        "poison_blocked",
                        {
                            "research_id": research_id,
                            "evidence_id": item.evidence_id,
                            "module": module.name,
                            "reasons": list(item.poison_reasons),
                        },
                    )
                    continue

                for pivot in outcome.pivots:
                    if identifier.depth >= self.budget.max_depth:
                        break
                    normalized = self._normalize_identifier(
                        ResearchIdentifier(
                            pivot.kind,
                            pivot.value,
                            depth=identifier.depth + 1,
                            parent_evidence_id=item.evidence_id,
                        )
                    )
                    if normalized.key in seen:
                        continue
                    if len(seen) >= self.budget.max_identifiers:
                        break
                    seen.add(normalized.key)
                    frontier.append(normalized)
                    new_pivots += 1
                    emit("pivot_discovered", normalized.to_dict())

            if new_pivots == 0:
                empty_rounds += 1
            else:
                empty_rounds = 0
            if empty_rounds >= self.budget.no_progress_rounds:
                break

        return self._finalize(
            research_id=research_id,
            status="COMPLETED",
            stop_reason="NO_MORE_TRUSTED_PIVOTS",
            duration_ms=int((time.monotonic() - started) * 1000),
            identifiers_seen=len(seen),
            module_invocations=invocations,
            evidence=evidence,
        )

    async def _invoke(
        self,
        module: ResearchModule,
        identifier: ResearchIdentifier,
        context: ModuleContext,
        semaphore: asyncio.Semaphore,
    ) -> tuple[ResearchModule, ResearchIdentifier, ModuleResult | Exception, int]:
        started = time.monotonic()
        async with semaphore:
            timeout = min(self.budget.per_module_timeout_seconds, context.remaining_seconds)
            if timeout <= 0:
                return module, identifier, TimeoutError(), 0
            try:
                result = await asyncio.wait_for(module.lookup(identifier, context), timeout=timeout)
                return module, identifier, result, int((time.monotonic() - started) * 1000)
            except Exception as exc:  # module failures are isolated evidence, not engine crashes
                return module, identifier, exc, int((time.monotonic() - started) * 1000)

    def _evidence_from_result(
        self,
        module: ResearchModule,
        identifier: ResearchIdentifier,
        result: ModuleResult,
    ) -> ResearchEvidence:
        sanitized = self.poison_checker.sanitize(result.fields)
        poison_reasons = self.poison_checker.inspect(result.fields)
        trust = TrustState.TAINTED if poison_reasons else TrustState.CLEAN
        payload = {
            "module": module.name,
            "identifier": identifier.to_dict(),
            "fields": sanitized,
            "confidence": max(0.0, min(1.0, float(result.confidence))),
            "source_urls": list(result.source_urls),
            "trust": trust.value,
            "poison_reasons": list(poison_reasons),
        }
        digest = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return ResearchEvidence(
            evidence_id=str(uuid4()),
            module=module.name,
            identifier=identifier,
            fields=sanitized if isinstance(sanitized, Mapping) else {"value": sanitized},
            confidence=payload["confidence"],
            source_urls=result.source_urls,
            trust=trust,
            poison_reasons=poison_reasons,
            collected_at=utc_iso(),
            evidence_sha256=digest,
        )

    def _normalize_identifier(self, identifier: ResearchIdentifier) -> ResearchIdentifier:
        value = identifier.value.strip()
        if identifier.kind is IdentifierKind.EMAIL:
            value = value.casefold()
            if len(value) > 320 or value.count("@") != 1:
                raise SherlockError("INVALID_RESEARCH_IDENTIFIER", "Niepoprawny EMAIL research seed.")
        elif identifier.kind is IdentifierKind.PHONE:
            raw = value
            if raw.startswith("00"):
                raw = "+" + raw[2:]
            if not raw.startswith("+"):
                raise SherlockError(
                    "INVALID_RESEARCH_IDENTIFIER",
                    "PHONE research seed wymaga numeru międzynarodowego z prefiksem +.",
                )
            digits = re.sub(r"\D", "", raw)
            if not 8 <= len(digits) <= 15:
                raise SherlockError(
                    "INVALID_RESEARCH_IDENTIFIER",
                    "Niepoprawny PHONE research seed.",
                )
            value = "+" + digits
        elif identifier.kind is IdentifierKind.DOMAIN:
            value = value.rstrip(".").casefold()
            if not value or len(value) > 253:
                raise SherlockError("INVALID_RESEARCH_IDENTIFIER", "Niepoprawna DOMAIN research seed.")
        elif identifier.kind is IdentifierKind.URL:
            if len(value) > 2048:
                raise SherlockError("INVALID_RESEARCH_IDENTIFIER", "URL research seed jest za długi.")
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise SherlockError("INVALID_RESEARCH_IDENTIFIER", "URL research seed wymaga http(s) i hosta.")
        elif identifier.kind is IdentifierKind.USERNAME:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
                raise SherlockError("INVALID_RESEARCH_IDENTIFIER", "Niepoprawny USERNAME research seed.")
        return ResearchIdentifier(identifier.kind, value, identifier.depth, identifier.parent_evidence_id)

    def _finalize(
        self,
        research_id: str,
        status: str,
        stop_reason: str,
        duration_ms: int,
        identifiers_seen: int,
        module_invocations: int,
        evidence: Sequence[ResearchEvidence],
    ) -> ResearchResult:
        compact = {
            "research_id": research_id,
            "status": status,
            "stop_reason": stop_reason,
            "duration_ms": duration_ms,
            "identifiers_seen": identifiers_seen,
            "module_invocations": module_invocations,
            "evidence_sha256": [item.evidence_sha256 for item in evidence],
        }
        digest = hashlib.sha256(
            json.dumps(compact, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return ResearchResult(
            research_id=research_id,
            status=status,
            stop_reason=stop_reason,
            duration_ms=duration_ms,
            identifiers_seen=identifiers_seen,
            module_invocations=module_invocations,
            evidence=tuple(evidence),
            tainted_evidence=sum(1 for item in evidence if item.trust is TrustState.TAINTED),
            result_sha256=digest,
        )
