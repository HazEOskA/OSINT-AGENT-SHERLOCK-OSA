from __future__ import annotations

import asyncio
import importlib.metadata
import json
import sys
from dataclasses import dataclass
from typing import Mapping

from sherlock_osa.research import (
    IdentifierKind,
    ModuleContext,
    ModuleResult,
    ResearchIdentifier,
    ResearchModule,
)


WORKER_PROTOCOL = "sherlock-source-worker.v1"


@dataclass(frozen=True, slots=True)
class SourceDescriptor:
    name: str
    package: str
    expected_version: str
    supported_kinds: frozenset[IdentifierKind]
    required_capability: str
    max_identifier_depth: int
    network_effect: bool = True

    def health(self) -> dict[str, object]:
        try:
            version = importlib.metadata.version(self.package)
        except importlib.metadata.PackageNotFoundError:
            return {
                "name": self.name,
                "package": self.package,
                "available": False,
                "version": None,
                "expected_version": self.expected_version,
                "version_match": False,
                "network_effect": self.network_effect,
                "max_identifier_depth": self.max_identifier_depth,
            }
        return {
            "name": self.name,
            "package": self.package,
            "available": True,
            "version": version,
            "expected_version": self.expected_version,
            "version_match": version == self.expected_version,
            "network_effect": self.network_effect,
            "max_identifier_depth": self.max_identifier_depth,
        }


HOLEHE = SourceDescriptor(
    name="holehe.email",
    package="holehe",
    expected_version="1.61",
    supported_kinds=frozenset({IdentifierKind.EMAIL}),
    required_capability="osint.email.lookup",
    max_identifier_depth=2,
)

MAIGRET = SourceDescriptor(
    name="maigret.username",
    package="maigret",
    expected_version="0.6.4",
    supported_kinds=frozenset({IdentifierKind.USERNAME}),
    required_capability="osint.username.lookup",
    max_identifier_depth=1,
)

SOURCE_DESCRIPTORS = (HOLEHE, MAIGRET)


class IsolatedSourceModule(ResearchModule):
    """Run third-party OSINT libraries in a killable subprocess.

    Identifier values are sent over stdin instead of argv so they are not exposed in
    the process list. The parent process owns the hard timeout and can kill the worker.
    """

    def __init__(self, descriptor: SourceDescriptor) -> None:
        self.descriptor = descriptor
        self.name = descriptor.name
        self.supported_kinds = descriptor.supported_kinds
        self.required_capability = descriptor.required_capability

    async def lookup(self, identifier: ResearchIdentifier, context: ModuleContext) -> ModuleResult:
        if identifier.depth > self.descriptor.max_identifier_depth:
            return ModuleResult(
                fields={
                    "provider": self.descriptor.name,
                    "skipped": "SOURCE_DEPTH_BOUND",
                    "identifier_depth": identifier.depth,
                    "max_identifier_depth": self.descriptor.max_identifier_depth,
                },
                confidence=0.0,
            )
        remaining = context.remaining_seconds
        if remaining <= 0:
            raise TimeoutError("research deadline reached")
        timeout = max(1.0, min(remaining, 60.0))
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "sherlock_osa.source_worker",
            self.descriptor.name,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        request = json.dumps(
            {
                "protocol": WORKER_PROTOCOL,
                "kind": identifier.kind.value,
                "value": identifier.value,
                "timeout_seconds": timeout,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(request), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.communicate()
            raise TimeoutError(f"{self.name} exceeded {timeout:.1f}s")

        if len(stdout) > 2_000_000:
            raise RuntimeError(f"{self.name} returned an oversized payload")
        if process.returncode != 0:
            error = stderr.decode("utf-8", errors="replace")[:1000].strip()
            raise RuntimeError(f"{self.name} worker failed: {error or process.returncode}")
        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"{self.name} worker returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("protocol") != WORKER_PROTOCOL:
            raise RuntimeError(f"{self.name} worker protocol mismatch")
        if payload.get("ok") is not True:
            raise RuntimeError(f"{self.name} source unavailable: {payload.get('error_code', 'UNKNOWN')}")

        fields = payload.get("fields", {})
        if not isinstance(fields, Mapping):
            fields = {"value": fields}
        raw_pivots = payload.get("pivots", [])
        pivots: list[ResearchIdentifier] = []
        if isinstance(raw_pivots, list):
            for raw in raw_pivots[:128]:
                if not isinstance(raw, Mapping):
                    continue
                try:
                    kind = IdentifierKind(str(raw.get("kind")))
                except ValueError:
                    continue
                value = raw.get("value")
                if isinstance(value, str) and value.strip():
                    pivots.append(ResearchIdentifier(kind, value.strip()))
        raw_urls = payload.get("source_urls", [])
        source_urls = tuple(
            value for value in raw_urls[:128] if isinstance(value, str) and value.startswith(("http://", "https://"))
        ) if isinstance(raw_urls, list) else ()
        try:
            confidence = float(payload.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return ModuleResult(
            fields=dict(fields),
            confidence=max(0.0, min(1.0, confidence)),
            pivots=tuple(pivots),
            source_urls=source_urls,
        )


def build_source_modules() -> tuple[ResearchModule, ...]:
    return tuple(IsolatedSourceModule(descriptor) for descriptor in SOURCE_DESCRIPTORS)


def source_health() -> dict[str, object]:
    sources = [descriptor.health() for descriptor in SOURCE_DESCRIPTORS]
    return {
        "protocol": WORKER_PROTOCOL,
        "sources": sources,
        "all_dependencies_available": all(bool(source["available"]) for source in sources),
        "all_versions_pinned": all(bool(source["version_match"]) for source in sources),
    }
