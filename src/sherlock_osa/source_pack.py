from __future__ import annotations

import asyncio
import json
import sys
from typing import Mapping

from sherlock_osa.research import (
    ModuleContext,
    ModuleResult,
    ResearchIdentifier,
    ResearchModule,
)
from sherlock_osa.social_mesh import SocialMeshUsernameModule
from sherlock_osa.source_registry import (
    COMMONCRAWL_DOMAIN,
    COMMONCRAWL_URL,
    CRTSH_DOMAIN,
    GITHUB_USERNAME,
    GITLAB_USERNAME,
    GRAVATAR_EMAIL,
    HIBP_ACCOUNT,
    HOLEHE,
    MAIGRET,
    RDAP_DOMAIN,
    SOCIAL_MESH_USERNAME,
    SOURCE_DESCRIPTORS,
    WAYBACK_DOMAIN,
    WAYBACK_URL,
    SourceDescriptor,
    registry_health,
)


WORKER_PROTOCOL = "sherlock-source-worker.v2"


class IsolatedSourceModule(ResearchModule):
    """Run network OSINT sources in a killable subprocess.

    Identifier values are sent over stdin instead of argv so they are not exposed in
    the process list. The parent process owns the hard timeout and can kill the worker.
    Successful normalized results are retained only in-memory for the current case so
    the Social Graph can combine direct GitHub/GitLab/Holehe/Maigret evidence with
    EmailOSINT and the dataset-driven Site Probe Engine.
    """

    def __init__(self, descriptor: SourceDescriptor) -> None:
        self.descriptor = descriptor
        self.name = descriptor.name
        self.supported_kinds = descriptor.supported_kinds
        self.required_capability = descriptor.required_capability
        self.results: list[dict[str, object]] = []

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
        if remaining <= 1.0:
            raise TimeoutError("research deadline reached")
        timeout = max(
            0.5,
            min(
                float(self.descriptor.timeout_seconds),
                remaining - 0.5,
            ),
        )
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
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
            raise TimeoutError(f"{self.name} exceeded {timeout:.1f}s")
        except asyncio.CancelledError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
            raise

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
            raise RuntimeError(
                f"{self.name} source unavailable: {payload.get('error_code', 'UNKNOWN')}"
            )

        fields = payload.get("fields", {})
        if not isinstance(fields, Mapping):
            fields = {"value": fields}

        raw_pivots = payload.get("pivots", [])
        pivots: list[ResearchIdentifier] = []
        if isinstance(raw_pivots, list):
            from sherlock_osa.research import IdentifierKind

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
        source_urls = (
            tuple(
                value
                for value in raw_urls[:128]
                if isinstance(value, str) and value.startswith(("http://", "https://"))
            )
            if isinstance(raw_urls, list)
            else ()
        )

        try:
            confidence = float(payload.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        if len(self.results) < 128:
            self.results.append(
                {
                    "source": self.name,
                    "family": self.descriptor.family,
                    "identifier_kind": identifier.kind.value,
                    "identifier_value": identifier.value,
                    "identifier_depth": identifier.depth,
                    "fields": dict(fields),
                    "source_urls": list(source_urls),
                    "confidence": confidence,
                }
            )

        return ModuleResult(
            fields=dict(fields),
            confidence=confidence,
            pivots=tuple(pivots),
            source_urls=source_urls,
        )


def build_source_modules(mode: str = "DEEP") -> tuple[ResearchModule, ...]:
    modules: list[ResearchModule] = []
    for descriptor in SOURCE_DESCRIPTORS:
        if descriptor.name == SOCIAL_MESH_USERNAME.name:
            social = SocialMeshUsernameModule(mode)
            social.descriptor = descriptor
            modules.append(social)
        else:
            modules.append(IsolatedSourceModule(descriptor))
    return tuple(modules)


def source_health() -> dict[str, object]:
    return {
        "protocol": WORKER_PROTOCOL,
        **registry_health(),
    }


__all__ = [
    "COMMONCRAWL_DOMAIN",
    "COMMONCRAWL_URL",
    "CRTSH_DOMAIN",
    "GITHUB_USERNAME",
    "GITLAB_USERNAME",
    "GRAVATAR_EMAIL",
    "HIBP_ACCOUNT",
    "HOLEHE",
    "IsolatedSourceModule",
    "MAIGRET",
    "RDAP_DOMAIN",
    "SOCIAL_MESH_USERNAME",
    "SOURCE_DESCRIPTORS",
    "WAYBACK_DOMAIN",
    "WAYBACK_URL",
    "WORKER_PROTOCOL",
    "build_source_modules",
    "source_health",
]
