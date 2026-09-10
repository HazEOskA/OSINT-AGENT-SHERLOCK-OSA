from __future__ import annotations

import asyncio
import json
import sys
from typing import Mapping

from sherlock_osa.research import (
    IdentifierKind,
    ModuleContext,
    ModuleResult,
    ResearchIdentifier,
)
from sherlock_osa.social_probe_worker import PROTOCOL


class SocialMeshUsernameModule:
    """Dataset-driven public username enumeration across hundreds of sites.

    The module intentionally runs in a killable subprocess. It does not use
    authenticated sessions, proxy rotation, CAPTCHA bypass, or registration
    side effects. Dataset-defined POST probes are skipped by the worker.
    """

    name = "socialmesh.username"
    family = "SOCIAL_MESH"
    required_capability = "osint.username.lookup"
    supported_kinds = frozenset({IdentifierKind.USERNAME})

    def __init__(self, mode: str = "MAX") -> None:
        self.mode = str(mode).upper()

    async def lookup(
        self,
        identifier: ResearchIdentifier,
        context: ModuleContext,
    ) -> ModuleResult:
        if identifier.kind is not IdentifierKind.USERNAME:
            raise ValueError("social mesh requires USERNAME")
        if identifier.depth > 0:
            return ModuleResult(
                fields={
                    "provider": "socialmesh",
                    "skipped": "CANONICAL_USERNAME_ONLY",
                    "identifier_depth": identifier.depth,
                },
                confidence=0.0,
            )

        remaining = context.remaining_seconds
        if remaining <= 2.0:
            raise TimeoutError("research deadline reached")
        timeout = max(5.0, min(55.0, remaining - 1.0))

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "sherlock_osa.social_probe_worker",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        request = json.dumps(
            {
                "protocol": PROTOCOL,
                "username": identifier.value,
                "mode": self.mode,
                "timeout_seconds": timeout,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(request),
                timeout=timeout,
            )
        except TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
            raise TimeoutError(f"social mesh exceeded {timeout:.1f}s")
        except asyncio.CancelledError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.communicate()
            raise

        if process.returncode != 0:
            error = stderr.decode("utf-8", errors="replace")[:1200].strip()
            raise RuntimeError(f"social mesh worker failed: {error or process.returncode}")
        if len(stdout) > 4_000_000:
            raise RuntimeError("social mesh payload too large")

        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("social mesh worker returned invalid JSON") from exc
        if not isinstance(payload, Mapping) or payload.get("protocol") != PROTOCOL:
            raise RuntimeError("social mesh protocol mismatch")
        if payload.get("ok") is not True:
            raise RuntimeError("social mesh worker did not complete")

        batch = payload.get("batch")
        if not isinstance(batch, Mapping):
            raise RuntimeError("social mesh batch missing")

        found_raw = batch.get("found", [])
        found = [item for item in found_raw if isinstance(item, Mapping)] if isinstance(found_raw, list) else []

        urls: list[str] = []
        pivots: list[ResearchIdentifier] = []
        seen_urls: set[str] = set()
        for item in found[:300]:
            url = item.get("profile_url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            if url in seen_urls:
                continue
            seen_urls.add(url)
            urls.append(url)
            pivots.append(ResearchIdentifier(IdentifierKind.URL, url))
            if len(urls) >= 128:
                break

        confidence = 0.0
        if found:
            reliability = [
                float(item.get("reliability", 0.0))
                for item in found
                if isinstance(item.get("reliability"), (int, float))
            ]
            confidence = max(reliability, default=0.75)

        return ModuleResult(
            fields={
                "provider": "socialmesh",
                "found": bool(found),
                "username": identifier.value,
                "social_mesh": dict(batch),
                "accounts": [dict(item) for item in found[:300]],
            },
            confidence=max(0.0, min(0.99, confidence)),
            pivots=tuple(pivots),
            source_urls=tuple(urls),
        )
