from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.emailosint import EmailOsintClient
from sherlock_osa.research import (
    IdentifierKind,
    ModuleContext,
    ModuleResult,
    ResearchIdentifier,
)


class EmailOsintResearchModule:
    """Expose EmailOSINT as one high-value sensor inside the bounded source mesh."""

    name = "emailosint.email"
    family = "IDENTITY"
    required_capability = "osint.email.lookup"
    supported_kinds = frozenset({IdentifierKind.EMAIL})

    def __init__(self, client: EmailOsintClient) -> None:
        self.client = client

    async def lookup(
        self,
        identifier: ResearchIdentifier,
        context: ModuleContext,
    ) -> ModuleResult:
        if context.remaining_seconds <= 1.0:
            raise TimeoutError("research deadline reached")

        bundle = await asyncio.to_thread(
            self.client.lookup,
            {"email": identifier.value},
        )
        pivots = self._extract_pivots(bundle)
        source_urls = self._extract_urls(bundle)
        parity = bundle.get("parity", {}) if isinstance(bundle, Mapping) else {}

        return ModuleResult(
            fields={
                "provider": "EmailOSINT",
                "found": True,
                "parity": dict(parity) if isinstance(parity, Mapping) else {},
                "bundle": bundle,
            },
            confidence=0.96,
            pivots=pivots,
            source_urls=source_urls,
        )

    def _extract_pivots(self, value: object) -> tuple[ResearchIdentifier, ...]:
        pivots: dict[str, ResearchIdentifier] = {}

        def add(kind: IdentifierKind, raw: object) -> None:
            if not isinstance(raw, str):
                return
            candidate = raw.strip()
            if not candidate or candidate == "[REDACTED]":
                return

            try:
                if kind is IdentifierKind.EMAIL:
                    if candidate.count("@") != 1 or len(candidate) > 320:
                        return
                    candidate = candidate.casefold()
                elif kind is IdentifierKind.PHONE:
                    if candidate.startswith("00"):
                        candidate = "+" + candidate[2:]
                    if not candidate.startswith("+"):
                        return
                    digits = re.sub(r"\D", "", candidate)
                    if not 8 <= len(digits) <= 15:
                        return
                    candidate = "+" + digits
                elif kind is IdentifierKind.USERNAME:
                    if len(candidate) > 64 or any(ch.isspace() for ch in candidate):
                        return
                elif kind is IdentifierKind.DOMAIN:
                    candidate = candidate.rstrip(".").casefold()
                    if "." not in candidate or len(candidate) > 253:
                        return
                elif kind is IdentifierKind.URL:
                    parsed = urlsplit(candidate)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                        return
                else:
                    return
            except ValueError:
                return

            pivot = ResearchIdentifier(kind, candidate)
            pivots[pivot.key] = pivot

        def values_of(child: object) -> Sequence[object]:
            if isinstance(child, Sequence) and not isinstance(
                child,
                (str, bytes, bytearray),
            ):
                return list(child)[:128]
            return (child,)

        def walk(node: object, depth: int = 0) -> None:
            if depth > 7 or len(pivots) >= 192:
                return
            if isinstance(node, Mapping):
                for key, child in list(node.items())[:128]:
                    key_text = str(key).casefold()
                    values = values_of(child)

                    if key_text in {
                        "email",
                        "emails",
                        "mail",
                        "mails",
                        "public_email",
                    }:
                        for item in values:
                            add(IdentifierKind.EMAIL, item)
                    elif key_text in {
                        "phone",
                        "phones",
                        "telephone",
                        "mobile",
                        "phone_number",
                    }:
                        for item in values:
                            add(IdentifierKind.PHONE, item)
                    elif key_text in {
                        "username",
                        "usernames",
                        "handle",
                        "handles",
                        "nickname",
                        "nick",
                        "login",
                        "twitter_username",
                    }:
                        for item in values:
                            add(IdentifierKind.USERNAME, item)
                    elif key_text in {
                        "domain",
                        "domains",
                        "host",
                        "hostname",
                    }:
                        for item in values:
                            add(IdentifierKind.DOMAIN, item)
                    elif key_text in {
                        "url",
                        "urls",
                        "profile_url",
                        "website",
                        "websites",
                        "website_url",
                        "web_url",
                        "html_url",
                        "origin_url",
                        "link",
                        "links",
                    }:
                        for item in values:
                            add(IdentifierKind.URL, item)

                    if isinstance(child, (Mapping, list, tuple)):
                        walk(child, depth + 1)

            elif isinstance(node, (list, tuple)):
                for child in node[:128]:
                    walk(child, depth + 1)

        walk(value)
        return tuple(pivots[key] for key in sorted(pivots))[:192]

    def _extract_urls(self, value: object) -> tuple[str, ...]:
        urls: set[str] = set()

        def walk(node: object, depth: int = 0) -> None:
            if depth > 7 or len(urls) >= 192:
                return
            if isinstance(node, str):
                candidate = node.strip()
                if candidate.startswith(("http://", "https://")):
                    try:
                        parsed = urlsplit(candidate)
                    except ValueError:
                        return
                    if parsed.hostname:
                        urls.add(candidate[:2048])
                return
            if isinstance(node, Mapping):
                for child in list(node.values())[:128]:
                    walk(child, depth + 1)
            elif isinstance(node, (list, tuple)):
                for child in node[:128]:
                    walk(child, depth + 1)

        walk(value)
        return tuple(sorted(urls))[:192]
