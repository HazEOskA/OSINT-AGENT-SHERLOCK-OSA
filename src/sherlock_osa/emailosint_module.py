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
from sherlock_osa.truth_engine import TruthVerdict, confidence_for_presence


class EmailOsintResearchModule:
    """Expose EmailOSINT as a truth-aware high-value sensor.

    Transport success is not treated as account existence. Only provider signals that
    the normalizer classified as FOUND may create pivots or a positive source verdict.
    """

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
        identity = bundle.get("identity", {}) if isinstance(bundle, Mapping) else {}
        signals = identity.get("signals", []) if isinstance(identity, Mapping) else []
        found_signals = [
            signal
            for signal in signals
            if isinstance(signal, Mapping)
            and str(signal.get("status", "")).upper() == TruthVerdict.FOUND.value
        ] if isinstance(signals, list) else []
        observed_signals = [
            signal
            for signal in signals
            if isinstance(signal, Mapping)
            and str(signal.get("status", "")).upper() == TruthVerdict.OBSERVED.value
        ] if isinstance(signals, list) else []

        verdict = TruthVerdict.FOUND if found_signals else (
            TruthVerdict.OBSERVED if observed_signals else TruthVerdict.NOT_FOUND
        )
        positive_payload = {"linked_accounts": found_signals}
        pivots = self._extract_pivots(positive_payload)
        source_urls = self._extract_urls(positive_payload)
        parity = bundle.get("parity", {}) if isinstance(bundle, Mapping) else {}
        confidence = confidence_for_presence(
            verdict,
            base=0.96,
            checked_count=max(1, len(signals) if isinstance(signals, list) else 0),
        )

        return ModuleResult(
            fields={
                "provider": "EmailOSINT",
                "found": verdict is TruthVerdict.FOUND,
                "truth_verdict": verdict.value,
                "positive_signal_count": len(found_signals),
                "observed_signal_count": len(observed_signals),
                "parity": dict(parity) if isinstance(parity, Mapping) else {},
                "bundle": bundle,
            },
            confidence=confidence,
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
                # Never pivot from explicitly negative/observed identity signals.
                status = str(node.get("status", "")).upper()
                if status and status != TruthVerdict.FOUND.value and (
                    "provider_payload" in node or "fields" in node
                ):
                    return
                for key, child in list(node.items())[:128]:
                    key_text = str(key).casefold()
                    values = values_of(child)

                    if key_text in {
                        "email", "emails", "mail", "mails", "public_email",
                    }:
                        for item in values:
                            add(IdentifierKind.EMAIL, item)
                    elif key_text in {
                        "phone", "phones", "telephone", "mobile", "phone_number",
                    }:
                        for item in values:
                            add(IdentifierKind.PHONE, item)
                    elif key_text in {
                        "username", "usernames", "handle", "handles", "nickname",
                        "nick", "login", "twitter_username",
                    }:
                        for item in values:
                            add(IdentifierKind.USERNAME, item)
                    elif key_text in {"domain", "domains", "host", "hostname"}:
                        for item in values:
                            add(IdentifierKind.DOMAIN, item)
                    elif key_text in {
                        "url", "urls", "profile_url", "website", "websites",
                        "website_url", "web_url", "html_url", "link", "links",
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
                status = str(node.get("status", "")).upper()
                if status and status != TruthVerdict.FOUND.value and (
                    "provider_payload" in node or "fields" in node
                ):
                    return
                for child in list(node.values())[:128]:
                    walk(child, depth + 1)
            elif isinstance(node, (list, tuple)):
                for child in node[:128]:
                    walk(child, depth + 1)

        walk(value)
        return tuple(sorted(urls))[:192]
