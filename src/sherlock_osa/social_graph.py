from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.social_taxonomy import (
    SOCIAL_CATEGORIES,
    categorise_accounts,
    classify_service,
    normalise_service_name,
    signal_presence_status,
)


_GENERIC_NAMES = {
    "unknown",
    "emailosint",
    "provider",
    "source",
    "account",
    "profile",
    "identifier",
    "result",
    "results",
    "data",
    "module",
    "service",
}
_SERVICE_KEYS = (
    "service",
    "platform",
    "site",
    "source",
    "provider",
    "network",
    "app",
    "application",
    "module",
    "name",
)
_URL_KEYS = (
    "profile_url",
    "url",
    "web_url",
    "website_url",
    "uri_pretty",
    "link",
)
_USERNAME_KEYS = (
    "username",
    "handle",
    "nickname",
    "nick",
    "login",
    "user",
)


@dataclass(frozen=True, slots=True)
class SocialAccount:
    service: str
    category: str
    status: str
    source: str
    confidence: float
    username: str = ""
    profile_url: str = ""
    evidence_urls: tuple[str, ...] = ()
    fields: Mapping[str, Any] | None = None
    origin: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "service": self.service,
            "category": self.category,
            "status": self.status,
            "source": self.source,
            "confidence": round(float(self.confidence), 3),
            "username": self.username,
            "profile_url": self.profile_url,
            "evidence_urls": list(self.evidence_urls),
            "fields": dict(self.fields or {}),
            "origin": self.origin,
        }


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _first(mapping: Mapping[str, Any], names: Sequence[str]) -> object:
    for name in names:
        if name in mapping and mapping.get(name) is not None:
            return mapping.get(name)
    return None


def _extract_urls(value: object, *, limit: int = 32) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()

    def walk(node: object, depth: int = 0) -> None:
        if depth > 7 or len(found) >= limit:
            return
        if isinstance(node, str):
            candidate = node.strip()
            if candidate.startswith(("http://", "https://")) and candidate not in seen:
                try:
                    parsed = urlsplit(candidate)
                except ValueError:
                    return
                if parsed.hostname:
                    seen.add(candidate)
                    found.append(candidate[:2048])
            return
        if isinstance(node, Mapping):
            for child in list(node.values())[:160]:
                walk(child, depth + 1)
        elif isinstance(node, (list, tuple)):
            for child in list(node)[:160]:
                walk(child, depth + 1)

    walk(value)
    return tuple(found)


def _service_name(mapping: Mapping[str, Any], fallback: str = "") -> str:
    for key in _SERVICE_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            candidate = normalise_service_name(value)
            if candidate.casefold() not in _GENERIC_NAMES:
                return candidate
        if isinstance(value, Mapping):
            nested = _service_name(value)
            if nested and nested.casefold() not in _GENERIC_NAMES:
                return nested
    candidate = normalise_service_name(fallback)
    return "" if candidate.casefold() in _GENERIC_NAMES else candidate


def _username(mapping: Mapping[str, Any]) -> str:
    value = _first(mapping, _USERNAME_KEYS)
    if isinstance(value, str):
        candidate = value.strip()
        if candidate and len(candidate) <= 128 and not any(ch.isspace() for ch in candidate):
            return candidate
    return ""


def _profile_url(mapping: Mapping[str, Any]) -> str:
    value = _first(mapping, _URL_KEYS)
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return value[:2048]
    urls = _extract_urls(mapping, limit=1)
    return urls[0] if urls else ""


def _looks_like_service_record(mapping: Mapping[str, Any], fallback_name: str = "") -> bool:
    service = _service_name(mapping, fallback_name)
    if not service:
        return False

    presence_keys = {
        "exists",
        "registered",
        "found",
        "account_exists",
        "present",
        "taken",
        "claimed",
        "available",
        "missing",
        "not_found",
        "unclaimed",
        "status",
    }
    if presence_keys.intersection({str(key).casefold() for key in mapping}):
        return True
    if _profile_url(mapping):
        return True
    if _username(mapping) and classify_service(service) != "OTHER":
        return True
    return False


def _account_from_mapping(
    mapping: Mapping[str, Any],
    *,
    fallback_service: str = "",
    source: str,
    origin: str,
    confidence: float,
) -> SocialAccount | None:
    service = _service_name(mapping, fallback_service)
    if not service:
        return None
    profile_url = _profile_url(mapping)
    category = classify_service(
        service,
        url=profile_url,
        category_hint=mapping.get("category", mapping.get("cat", "")),
        is_nsfw=bool(mapping.get("is_nsfw", mapping.get("isNSFW", False))),
    )
    return SocialAccount(
        service=service,
        category=category,
        status=signal_presence_status(mapping),
        source=source,
        confidence=confidence,
        username=_username(mapping),
        profile_url=profile_url,
        evidence_urls=_extract_urls(mapping),
        fields=dict(mapping),
        origin=origin,
    )


def _walk_service_records(
    value: object,
    *,
    source: str,
    origin: str,
    fallback_service: str = "",
    confidence: float = 0.72,
    limit: int = 1000,
) -> list[SocialAccount]:
    accounts: list[SocialAccount] = []

    def walk(node: object, path: str, depth: int = 0, inherited_service: str = "") -> None:
        if depth > 8 or len(accounts) >= limit:
            return
        if isinstance(node, Mapping):
            fallback = inherited_service or fallback_service
            if _looks_like_service_record(node, fallback):
                account = _account_from_mapping(
                    node,
                    fallback_service=fallback,
                    source=source,
                    origin=f"{origin}:{path}",
                    confidence=confidence,
                )
                if account:
                    accounts.append(account)
            service = _service_name(node, fallback)
            for key, child in list(node.items())[:256]:
                if isinstance(child, (Mapping, list, tuple)):
                    child_service = service
                    # Some providers use the service name itself as an object key.
                    key_text = str(key).strip()
                    if (
                        isinstance(child, Mapping)
                        and key_text
                        and key_text.casefold() not in _GENERIC_NAMES
                        and classify_service(key_text) != "OTHER"
                    ):
                        child_service = key_text
                    walk(child, f"{path}.{key}", depth + 1, child_service)
        elif isinstance(node, (list, tuple)):
            for index, child in enumerate(list(node)[:256]):
                if isinstance(child, (Mapping, list, tuple)):
                    walk(child, f"{path}[{index}]", depth + 1, inherited_service)

    walk(value, "root")
    return accounts


def _emailosint_accounts(emailosint: object) -> list[SocialAccount]:
    if not isinstance(emailosint, Mapping):
        return []
    accounts: list[SocialAccount] = []

    identity = emailosint.get("identity")
    if isinstance(identity, Mapping):
        signals = identity.get("signals")
        if isinstance(signals, list):
            for signal in signals:
                if not isinstance(signal, Mapping):
                    continue
                fields = signal.get("fields")
                payload = signal.get("provider_payload")
                base = payload if isinstance(payload, Mapping) else fields if isinstance(fields, Mapping) else signal
                if isinstance(base, Mapping):
                    source_name = _string(signal.get("source")) or "EmailOSINT"
                    account = _account_from_mapping(
                        base,
                        fallback_service=source_name,
                        source="EmailOSINT",
                        origin="emailosint.identity.signals",
                        confidence=0.96 if str(signal.get("status")) == "FOUND" else 0.72,
                    )
                    if account:
                        # Preserve the normalized provider verdict if available.
                        accounts.append(
                            SocialAccount(
                                service=account.service,
                                category=account.category,
                                status=str(signal.get("status") or account.status),
                                source=account.source,
                                confidence=account.confidence,
                                username=account.username,
                                profile_url=account.profile_url,
                                evidence_urls=account.evidence_urls,
                                fields=account.fields,
                                origin=account.origin,
                            )
                        )

    provider = emailosint.get("provider")
    if isinstance(provider, Mapping):
        events = provider.get("events")
        if isinstance(events, list):
            for event in events[:1000]:
                if not isinstance(event, Mapping):
                    continue
                event_name = _string(event.get("event"))
                data = event.get("data")
                fallback = event_name if classify_service(event_name) != "OTHER" else ""
                accounts.extend(
                    _walk_service_records(
                        data,
                        source="EmailOSINT",
                        origin=f"emailosint.event.{event_name or 'message'}",
                        fallback_service=fallback,
                        confidence=0.9,
                        limit=500,
                    )
                )

        raw = provider.get("raw")
        accounts.extend(
            _walk_service_records(
                raw,
                source="EmailOSINT",
                origin="emailosint.provider.raw",
                confidence=0.82,
                limit=700,
            )
        )

    return accounts


def _socialmesh_accounts(sensor_payloads: object) -> list[SocialAccount]:
    if not isinstance(sensor_payloads, Mapping):
        return []
    raw = sensor_payloads.get("social_mesh")
    if raw is None:
        return []

    batches: list[Mapping[str, Any]] = []
    if isinstance(raw, Mapping):
        raw_batches = raw.get("batches")
        if isinstance(raw_batches, list):
            batches.extend(item for item in raw_batches if isinstance(item, Mapping))
        elif "found" in raw:
            batches.append(raw)
    elif isinstance(raw, list):
        batches.extend(item for item in raw if isinstance(item, Mapping))

    accounts: list[SocialAccount] = []
    for batch in batches:
        username = _string(batch.get("username"))
        found = batch.get("found")
        if not isinstance(found, list):
            continue
        for item in found:
            if not isinstance(item, Mapping):
                continue
            service = _string(item.get("site")) or _string(item.get("service")) or "unknown"
            profile_url = _string(item.get("profile_url"))
            reliability = item.get("reliability", 0.75)
            confidence = float(reliability) if isinstance(reliability, (int, float)) else 0.75
            category = classify_service(
                service,
                url=profile_url,
                category_hint=item.get("category", ""),
            )
            accounts.append(
                SocialAccount(
                    service=service,
                    category=category,
                    status="FOUND",
                    source="Sherlock Social Mesh",
                    confidence=confidence,
                    username=username,
                    profile_url=profile_url,
                    evidence_urls=tuple(
                        url
                        for url in (profile_url, _string(item.get("probe_url")))
                        if url.startswith(("http://", "https://"))
                    ),
                    fields=dict(item),
                    origin="socialmesh.username",
                )
            )
    return accounts


def _dedupe_accounts(accounts: Iterable[SocialAccount]) -> list[SocialAccount]:
    merged: dict[str, SocialAccount] = {}
    for account in accounts:
        service_key = re.sub(r"[^a-z0-9]+", "", account.service.casefold())
        url_key = account.profile_url.casefold().rstrip("/")
        user_key = account.username.casefold()
        key = "|".join((service_key, url_key, user_key, account.status))
        existing = merged.get(key)
        if existing is None or account.confidence > existing.confidence:
            merged[key] = account
        elif existing:
            urls = tuple(dict.fromkeys((*existing.evidence_urls, *account.evidence_urls)))[:32]
            sources = " + ".join(dict.fromkeys((*existing.source.split(" + "), *account.source.split(" + "))))
            merged[key] = SocialAccount(
                service=existing.service,
                category=existing.category if existing.category != "OTHER" else account.category,
                status=existing.status,
                source=sources,
                confidence=max(existing.confidence, account.confidence),
                username=existing.username or account.username,
                profile_url=existing.profile_url or account.profile_url,
                evidence_urls=urls,
                fields=existing.fields or account.fields,
                origin=existing.origin,
            )
    return sorted(
        merged.values(),
        key=lambda item: (
            item.status != "FOUND",
            SOCIAL_CATEGORIES.index(item.category) if item.category in SOCIAL_CATEGORIES else 99,
            -item.confidence,
            item.service.casefold(),
        ),
    )


def build_social_graph(
    *,
    emailosint: object = None,
    sensor_payloads: object = None,
) -> dict[str, object]:
    accounts = _dedupe_accounts(
        [
            *_emailosint_accounts(emailosint),
            *_socialmesh_accounts(sensor_payloads),
        ]
    )
    account_dicts = [account.to_dict() for account in accounts]
    grouped = categorise_accounts(account_dicts)

    category_counts = {
        category: sum(1 for item in items if item.get("status") == "FOUND")
        for category, items in grouped.items()
    }
    status_counts = Counter(str(account.status) for account in accounts)

    nodes: list[dict[str, object]] = [
        {"id": "target", "type": "TARGET", "label": "badany trop"}
    ]
    edges: list[dict[str, object]] = []
    seen_nodes: set[str] = {"target"}

    for index, account in enumerate(accounts[:500]):
        service_id = "service:" + re.sub(r"[^a-z0-9]+", "-", account.service.casefold()).strip("-")
        if service_id not in seen_nodes:
            seen_nodes.add(service_id)
            nodes.append(
                {
                    "id": service_id,
                    "type": "SERVICE",
                    "label": account.service,
                    "category": account.category,
                }
            )
        edges.append(
            {
                "id": f"edge:{index}:target-service",
                "from": "target",
                "to": service_id,
                "type": "ACCOUNT_SIGNAL",
                "status": account.status,
                "confidence": account.confidence,
                "source": account.source,
            }
        )
        if account.username:
            username_id = "username:" + account.username.casefold()
            if username_id not in seen_nodes:
                seen_nodes.add(username_id)
                nodes.append(
                    {
                        "id": username_id,
                        "type": "USERNAME",
                        "label": account.username,
                    }
                )
            edges.append(
                {
                    "id": f"edge:{index}:service-username",
                    "from": service_id,
                    "to": username_id,
                    "type": "USES_USERNAME",
                    "status": account.status,
                    "confidence": account.confidence,
                    "source": account.source,
                }
            )

    return {
        "version": "v3",
        "accounts": account_dicts,
        "categories": grouped,
        "category_counts": category_counts,
        "status_counts": dict(sorted(status_counts.items())),
        "summary": {
            "signals_total": len(accounts),
            "found_total": sum(1 for account in accounts if account.status == "FOUND"),
            "google_found": category_counts.get("GOOGLE", 0),
            "social_found": category_counts.get("SOCIAL", 0),
            "dating_found": category_counts.get("DATING", 0),
            "messaging_found": category_counts.get("MESSAGING", 0),
        },
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "truth": {
            "found_requires_source_signal": True,
            "category_is_classification_not_identity_proof": True,
            "same_username_is_not_same_person": True,
            "raw_secret_values_exposed": False,
        },
    }
