from __future__ import annotations

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
    "html_url",
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
_STATUS_RANK = {
    "FOUND": 0,
    "OBSERVED": 1,
    "UNKNOWN": 2,
    "RATE_LIMITED": 3,
    "BLOCKED": 4,
    "NOT_FOUND": 5,
}


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
    return bool(_username(mapping) and classify_service(service) != "OTHER")


def _account_from_mapping(
    mapping: Mapping[str, Any],
    *,
    fallback_service: str = "",
    source: str,
    origin: str,
    confidence: float,
    forced_status: str | None = None,
    forced_username: str = "",
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
        status=forced_status or signal_presence_status(mapping),
        source=source,
        confidence=max(0.0, min(0.99, float(confidence))),
        username=_username(mapping) or forced_username,
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
                source_name = _string(signal.get("source")) or "EmailOSINT"
                if isinstance(base, Mapping):
                    account = _account_from_mapping(
                        base,
                        fallback_service=source_name,
                        source="EmailOSINT",
                        origin="emailosint.identity.signals",
                        confidence=0.96 if str(signal.get("status")) == "FOUND" else 0.72,
                        forced_status=str(signal.get("status")) if signal.get("status") else None,
                    )
                    if account:
                        accounts.append(account)

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
        accounts.extend(
            _walk_service_records(
                provider.get("raw"),
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
            accounts.append(
                SocialAccount(
                    service=service,
                    category=classify_service(
                        service,
                        url=profile_url,
                        category_hint=item.get("category", ""),
                    ),
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


def _direct_source_accounts(sensor_payloads: object) -> list[SocialAccount]:
    if not isinstance(sensor_payloads, Mapping):
        return []
    records = sensor_payloads.get("source_records")
    if not isinstance(records, list):
        return []

    accounts: list[SocialAccount] = []
    for record in records[:1000]:
        if not isinstance(record, Mapping):
            continue
        source = _string(record.get("source"))
        fields = record.get("fields")
        if not isinstance(fields, Mapping):
            continue
        confidence_raw = record.get("confidence", 0.72)
        confidence = float(confidence_raw) if isinstance(confidence_raw, (int, float)) else 0.72
        seed_username = _string(record.get("identifier_value")) if record.get("identifier_kind") == "USERNAME" else ""

        if source == "holehe.email":
            registered = fields.get("registered")
            if isinstance(registered, list):
                for item in registered[:256]:
                    if not isinstance(item, Mapping):
                        continue
                    account = _account_from_mapping(
                        item,
                        source="Holehe",
                        origin="holehe.registered",
                        confidence=max(0.75, confidence),
                        forced_status="FOUND",
                    )
                    if account:
                        accounts.append(account)
            continue

        if source == "maigret.username":
            profiles = fields.get("profiles")
            if isinstance(profiles, list):
                for item in profiles[:256]:
                    if not isinstance(item, Mapping):
                        continue
                    account = _account_from_mapping(
                        item,
                        fallback_service=_string(item.get("site")),
                        source="Maigret",
                        origin="maigret.profiles",
                        confidence=max(0.7, confidence),
                        forced_status="FOUND",
                        forced_username=seed_username,
                    )
                    if account:
                        accounts.append(account)
            continue

        if source in {"github.username", "gitlab.username"}:
            service = "GitHub" if source.startswith("github") else "GitLab"
            found = fields.get("found") is True
            profile = fields.get("profile")
            base = profile if isinstance(profile, Mapping) else fields
            account = _account_from_mapping(
                base,
                fallback_service=service,
                source=service,
                origin=source,
                confidence=confidence,
                forced_status="FOUND" if found else "NOT_FOUND",
                forced_username=seed_username,
            )
            if account:
                accounts.append(account)
            continue

        if source == "gravatar.email":
            if fields.get("found") is True:
                profile = fields.get("profile")
                if isinstance(profile, Mapping):
                    accounts.extend(
                        _walk_service_records(
                            profile,
                            source="Gravatar",
                            origin="gravatar.profile",
                            fallback_service="Gravatar",
                            confidence=confidence,
                            limit=128,
                        )
                    )
            continue

    return accounts


def _merge_two(left: SocialAccount, right: SocialAccount) -> SocialAccount:
    rank_left = _STATUS_RANK.get(left.status, 9)
    rank_right = _STATUS_RANK.get(right.status, 9)
    preferred = right if (rank_right, -right.confidence) < (rank_left, -left.confidence) else left
    secondary = left if preferred is right else right
    sources = " + ".join(
        dict.fromkeys((*preferred.source.split(" + "), *secondary.source.split(" + ")))
    )
    urls = tuple(dict.fromkeys((*preferred.evidence_urls, *secondary.evidence_urls)))[:32]
    return SocialAccount(
        service=preferred.service,
        category=preferred.category if preferred.category != "OTHER" else secondary.category,
        status=preferred.status,
        source=sources,
        confidence=max(left.confidence, right.confidence),
        username=preferred.username or secondary.username,
        profile_url=preferred.profile_url or secondary.profile_url,
        evidence_urls=urls,
        fields=preferred.fields or secondary.fields,
        origin=" + ".join(dict.fromkeys((preferred.origin, secondary.origin))),
    )


def _dedupe_accounts(accounts: Iterable[SocialAccount]) -> list[SocialAccount]:
    merged: dict[str, SocialAccount] = {}
    for account in accounts:
        service_key = re.sub(r"[^a-z0-9]+", "", account.service.casefold())
        user_key = account.username.casefold()
        url_key = account.profile_url.casefold().rstrip("/")
        identity_key = user_key or url_key or service_key
        key = "|".join((service_key, identity_key))
        existing = merged.get(key)
        merged[key] = account if existing is None else _merge_two(existing, account)
    return sorted(
        merged.values(),
        key=lambda item: (
            _STATUS_RANK.get(item.status, 9),
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
            *_direct_source_accounts(sensor_payloads),
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
        service_slug = re.sub(r"[^a-z0-9]+", "-", account.service.casefold()).strip("-") or str(index)
        service_id = "service:" + service_slug
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
                    {"id": username_id, "type": "USERNAME", "label": account.username}
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
        "version": "v3.1",
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
            "developer_found": category_counts.get("DEVELOPER", 0),
            "music_found": category_counts.get("MUSIC", 0),
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
            "direct_sources_merged": True,
            "raw_secret_values_exposed": False,
        },
    }
