from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.social_taxonomy import (
    NSFW_BUCKETS,
    SOCIAL_CATEGORIES,
    categorise_accounts,
    classify_sensitive_bucket,
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
    "UNRELIABLE": 3,
    "RATE_LIMITED": 4,
    "BLOCKED": 5,
    "TIMEOUT": 6,
    "ERROR": 7,
    "NOT_FOUND": 8,
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
        "truth_verdict",
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
    """Consume only normalized EmailOSINT identity signals.

    Provider raw payload is preserved elsewhere for audit/debugging but is not walked
    as account evidence. This prevents metadata, AI prose, breach URLs or generic
    profile-like objects from silently becoming social-account claims.
    """

    if not isinstance(emailosint, Mapping):
        return []
    accounts: list[SocialAccount] = []

    identity = emailosint.get("identity")
    if not isinstance(identity, Mapping):
        return accounts
    signals = identity.get("signals")
    if not isinstance(signals, list):
        return accounts

    for signal in signals:
        if not isinstance(signal, Mapping):
            continue
        status = str(signal.get("status", "OBSERVED")).upper()
        if status not in _STATUS_RANK:
            status = "UNKNOWN"
        fields = signal.get("fields")
        payload = signal.get("provider_payload")
        base = payload if isinstance(payload, Mapping) else fields if isinstance(fields, Mapping) else signal
        source_name = _string(signal.get("source")) or "EmailOSINT"
        if not isinstance(base, Mapping):
            continue
        account = _account_from_mapping(
            base,
            fallback_service=source_name,
            source="EmailOSINT",
            origin="emailosint.identity.signals.v4",
            confidence=0.96 if status == "FOUND" else 0.35 if status == "OBSERVED" else 0.1,
            forced_status=status,
        )
        if account:
            accounts.append(account)
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
                        is_nsfw=bool(item.get("is_nsfw", item.get("isNSFW", False))),
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
                    origin="socialmesh.username.truth-v4",
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
        truth_verdict = _string(fields.get("truth_verdict")).upper()
        if truth_verdict in {"UNRELIABLE", "ERROR", "BLOCKED", "RATE_LIMITED", "TIMEOUT"}:
            continue
        confidence_raw = record.get("confidence", 0.72)
        confidence = float(confidence_raw) if isinstance(confidence_raw, (int, float)) else 0.72
        seed_username = _string(record.get("identifier_value")) if record.get("identifier_kind") == "USERNAME" else ""

        if source == "holehe.email":
            if truth_verdict and truth_verdict != "FOUND":
                continue
            registered = fields.get("registered")
            if isinstance(registered, list):
                for item in registered[:256]:
                    if not isinstance(item, Mapping):
                        continue
                    account = _account_from_mapping(
                        item,
                        source="Holehe",
                        origin="holehe.registered.truth-v4",
                        confidence=confidence,
                        forced_status="FOUND",
                    )
                    if account:
                        accounts.append(account)
            continue

        if source == "maigret.username":
            if truth_verdict and truth_verdict != "FOUND":
                continue
            profiles = fields.get("profiles")
            if isinstance(profiles, list):
                for item in profiles[:256]:
                    if not isinstance(item, Mapping):
                        continue
                    account = _account_from_mapping(
                        item,
                        fallback_service=_string(item.get("site")),
                        source="Maigret",
                        origin="maigret.profiles.truth-v4",
                        confidence=confidence,
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
                            origin="gravatar.profile.truth-v4",
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


def _sensitive_intelligence(account_dicts: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    visible: list[dict[str, object]] = []
    sections: dict[str, list[dict[str, object]]] = {bucket: [] for bucket in NSFW_BUCKETS}

    for account in account_dicts:
        if account.get("category") != "ADULT" or account.get("status") == "NOT_FOUND":
            continue
        item = dict(account)
        bucket = classify_sensitive_bucket(
            item.get("service", "unknown"),
            url=item.get("profile_url", ""),
            origin=item.get("origin", ""),
        )
        urls = [
            url
            for url in [item.get("profile_url"), *(item.get("evidence_urls") or [])]
            if isinstance(url, str) and url.startswith(("http://", "https://"))
        ]
        status = str(item.get("status") or "OBSERVED")
        item["sensitive_bucket"] = bucket
        item["evidence_tier"] = (
            "DIRECT_PUBLIC_SIGNAL"
            if status == "FOUND" and bool(urls)
            else "SOURCE_SIGNAL"
            if status == "FOUND"
            else "OBSERVED_ONLY"
        )
        item["media_autoload"] = False
        visible.append(item)
        sections[bucket].append(item)

    status_counts = Counter(str(item.get("status") or "OBSERVED") for item in visible)
    direct_public = sum(
        1 for item in visible if item.get("evidence_tier") == "DIRECT_PUBLIC_SIGNAL"
    )
    found_total = int(status_counts.get("FOUND", 0))

    return {
        "version": "v1-truth-v4",
        "default_collapsed": True,
        "placement": "CASE_REPORT_BOTTOM",
        "media_autoload": False,
        "accounts": visible,
        "sections": sections,
        "summary": {
            "signals_total": len(visible),
            "found_total": found_total,
            "direct_public_profiles": direct_public,
            "observed_total": int(status_counts.get("OBSERVED", 0)),
            "blocked_total": int(status_counts.get("BLOCKED", 0)),
            "rate_limited_total": int(status_counts.get("RATE_LIMITED", 0)),
            "unreliable_total": int(status_counts.get("UNRELIABLE", 0)),
        },
        "truth": {
            "sensitive_category_is_not_identity_proof": True,
            "same_username_is_not_same_person": True,
            "found_requires_truth_verified_source_signal": True,
            "direct_public_profile_requires_url": True,
            "not_found_hidden_from_sensitive_ui": True,
            "explicit_media_autoload": False,
            "authenticated_sessions_used": False,
            "captcha_bypass_used": False,
        },
    }


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
    sensitive = _sensitive_intelligence(account_dicts)

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
        "version": "v4",
        "truth_engine": "SHERLOCK_TRUTH_ENGINE_V4",
        "accounts": account_dicts,
        "categories": grouped,
        "category_counts": category_counts,
        "status_counts": dict(sorted(status_counts.items())),
        "sensitive_intelligence": sensitive,
        "summary": {
            "signals_total": len(accounts),
            "found_total": sum(1 for account in accounts if account.status == "FOUND"),
            "google_found": category_counts.get("GOOGLE", 0),
            "social_found": category_counts.get("SOCIAL", 0),
            "dating_found": category_counts.get("DATING", 0),
            "messaging_found": category_counts.get("MESSAGING", 0),
            "developer_found": category_counts.get("DEVELOPER", 0),
            "music_found": category_counts.get("MUSIC", 0),
            "adult_found": category_counts.get("ADULT", 0),
        },
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "truth": {
            "found_requires_truth_verified_source_signal": True,
            "raw_provider_payload_is_account_evidence": False,
            "category_is_classification_not_identity_proof": True,
            "same_username_is_not_same_person": True,
            "direct_sources_merged": True,
            "raw_secret_values_exposed": False,
            "sensitive_layer_default_collapsed": True,
            "sensitive_media_autoload": False,
        },
    }
