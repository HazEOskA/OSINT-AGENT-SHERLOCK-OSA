from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


class TruthVerdict(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    OBSERVED = "OBSERVED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    UNRELIABLE = "UNRELIABLE"


_POSITIVE_KEYS = (
    "found",
    "exists",
    "registered",
    "account_exists",
    "present",
    "claimed",
    "taken",
    "breached",
)
_NEGATIVE_KEYS = (
    "missing",
    "not_found",
    "unclaimed",
)
_COUNT_KEYS = (
    "registered_count",
    "found_count",
    "capture_count",
    "domain_count",
    "breach_count",
)


def presence_verdict(
    fields: Mapping[str, Any] | object,
    *,
    event_name: str = "",
    explicit_container: str = "",
) -> TruthVerdict:
    """Classify source output without confusing transport success with truth."""

    if not isinstance(fields, Mapping):
        return TruthVerdict.OBSERVED

    explicit = str(fields.get("truth_verdict", "")).strip().upper()
    if explicit in TruthVerdict.__members__:
        return TruthVerdict[explicit]

    positives: list[str] = []
    negatives: list[str] = []
    for key in _POSITIVE_KEYS:
        value = fields.get(key)
        if value is True:
            positives.append(key)
        elif value is False:
            negatives.append(key)
    for key in _NEGATIVE_KEYS:
        value = fields.get(key)
        if value is True:
            negatives.append(key)
        elif value is False:
            positives.append(key)

    if positives and negatives:
        return TruthVerdict.UNKNOWN
    if positives:
        return TruthVerdict.FOUND
    if negatives:
        return TruthVerdict.NOT_FOUND

    for key in _COUNT_KEYS:
        value = fields.get(key)
        if isinstance(value, int):
            if value > 0:
                return TruthVerdict.FOUND
            if value == 0:
                return TruthVerdict.NOT_FOUND

    status = str(fields.get("status", "")).strip().upper()
    if status in TruthVerdict.__members__:
        return TruthVerdict[status]

    container = explicit_container.casefold()
    if container in {"linked_accounts", "accounts_found", "confirmed_accounts"}:
        return TruthVerdict.FOUND

    if event_name.casefold() in {"identifier_result", "account_result", "profile_result"}:
        for key in ("profile_url", "url", "web_url", "html_url"):
            value = fields.get(key)
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                return TruthVerdict.FOUND

    return TruthVerdict.OBSERVED


def positive_evidence(fields: Mapping[str, Any] | object) -> bool:
    return presence_verdict(fields) is TruthVerdict.FOUND


def confidence_for_presence(
    verdict: TruthVerdict | str,
    *,
    base: float,
    error_count: int = 0,
    rate_limited_count: int = 0,
    checked_count: int = 0,
) -> float:
    try:
        state = TruthVerdict(str(verdict))
    except ValueError:
        state = TruthVerdict.UNKNOWN

    if state is TruthVerdict.FOUND:
        score = base
    elif state is TruthVerdict.NOT_FOUND:
        score = min(base, 0.8)
    elif state in {TruthVerdict.BLOCKED, TruthVerdict.RATE_LIMITED, TruthVerdict.TIMEOUT}:
        score = 0.05
    elif state in {TruthVerdict.ERROR, TruthVerdict.UNRELIABLE}:
        score = 0.0
    else:
        score = min(base, 0.35)

    denominator = max(1, checked_count)
    degraded = min(0.5, (max(0, error_count) + max(0, rate_limited_count)) / denominator)
    return round(max(0.0, min(0.99, score * (1.0 - degraded))), 3)


def mechanism_key(module: str, url: str = "") -> str:
    """Collapse aggregators that report the same underlying public service."""

    family = module.split(".", 1)[0].casefold() if module else "unknown"
    aggregator_families = {"maigret", "socialmesh", "emailosint", "holehe"}
    if url:
        try:
            host = (urlsplit(url).hostname or "").casefold()
        except ValueError:
            host = ""
        if host:
            if host.startswith("www."):
                host = host[4:]
            if family in aggregator_families:
                return f"service:{host}"
            return f"{family}:{host}"
    return f"source:{family}"


def canary_username(seed: str) -> str:
    digest = hashlib.sha256(seed.casefold().encode("utf-8")).hexdigest()[:18]
    return f"osatruth{digest}"


_INTERSTITIAL_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("CLOUDFLARE", ("cf-chl-", "challenge-platform", "cloudflare ray id")),
    ("ANUBIS", ("anubis", "making sure you're not a bot", "proof-of-work")),
    ("AWS_WAF", ("awswaf", "aws waf", "request blocked")),
    ("PERIMETERX", ("perimeterx", "px-captcha", "human challenge")),
    ("DDOS_GUARD", ("ddos-guard", "checking your browser")),
    ("GENERIC_CAPTCHA", ("captcha", "verify you are human", "are you a robot")),
)


def detect_interstitial(body: str) -> str | None:
    text = body.casefold()
    for name, markers in _INTERSTITIAL_MARKERS:
        if any(marker in text for marker in markers):
            return name
    return None


def truth_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {state.value: 0 for state in TruthVerdict}
    for record in records:
        raw = str(record.get("verdict", record.get("status", "UNKNOWN"))).upper()
        try:
            state = TruthVerdict(raw)
        except ValueError:
            state = TruthVerdict.UNKNOWN
        counts[state.value] += 1
    return {key: value for key, value in counts.items() if value}
