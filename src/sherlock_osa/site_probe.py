from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.social_taxonomy import classify_service


WMN_COMMIT = "e62338e4fc88536a330733d355a9d33a3a1697c6"
SHERLOCK_DATA_COMMIT = "376018708c0f6948d3f978a9ae2915024e794654"
WMN_DATA_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
    f"{WMN_COMMIT}/wmn-data.json"
)
SHERLOCK_DATA_URL = (
    "https://raw.githubusercontent.com/sherlock-project/sherlock/"
    f"{SHERLOCK_DATA_COMMIT}/sherlock_project/resources/data.json"
)
USER_AGENT = "Sherlock-OSA-Social-Mesh/3.0 (+public-source-probe)"
MAX_DATASET_BYTES = 5_000_000
MAX_RESPONSE_BYTES = 300_000
MAX_RESULTS = 600


class ProbeVerdict(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    INVALID = "INVALID"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"
    UNRELIABLE = "UNRELIABLE"


@dataclass(frozen=True, slots=True)
class SiteDefinition:
    name: str
    source: str
    category: str
    url_check: str
    url_pretty: str
    method: str = "GET"
    username_regex: str | None = None
    exists_code: int | None = None
    missing_code: int | None = None
    exists_text: str = ""
    missing_text: str = ""
    error_type: str = ""
    strip_bad_char: str = ""
    protection: tuple[str, ...] = ()
    known_positive: str = ""
    known_negative: str = ""
    is_nsfw: bool = False
    attribution: tuple[str, ...] = ()
    dataset_commit: str = ""

    @property
    def host(self) -> str:
        try:
            return (urlsplit(self.url_pretty or self.url_check).hostname or "").casefold()
        except ValueError:
            return ""

    @property
    def stable_key(self) -> str:
        host = self.host or re.sub(r"[^a-z0-9]+", "-", self.name.casefold()).strip("-")
        return f"{host}|{self.name.casefold()}"

    @property
    def public_get_safe(self) -> bool:
        if self.method.upper() not in {"GET", "HEAD"}:
            return False
        blocked = {"captcha", "user-auth", "anubis", "ddos-guard", "multiple"}
        return not blocked.intersection({item.casefold() for item in self.protection})

    @property
    def base_reliability(self) -> float:
        if not self.public_get_safe:
            return 0.0
        if self.exists_code is not None and self.missing_code is not None and self.exists_code != self.missing_code:
            return 0.96
        if self.exists_text and self.missing_text:
            return 0.94
        if self.missing_text and self.error_type in {"message", "status_code"}:
            return 0.84
        if self.missing_code is not None or self.exists_code is not None:
            return 0.82
        if self.error_type == "response_url":
            return 0.68
        return 0.45


@dataclass(frozen=True, slots=True)
class ProbeResult:
    site: str
    category: str
    verdict: ProbeVerdict
    profile_url: str
    probe_url: str
    source: str
    http_status: int | None
    response_ms: int
    reliability: float
    reason: str
    dataset_commit: str
    attribution: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "site": self.site,
            "category": self.category,
            "verdict": self.verdict.value,
            "profile_url": self.profile_url,
            "probe_url": self.probe_url,
            "source": self.source,
            "http_status": self.http_status,
            "response_ms": self.response_ms,
            "reliability": self.reliability,
            "reason": self.reason,
            "dataset_commit": self.dataset_commit,
            "attribution": list(self.attribution),
        }


@dataclass(frozen=True, slots=True)
class ProbeBatch:
    username: str
    mode: str
    results: tuple[ProbeResult, ...]
    definitions_total: int
    definitions_eligible: int
    duration_ms: int
    datasets: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        found = []
        for result in self.results:
            counts[result.verdict.value] = counts.get(result.verdict.value, 0) + 1
            if result.verdict is ProbeVerdict.FOUND:
                category_counts[result.category] = category_counts.get(result.category, 0) + 1
                found.append(result.to_dict())
        return {
            "username": self.username,
            "mode": self.mode,
            "definitions_total": self.definitions_total,
            "definitions_eligible": self.definitions_eligible,
            "probed": len(self.results),
            "found": found,
            "counts": dict(sorted(counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "duration_ms": self.duration_ms,
            "datasets": list(self.datasets),
            "truth": {
                "public_only": True,
                "cookies_used": False,
                "authenticated_sessions_used": False,
                "proxy_rotation": False,
                "captcha_bypass": False,
                "post_probe_side_effect_guard": True,
                "unknown_is_not_found": False,
            },
        }


def _fetch_json(url: str, timeout_seconds: float) -> Any:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=max(1.0, min(timeout_seconds, 15.0))) as response:
        raw = response.read(MAX_DATASET_BYTES + 1)
    if len(raw) > MAX_DATASET_BYTES:
        raise RuntimeError("dataset payload too large")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("dataset returned invalid JSON") from exc


def _safe_url_template(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if len(candidate) > 4096 or "{account}" not in candidate and "{}" not in candidate:
        return ""
    try:
        parsed = urlsplit(candidate.replace("{account}", "testuser").replace("{}", "testuser"))
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return candidate


def _safe_pretty(value: object, fallback: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    candidate = value.strip()
    if len(candidate) > 4096:
        return fallback
    return candidate


def parse_wmn(data: object) -> list[SiteDefinition]:
    if not isinstance(data, Mapping):
        return []
    raw_sites = data.get("sites")
    if not isinstance(raw_sites, list):
        return []

    definitions: list[SiteDefinition] = []
    for row in raw_sites:
        if not isinstance(row, Mapping) or row.get("valid") is False:
            continue
        name = str(row.get("name", "")).strip()
        url_check = _safe_url_template(row.get("uri_check"))
        if not name or not url_check:
            continue
        url_pretty = _safe_pretty(row.get("uri_pretty"), url_check)
        post_body = row.get("post_body")
        method = "POST" if isinstance(post_body, str) and post_body else "GET"
        known = row.get("known")
        known_positive = ""
        if isinstance(known, list):
            known_positive = next((str(item) for item in known if isinstance(item, str) and item), "")

        category_hint = str(row.get("cat", ""))
        protection_raw = row.get("protection", [])
        protection = tuple(
            str(item)
            for item in protection_raw
            if isinstance(item, str)
        ) if isinstance(protection_raw, list) else ()

        definitions.append(
            SiteDefinition(
                name=name,
                source="WhatsMyName",
                category=classify_service(
                    name,
                    url=url_pretty,
                    category_hint=category_hint,
                    is_nsfw=category_hint.casefold() == "xx nsfw xx",
                ),
                url_check=url_check,
                url_pretty=url_pretty,
                method=method,
                username_regex=None,
                exists_code=int(row["e_code"]) if isinstance(row.get("e_code"), int) else None,
                missing_code=int(row["m_code"]) if isinstance(row.get("m_code"), int) else None,
                exists_text=str(row.get("e_string", "") or ""),
                missing_text=str(row.get("m_string", "") or ""),
                error_type="wmn",
                strip_bad_char=str(row.get("strip_bad_char", "") or ""),
                protection=protection,
                known_positive=known_positive,
                known_negative="",
                is_nsfw=category_hint.casefold() == "xx nsfw xx",
                attribution=(
                    "WebBreacher/WhatsMyName",
                    "CC BY-SA 4.0 dataset; definitions fetched at runtime",
                ),
                dataset_commit=WMN_COMMIT,
            )
        )
    return definitions


def parse_sherlock(data: object) -> list[SiteDefinition]:
    if not isinstance(data, Mapping):
        return []

    definitions: list[SiteDefinition] = []
    for name, row in data.items():
        if str(name).startswith("$") or not isinstance(row, Mapping):
            continue
        url_profile = _safe_url_template(row.get("url"))
        url_probe = _safe_url_template(row.get("urlProbe")) or url_profile
        if not url_profile or not url_probe:
            continue

        method = str(row.get("request_method", "GET") or "GET").upper()
        error_type = str(row.get("errorType", "") or "").casefold()
        error_code = row.get("errorCode")
        missing_code = int(error_code) if isinstance(error_code, int) else (404 if error_type == "status_code" else None)
        exists_code = None
        if error_type == "status_code" and missing_code != 200:
            exists_code = 200

        definitions.append(
            SiteDefinition(
                name=str(name),
                source="Sherlock Project",
                category=classify_service(
                    str(name),
                    url=url_profile,
                    is_nsfw=bool(row.get("isNSFW", False)),
                ),
                url_check=url_probe,
                url_pretty=url_profile,
                method=method,
                username_regex=(
                    str(row.get("regexCheck"))
                    if isinstance(row.get("regexCheck"), str)
                    else None
                ),
                exists_code=exists_code,
                missing_code=missing_code,
                exists_text="",
                missing_text=str(row.get("errorMsg", "") or ""),
                error_type=error_type,
                strip_bad_char="",
                protection=(),
                known_positive=str(row.get("username_claimed", "") or ""),
                known_negative=str(row.get("username_unclaimed", "") or ""),
                is_nsfw=bool(row.get("isNSFW", False)),
                attribution=(
                    "sherlock-project/sherlock",
                    "MIT; site definitions fetched at runtime",
                ),
                dataset_commit=SHERLOCK_DATA_COMMIT,
            )
        )
    return definitions


def _merge_definition(primary: SiteDefinition, secondary: SiteDefinition) -> SiteDefinition:
    # Prefer WMN category/protection metadata and explicit positive+negative rules,
    # but borrow a missing regex/canary from Sherlock when the same site is represented.
    if primary.source != "WhatsMyName" and secondary.source == "WhatsMyName":
        primary, secondary = secondary, primary
    return SiteDefinition(
        name=primary.name,
        source=" + ".join(dict.fromkeys((primary.source, secondary.source))),
        category=primary.category if primary.category != "OTHER" else secondary.category,
        url_check=primary.url_check,
        url_pretty=primary.url_pretty,
        method=primary.method,
        username_regex=primary.username_regex or secondary.username_regex,
        exists_code=primary.exists_code if primary.exists_code is not None else secondary.exists_code,
        missing_code=primary.missing_code if primary.missing_code is not None else secondary.missing_code,
        exists_text=primary.exists_text or secondary.exists_text,
        missing_text=primary.missing_text or secondary.missing_text,
        error_type=primary.error_type or secondary.error_type,
        strip_bad_char=primary.strip_bad_char or secondary.strip_bad_char,
        protection=tuple(dict.fromkeys((*primary.protection, *secondary.protection))),
        known_positive=primary.known_positive or secondary.known_positive,
        known_negative=primary.known_negative or secondary.known_negative,
        is_nsfw=primary.is_nsfw or secondary.is_nsfw,
        attribution=tuple(dict.fromkeys((*primary.attribution, *secondary.attribution))),
        dataset_commit=f"{primary.dataset_commit}+{secondary.dataset_commit}",
    )


def merge_definitions(*groups: Sequence[SiteDefinition]) -> list[SiteDefinition]:
    merged: dict[str, SiteDefinition] = {}
    by_host: dict[str, str] = {}
    for definition in (item for group in groups for item in group):
        key = definition.stable_key
        host = definition.host
        existing_key = by_host.get(host) if host else None
        if key in merged:
            merged[key] = _merge_definition(merged[key], definition)
        elif existing_key and existing_key in merged:
            merged[existing_key] = _merge_definition(merged[existing_key], definition)
        else:
            merged[key] = definition
            if host:
                by_host[host] = key
    return list(merged.values())


def load_site_definitions(timeout_seconds: float = 12.0) -> tuple[list[SiteDefinition], tuple[dict[str, object], ...]]:
    datasets: list[dict[str, object]] = []
    groups: list[list[SiteDefinition]] = []

    for name, url, commit, parser, license_note in (
        (
            "WhatsMyName",
            WMN_DATA_URL,
            WMN_COMMIT,
            parse_wmn,
            "CC BY-SA 4.0; runtime reference, not vendored",
        ),
        (
            "Sherlock Project",
            SHERLOCK_DATA_URL,
            SHERLOCK_DATA_COMMIT,
            parse_sherlock,
            "MIT; runtime reference, not vendored",
        ),
    ):
        started = time.monotonic()
        try:
            payload = _fetch_json(url, timeout_seconds)
            definitions = parser(payload)
            groups.append(definitions)
            datasets.append(
                {
                    "name": name,
                    "commit": commit,
                    "url": url,
                    "definitions": len(definitions),
                    "status": "LOADED",
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "license": license_note,
                }
            )
        except Exception as exc:
            datasets.append(
                {
                    "name": name,
                    "commit": commit,
                    "url": url,
                    "definitions": 0,
                    "status": "ERROR",
                    "error": type(exc).__name__,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "license": license_note,
                }
            )

    return merge_definitions(*groups), tuple(datasets)


def _render(template: str, username: str) -> str:
    quoted = urllib.parse.quote(username, safe="-._~")
    if "{account}" in template:
        return template.replace("{account}", quoted)
    return template.replace("{}", quoted)


def _request_once(url: str, timeout_seconds: float) -> tuple[int | None, str, str, int, str]:
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=max(1.0, min(timeout_seconds, 8.0)),
        ) as response:
            status = int(getattr(response, "status", 200))
            final_url = str(response.geturl())
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        final_url = str(exc.geturl())
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
        duration = int((time.monotonic() - started) * 1000)
        if isinstance(getattr(exc, "reason", None), socket.timeout) or isinstance(exc, (TimeoutError, socket.timeout)):
            return None, "", "", duration, "TIMEOUT"
        return None, "", "", duration, "NETWORK_ERROR"

    if len(raw) > MAX_RESPONSE_BYTES:
        raw = raw[:MAX_RESPONSE_BYTES]
    body = raw.decode("utf-8", errors="replace")
    duration = int((time.monotonic() - started) * 1000)
    return status, final_url, body, duration, "OK"


def _evaluate(definition: SiteDefinition, status: int | None, final_url: str, body: str) -> tuple[ProbeVerdict, str]:
    if status is None:
        return ProbeVerdict.ERROR, "NO_HTTP_STATUS"
    if status == 429:
        return ProbeVerdict.RATE_LIMITED, "HTTP_429"
    if status in {401, 407}:
        return ProbeVerdict.BLOCKED, f"HTTP_{status}_AUTH_REQUIRED"
    if status == 403:
        return ProbeVerdict.BLOCKED, "HTTP_403"
    if 500 <= status <= 599:
        return ProbeVerdict.ERROR, f"HTTP_{status}"

    exists_text = definition.exists_text
    missing_text = definition.missing_text
    has_exists = bool(exists_text and exists_text in body)
    has_missing = bool(missing_text and missing_text in body)

    if has_exists and not has_missing:
        return ProbeVerdict.FOUND, "POSITIVE_SIGNATURE"
    if has_missing and not has_exists:
        return ProbeVerdict.NOT_FOUND, "NEGATIVE_SIGNATURE"
    if has_exists and has_missing:
        return ProbeVerdict.UNKNOWN, "CONFLICTING_SIGNATURES"

    if definition.exists_code is not None and status == definition.exists_code:
        if definition.missing_code is None or status != definition.missing_code:
            return ProbeVerdict.FOUND, "POSITIVE_STATUS"
    if definition.missing_code is not None and status == definition.missing_code:
        if definition.exists_code is None or status != definition.exists_code:
            return ProbeVerdict.NOT_FOUND, "NEGATIVE_STATUS"

    if definition.error_type == "message":
        if 200 <= status < 400 and missing_text and missing_text not in body:
            return ProbeVerdict.FOUND, "MESSAGE_ABSENT_ON_SUCCESS"
    elif definition.error_type == "status_code":
        if 200 <= status < 400:
            return ProbeVerdict.FOUND, "STATUS_SUCCESS"
    elif definition.error_type == "response_url":
        expected_host = urlsplit(_render(definition.url_pretty, "osa-check")).hostname
        final_host = urlsplit(final_url).hostname if final_url else None
        if expected_host and final_host == expected_host and 200 <= status < 400:
            return ProbeVerdict.UNKNOWN, "RESPONSE_URL_NEEDS_SITE_SPECIFIC_RULE"

    return ProbeVerdict.UNKNOWN, "INSUFFICIENT_SIGNAL"


def _valid_username(definition: SiteDefinition, username: str) -> tuple[bool, str]:
    transformed = username
    if definition.strip_bad_char:
        transformed = transformed.translate(str.maketrans("", "", definition.strip_bad_char))
    if not transformed:
        return False, transformed
    if definition.username_regex:
        try:
            if re.fullmatch(definition.username_regex, transformed) is None:
                return False, transformed
        except re.error:
            return False, transformed
    return True, transformed


def _canary_verdict(definition: SiteDefinition, username: str, timeout_seconds: float) -> ProbeVerdict:
    valid, transformed = _valid_username(definition, username)
    if not valid:
        return ProbeVerdict.INVALID
    status, final_url, body, _duration, network_state = _request_once(
        _render(definition.url_check, transformed),
        timeout_seconds,
    )
    if network_state == "TIMEOUT":
        return ProbeVerdict.TIMEOUT
    if network_state != "OK":
        return ProbeVerdict.ERROR
    verdict, _ = _evaluate(definition, status, final_url, body)
    return verdict


def _probe_one(definition: SiteDefinition, username: str, timeout_seconds: float) -> ProbeResult:
    valid, transformed = _valid_username(definition, username)
    profile_url = _render(definition.url_pretty, transformed or username)
    probe_url = _render(definition.url_check, transformed or username)

    if not valid:
        return ProbeResult(
            site=definition.name,
            category=definition.category,
            verdict=ProbeVerdict.INVALID,
            profile_url=profile_url,
            probe_url=probe_url,
            source=definition.source,
            http_status=None,
            response_ms=0,
            reliability=0.0,
            reason="USERNAME_REGEX_REJECTED",
            dataset_commit=definition.dataset_commit,
            attribution=definition.attribution,
        )

    if not definition.public_get_safe:
        reason = "SIDE_EFFECT_GUARD" if definition.method.upper() not in {"GET", "HEAD"} else "ANTI_AUTOMATION_OR_AUTH_PROTECTION"
        return ProbeResult(
            site=definition.name,
            category=definition.category,
            verdict=ProbeVerdict.SKIPPED,
            profile_url=profile_url,
            probe_url=probe_url,
            source=definition.source,
            http_status=None,
            response_ms=0,
            reliability=0.0,
            reason=reason,
            dataset_commit=definition.dataset_commit,
            attribution=definition.attribution,
        )

    status, final_url, body, duration_ms, network_state = _request_once(probe_url, timeout_seconds)
    if network_state == "TIMEOUT":
        verdict, reason = ProbeVerdict.TIMEOUT, "NETWORK_TIMEOUT"
    elif network_state != "OK":
        verdict, reason = ProbeVerdict.ERROR, network_state
    else:
        verdict, reason = _evaluate(definition, status, final_url, body)

    reliability = definition.base_reliability

    # Automatic quarantine for medium-confidence positive detectors when the
    # upstream dataset supplies both known-positive and known-negative fixtures.
    # This mirrors the strongest pattern from mature username-enumeration tools:
    # verify the detector itself instead of trusting HTTP 200 blindly.
    if (
        verdict is ProbeVerdict.FOUND
        and reliability < 0.9
        and definition.known_positive
        and definition.known_negative
    ):
        canary_timeout = max(1.0, min(timeout_seconds / 3.0, 3.0))
        positive = _canary_verdict(definition, definition.known_positive, canary_timeout)
        negative = _canary_verdict(definition, definition.known_negative, canary_timeout)
        if positive is not ProbeVerdict.FOUND or negative is not ProbeVerdict.NOT_FOUND:
            verdict = ProbeVerdict.UNRELIABLE
            reason = f"CANARY_FAILED:{positive.value}/{negative.value}"
            reliability = min(reliability, 0.25)
        else:
            reliability = min(0.97, reliability + 0.08)
            reason = f"{reason}+CANARY_PASS"

    return ProbeResult(
        site=definition.name,
        category=definition.category,
        verdict=verdict,
        profile_url=profile_url,
        probe_url=probe_url,
        source=definition.source,
        http_status=status,
        response_ms=duration_ms,
        reliability=round(reliability, 3),
        reason=reason,
        dataset_commit=definition.dataset_commit,
        attribution=definition.attribution,
    )


def _priority(definition: SiteDefinition) -> tuple[int, float, str]:
    category_order = {
        "GOOGLE": 0,
        "DATING": 1,
        "SOCIAL": 2,
        "MESSAGING": 3,
        "DEVELOPER": 4,
        "GAMING": 5,
        "MUSIC": 6,
        "VIDEO": 7,
        "SHOPPING": 8,
        "FINANCE": 9,
        "FORUMS": 10,
        "OTHER": 11,
        "ADULT": 12,
    }
    return (
        category_order.get(definition.category, 99),
        -definition.base_reliability,
        definition.name.casefold(),
    )


def _mode_cap(mode: str) -> int:
    return {"QUICK": 160, "DEEP": 460, "MAX": 1200}.get(mode.upper(), 460)


def run_username_probe(
    username: str,
    *,
    mode: str = "MAX",
    timeout_seconds: float = 50.0,
    concurrency: int = 48,
) -> ProbeBatch:
    started = time.monotonic()
    username = username.strip()
    if not username or len(username) > 128 or any(ch.isspace() for ch in username):
        raise ValueError("invalid username")

    definitions, datasets = load_site_definitions(timeout_seconds=min(12.0, timeout_seconds / 4.0))
    ordered = sorted(definitions, key=_priority)
    selected = ordered[: _mode_cap(mode)]
    results: list[ProbeResult] = []

    elapsed = time.monotonic() - started
    remaining = max(1.0, timeout_seconds - elapsed)
    deadline = time.monotonic() + remaining

    with ThreadPoolExecutor(max_workers=max(4, min(concurrency, 64))) as pool:
        futures: dict[Future[ProbeResult], SiteDefinition] = {}
        for definition in selected:
            if time.monotonic() >= deadline:
                break
            per_request = max(1.0, min(7.0, deadline - time.monotonic()))
            futures[pool.submit(_probe_one, definition, username, per_request)] = definition

        try:
            for future in as_completed(futures, timeout=max(1.0, deadline - time.monotonic())):
                if time.monotonic() >= deadline:
                    break
                try:
                    results.append(future.result())
                except Exception as exc:
                    definition = futures[future]
                    results.append(
                        ProbeResult(
                            site=definition.name,
                            category=definition.category,
                            verdict=ProbeVerdict.ERROR,
                            profile_url=_render(definition.url_pretty, username),
                            probe_url=_render(definition.url_check, username),
                            source=definition.source,
                            http_status=None,
                            response_ms=0,
                            reliability=0.0,
                            reason=f"WORKER:{type(exc).__name__}",
                            dataset_commit=definition.dataset_commit,
                            attribution=definition.attribution,
                        )
                    )
                if len(results) >= MAX_RESULTS:
                    break
        except TimeoutError:
            pass

        for future in futures:
            if not future.done():
                future.cancel()

    results.sort(
        key=lambda item: (
            item.verdict is not ProbeVerdict.FOUND,
            item.category,
            -item.reliability,
            item.site.casefold(),
        )
    )
    return ProbeBatch(
        username=username,
        mode=mode.upper(),
        results=tuple(results[:MAX_RESULTS]),
        definitions_total=len(definitions),
        definitions_eligible=len(selected),
        duration_ms=int((time.monotonic() - started) * 1000),
        datasets=datasets,
    )
