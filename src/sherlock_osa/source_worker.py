from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from importlib.resources import files
from typing import Any, Mapping
from urllib.parse import urlsplit

from sherlock_osa.source_pack import WORKER_PROTOCOL


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,253}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
PHONE_RE = re.compile(r"^\+[1-9][0-9]{7,14}$")
MAX_HTTP_BYTES = 2_000_000
USER_AGENT = "sherlock-osa/0.4.0"


def _jsonable(value: object, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[TRUNCATED_DEPTH]"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value if not isinstance(value, str) else value[:2000]
    if isinstance(value, Mapping):
        return {
            str(key)[:120]: _jsonable(item, depth=depth + 1)
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item, depth=depth + 1) for item in list(value)[:64]]
    return str(value)[:2000]


def _candidate_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str)]
    return []


def _valid_domain(value: str) -> str | None:
    normalized = value.strip().rstrip(".").casefold()
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if not DOMAIN_RE.fullmatch(normalized):
        return None
    return normalized


def _valid_url(value: str) -> str | None:
    candidate = value.strip()
    if len(candidate) > 2048:
        return None
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return candidate


def _valid_phone(value: str) -> str | None:
    raw = value.strip()
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    if not raw.startswith("+"):
        return None
    digits = re.sub(r"\D", "", raw)
    normalized = "+" + digits
    if not PHONE_RE.fullmatch(normalized):
        return None
    return normalized


def _extract_pivots(ids_data: object) -> list[dict[str, str]]:
    pivots: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        normalized = value.strip()
        if kind == "EMAIL":
            normalized = normalized.casefold()
            if len(normalized) > 320 or not EMAIL_RE.fullmatch(normalized):
                return
        elif kind == "PHONE":
            valid_phone = _valid_phone(normalized)
            if valid_phone is None:
                return
            normalized = valid_phone
        elif kind == "USERNAME":
            if not USERNAME_RE.fullmatch(normalized):
                return
        elif kind == "URL":
            valid = _valid_url(normalized)
            if valid is None:
                return
            normalized = valid
        elif kind == "DOMAIN":
            valid_domain = _valid_domain(normalized)
            if valid_domain is None:
                return
            normalized = valid_domain
        key = (kind, normalized.casefold())
        if key in seen:
            return
        seen.add(key)
        pivots.append({"kind": kind, "value": normalized})

    def walk(value: object, parent_key: str = "", depth: int = 0) -> None:
        if depth > 4 or len(pivots) >= 96:
            return
        if isinstance(value, Mapping):
            for key, item in list(value.items())[:64]:
                key_text = str(key).casefold()
                values = _candidate_values(item)
                if key_text in {"email", "emails", "mail", "mails", "public_email"}:
                    for candidate in values:
                        add("EMAIL", candidate)
                elif key_text in {"phone", "phones", "telephone", "mobile"}:
                    for candidate in values:
                        add("PHONE", candidate)
                elif key_text in {
                    "username",
                    "usernames",
                    "nickname",
                    "nick",
                    "handle",
                    "handles",
                    "twitter_username",
                }:
                    for candidate in values:
                        add("USERNAME", candidate)
                elif key_text in {
                    "url",
                    "urls",
                    "website",
                    "websites",
                    "website_url",
                    "link",
                    "links",
                    "profile_url",
                    "web_url",
                    "html_url",
                }:
                    for candidate in values:
                        add("URL", candidate)
                elif key_text in {"domain", "domains", "host", "hostname"}:
                    for candidate in values:
                        add("DOMAIN", candidate)
                else:
                    walk(item, key_text, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in list(value)[:64]:
                walk(item, parent_key, depth + 1)

    walk(ids_data)
    return pivots[:96]


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(65_536)
    if not raw:
        raise ValueError("empty request")
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("protocol") != WORKER_PROTOCOL:
        raise ValueError("protocol mismatch")
    value = data.get("value")
    kind = data.get("kind")
    timeout = data.get("timeout_seconds", 30)
    if not isinstance(value, str) or not isinstance(kind, str):
        raise ValueError("invalid identifier")
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid timeout") from exc
    data["timeout_seconds"] = max(1.0, min(timeout_value, 60.0))
    return data


def _request_headers(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    if extra:
        headers.update({str(k): str(v) for k, v in extra.items() if str(v)})
    return headers


def _http_bytes_response(
    url: str,
    timeout_seconds: float,
    *,
    headers: Mapping[str, str] | None = None,
    allow_status: frozenset[int] = frozenset(),
) -> tuple[int, bytes, str]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers=_request_headers(headers),
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=max(1.0, min(timeout_seconds, 30.0)),
        ) as response:
            status = int(getattr(response, "status", 200))
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_HTTP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in allow_status:
            exc.read(2048)
            return exc.code, b"", exc.headers.get("Content-Type", "")
        exc.read(2048)
        raise RuntimeError(f"source HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"source unavailable: {exc}") from exc

    if len(raw) > MAX_HTTP_BYTES:
        raise RuntimeError("source response too large")
    return status, raw, content_type


def _http_json_response(
    url: str,
    timeout_seconds: float,
    *,
    headers: Mapping[str, str] | None = None,
    allow_status: frozenset[int] = frozenset(),
) -> tuple[int, object | None]:
    status, raw, content_type = _http_bytes_response(
        url,
        timeout_seconds,
        headers=headers,
        allow_status=allow_status,
    )
    if status in allow_status and not raw:
        return status, None
    if "json" not in content_type.casefold() and not raw.lstrip().startswith((b"[", b"{")):
        raise RuntimeError("source did not return JSON")
    try:
        return status, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("source returned invalid JSON") from exc


def _http_json(
    url: str,
    timeout_seconds: float,
    *,
    headers: Mapping[str, str] | None = None,
) -> object:
    _, payload = _http_json_response(url, timeout_seconds, headers=headers)
    if payload is None:
        raise RuntimeError("source returned no JSON")
    return payload


def _http_text_response(
    url: str,
    timeout_seconds: float,
    *,
    headers: Mapping[str, str] | None = None,
    allow_status: frozenset[int] = frozenset(),
) -> tuple[int, str]:
    status, raw, _ = _http_bytes_response(
        url,
        timeout_seconds,
        headers=headers,
        allow_status=allow_status,
    )
    return status, raw.decode("utf-8", errors="replace")


def _holehe_lookup(email: str, timeout_seconds: float) -> dict[str, object]:
    import httpx
    import trio
    from holehe.core import get_functions, import_submodules, launch_module

    if not EMAIL_RE.fullmatch(email.strip()):
        raise ValueError("holehe requires valid EMAIL")

    class Args:
        nopasswordrecovery = True

    modules = import_submodules("holehe.modules")
    websites = get_functions(modules, Args())

    async def runner() -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        client = httpx.AsyncClient(timeout=max(1.0, min(timeout_seconds, 20.0)))
        try:
            async with trio.open_nursery() as nursery:
                for website in websites:
                    nursery.start_soon(launch_module, website, email, client, output)
        finally:
            await client.aclose()
        return output

    output = trio.run(runner)
    registered: list[dict[str, object]] = []
    rate_limited = 0
    errors = 0
    for result in output:
        if not isinstance(result, Mapping):
            continue
        if bool(result.get("rateLimit")):
            rate_limited += 1
        if bool(result.get("error")):
            errors += 1
        if result.get("exists") is True:
            domain = str(result.get("domain", ""))[:253]
            registered.append(
                {
                    "service": str(result.get("name", ""))[:120],
                    "domain": domain,
                    "profile_url": f"https://{domain}" if _valid_domain(domain) else "",
                }
            )
    registered = registered[:128]
    source_urls = [
        str(item["profile_url"])
        for item in registered
        if isinstance(item.get("profile_url"), str) and item["profile_url"]
    ][:64]
    pivots = [
        {"kind": "DOMAIN", "value": str(item["domain"])}
        for item in registered
        if isinstance(item.get("domain"), str) and _valid_domain(str(item["domain"]))
    ][:64]
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "holehe",
            "checked": len(output),
            "registered_count": len(registered),
            "registered": registered,
            "rate_limited_count": rate_limited,
            "error_count": errors,
            "recovery_fields_retained": False,
        },
        "pivots": pivots,
        "source_urls": source_urls,
        "confidence": 0.9 if output else 0.0,
    }


async def _maigret_lookup(username: str, timeout_seconds: float) -> dict[str, object]:
    from maigret import search as maigret_search
    from maigret.sites import MaigretDatabase

    if not USERNAME_RE.fullmatch(username):
        raise ValueError("maigret requires valid USERNAME")

    resource = files("maigret").joinpath("resources").joinpath("data.json")
    database = MaigretDatabase().load_from_path(str(resource))
    sites = database.ranked_sites_dict(top=500)
    logger = logging.getLogger("sherlock.maigret")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False

    results = await maigret_search(
        username=username,
        site_dict=sites,
        logger=logger,
        timeout=max(1, min(int(timeout_seconds), 30)),
        is_parsing_enabled=True,
        max_connections=100,
        no_progressbar=True,
        retries=0,
        check_domains=False,
    )

    found: list[dict[str, object]] = []
    pivots: list[dict[str, str]] = []
    source_urls: list[str] = []
    for site_name, result in results.items():
        if not isinstance(result, Mapping):
            continue
        status = result.get("status")
        try:
            is_found = bool(status.is_found())
        except Exception:
            is_found = False
        if not is_found:
            continue
        url = result.get("url_user")
        url_text = str(url) if isinstance(url, str) else ""
        ids_data = result.get("ids_data")
        record = {
            "site": str(site_name)[:120],
            "username": username,
            "url": url_text[:2048],
            "http_status": _jsonable(result.get("http_status")),
            "rank": _jsonable(result.get("rank")),
            "ids_data": _jsonable(ids_data),
        }
        found.append(record)
        valid_url = _valid_url(url_text)
        if valid_url:
            source_urls.append(valid_url)
            pivots.append({"kind": "URL", "value": valid_url})
        pivots.extend(_extract_pivots(ids_data))
        if len(found) >= 75:
            break

    deduped_pivots: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pivot in pivots:
        key = (pivot["kind"], pivot["value"].casefold())
        if key in seen:
            continue
        seen.add(key)
        deduped_pivots.append(pivot)
        if len(deduped_pivots) >= 96:
            break

    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "maigret",
            "sites_considered": len(sites),
            "found_count": len(found),
            "profiles": found,
            "parsing_enabled": True,
        },
        "pivots": deduped_pivots,
        "source_urls": source_urls[:96],
        "confidence": min(0.99, 0.55 + 0.02 * len(found)) if found else 0.2,
    }


def _gravatar_lookup(email: str, timeout_seconds: float) -> dict[str, object]:
    normalized = email.strip().casefold()
    if not EMAIL_RE.fullmatch(normalized):
        raise ValueError("gravatar requires valid EMAIL")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    endpoint = f"https://api.gravatar.com/v3/profiles/{digest}"
    headers: dict[str, str] = {}
    api_key = os.getenv("GRAVATAR_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    status, payload = _http_json_response(
        endpoint,
        timeout_seconds,
        headers=headers,
        allow_status=frozenset({404}),
    )
    if status == 404 or not isinstance(payload, Mapping):
        return {
            "protocol": WORKER_PROTOCOL,
            "ok": True,
            "fields": {
                "provider": "gravatar",
                "found": False,
                "profile_hash": digest,
                "authenticated": bool(api_key),
            },
            "pivots": [],
            "source_urls": [f"https://gravatar.com/{digest}"],
            "confidence": 0.2,
        }

    allowed = (
        "profile_url",
        "display_name",
        "location",
        "description",
        "job_title",
        "company",
        "avatar_url",
        "verified_accounts",
        "links",
        "languages",
        "interests",
    )
    profile = {key: _jsonable(payload.get(key)) for key in allowed if key in payload}
    pivots = _extract_pivots(profile)
    source_urls: list[str] = [f"https://gravatar.com/{digest}"]
    for candidate in (profile.get("profile_url"), profile.get("avatar_url")):
        if isinstance(candidate, str) and _valid_url(candidate):
            source_urls.append(candidate)

    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "gravatar",
            "found": True,
            "profile_hash": digest,
            "authenticated": bool(api_key),
            "profile": profile,
        },
        "pivots": pivots,
        "source_urls": list(dict.fromkeys(source_urls))[:32],
        "confidence": 0.9,
    }


def _github_lookup(username: str, timeout_seconds: float) -> dict[str, object]:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("github requires valid USERNAME")
    endpoint = f"https://api.github.com/users/{urllib.parse.quote(username, safe='')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    status, payload = _http_json_response(
        endpoint,
        timeout_seconds,
        headers=headers,
        allow_status=frozenset({404}),
    )
    if status == 404 or not isinstance(payload, Mapping):
        return {
            "protocol": WORKER_PROTOCOL,
            "ok": True,
            "fields": {"provider": "github", "found": False, "username": username},
            "pivots": [],
            "source_urls": [f"https://github.com/{urllib.parse.quote(username, safe='')}"],
            "confidence": 0.15,
        }

    allowed = (
        "login",
        "id",
        "name",
        "company",
        "blog",
        "location",
        "email",
        "bio",
        "twitter_username",
        "public_repos",
        "public_gists",
        "followers",
        "following",
        "created_at",
        "updated_at",
        "html_url",
        "avatar_url",
        "type",
    )
    profile = {key: _jsonable(payload.get(key)) for key in allowed if key in payload}
    profile["username"] = str(payload.get("login", username))[:64]
    pivots = _extract_pivots(profile)
    source_urls = [
        candidate
        for candidate in (profile.get("html_url"), profile.get("blog"))
        if isinstance(candidate, str) and _valid_url(candidate)
    ]
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {"provider": "github", "found": True, "profile": profile},
        "pivots": pivots,
        "source_urls": list(dict.fromkeys(source_urls))[:32],
        "confidence": 0.98 if str(payload.get("login", "")).casefold() == username.casefold() else 0.8,
    }


def _gitlab_lookup(username: str, timeout_seconds: float) -> dict[str, object]:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("gitlab requires valid USERNAME")
    query = urllib.parse.urlencode({"username": username, "per_page": "20"})
    endpoint = f"https://gitlab.com/api/v4/users?{query}"
    headers: dict[str, str] = {}
    token = os.getenv("GITLAB_TOKEN", "").strip()
    if token:
        headers["PRIVATE-TOKEN"] = token
    payload = _http_json(endpoint, timeout_seconds, headers=headers)
    if not isinstance(payload, list):
        raise RuntimeError("gitlab users response must be a list")

    matches = [
        row
        for row in payload[:20]
        if isinstance(row, Mapping)
        and str(row.get("username", "")).casefold() == username.casefold()
    ]
    if not matches:
        return {
            "protocol": WORKER_PROTOCOL,
            "ok": True,
            "fields": {"provider": "gitlab", "found": False, "username": username},
            "pivots": [],
            "source_urls": [f"https://gitlab.com/{urllib.parse.quote(username, safe='')}"],
            "confidence": 0.15,
        }

    row = matches[0]
    allowed = (
        "id",
        "username",
        "name",
        "state",
        "locked",
        "avatar_url",
        "web_url",
        "public_email",
        "website_url",
        "organization",
        "bio",
        "location",
        "linkedin",
        "twitter",
        "discord",
        "github",
        "created_at",
    )
    profile = {key: _jsonable(row.get(key)) for key in allowed if key in row}
    pivots = _extract_pivots(profile)
    source_urls = [
        candidate
        for candidate in (profile.get("web_url"), profile.get("website_url"))
        if isinstance(candidate, str) and _valid_url(candidate)
    ]
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {"provider": "gitlab", "found": True, "profile": profile},
        "pivots": pivots,
        "source_urls": list(dict.fromkeys(source_urls))[:32],
        "confidence": 0.96,
    }


def _rdap_base_for_domain(payload: object, domain: str) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    services = payload.get("services")
    if not isinstance(services, list):
        return None
    tld = domain.rsplit(".", 1)[-1].casefold()
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, urls = service
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        if tld not in {str(item).casefold() for item in tlds}:
            continue
        for url in urls:
            if isinstance(url, str) and url.startswith("https://"):
                return url
    return None


def _rdap_lookup(domain: str, timeout_seconds: float) -> dict[str, object]:
    target = _valid_domain(domain)
    if target is None:
        raise ValueError("rdap requires valid DOMAIN")
    bootstrap = _http_json("https://data.iana.org/rdap/dns.json", timeout_seconds)
    base = _rdap_base_for_domain(bootstrap, target)
    if not base:
        raise RuntimeError("authoritative RDAP service not found in IANA bootstrap")
    endpoint = urllib.parse.urljoin(
        base.rstrip("/") + "/",
        "domain/" + urllib.parse.quote(target, safe=""),
    )
    status, payload = _http_json_response(
        endpoint,
        timeout_seconds,
        allow_status=frozenset({404}),
    )
    if status == 404 or not isinstance(payload, Mapping):
        return {
            "protocol": WORKER_PROTOCOL,
            "ok": True,
            "fields": {"provider": "rdap", "found": False, "domain": target},
            "pivots": [],
            "source_urls": [
                f"https://lookup.icann.org/en/lookup?name={urllib.parse.quote(target, safe='')}"
            ],
            "confidence": 0.2,
        }

    selected = {
        key: _jsonable(payload.get(key))
        for key in (
            "objectClassName",
            "handle",
            "ldhName",
            "unicodeName",
            "status",
            "events",
            "nameservers",
            "entities",
            "secureDNS",
            "notices",
            "remarks",
        )
        if key in payload
    }
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "rdap",
            "found": True,
            "domain": target,
            "registration": selected,
        },
        "pivots": [],
        "source_urls": [
            endpoint,
            f"https://lookup.icann.org/en/lookup?name={urllib.parse.quote(target, safe='')}",
        ],
        "confidence": 0.98,
    }


def _parse_wayback_rows(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, list) or not payload:
        return []
    header = payload[0]
    if not isinstance(header, list) or not all(isinstance(value, str) for value in header):
        return []
    indexes = {name: index for index, name in enumerate(header)}
    required = {"timestamp", "original"}
    if not required <= indexes.keys():
        return []
    rows: list[dict[str, str]] = []
    for raw in payload[1:76]:
        if not isinstance(raw, list):
            continue
        record: dict[str, str] = {}
        valid = True
        for key in ("timestamp", "original", "statuscode", "mimetype"):
            index = indexes.get(key)
            if index is None:
                continue
            if index >= len(raw) or not isinstance(raw[index], str):
                valid = False
                break
            record[key] = raw[index][:2048]
        if valid and _valid_url(record.get("original", "")):
            rows.append(record)
    return rows


def _wayback_lookup(value: str, kind: str, timeout_seconds: float) -> dict[str, object]:
    if kind == "URL":
        target = _valid_url(value)
        if target is None:
            raise ValueError("wayback requires valid URL")
        match_type = "exact"
    elif kind == "DOMAIN":
        target = _valid_domain(value)
        if target is None:
            raise ValueError("wayback requires valid DOMAIN")
        match_type = "domain"
    else:
        raise ValueError("wayback requires URL or DOMAIN")

    query = urllib.parse.urlencode(
        {
            "url": target,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "matchType": match_type,
            "limit": "75",
        }
    )
    endpoint = f"https://web.archive.org/cdx/search/cdx?{query}"
    rows = _parse_wayback_rows(_http_json(endpoint, timeout_seconds))
    pivots: list[dict[str, str]] = []
    source_urls: list[str] = []
    for row in rows:
        original = row["original"]
        if kind == "DOMAIN":
            pivots.append({"kind": "URL", "value": original})
        timestamp = row.get("timestamp", "")
        if timestamp:
            source_urls.append(f"https://web.archive.org/web/{timestamp}/{original}"[:2048])
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "internet-archive-cdx",
            "match_type": match_type,
            "capture_count": len(rows),
            "captures": rows,
        },
        "pivots": pivots[:75],
        "source_urls": source_urls[:75],
        "confidence": 0.95 if rows else 0.2,
    }


def _parse_crtsh_names(payload: object, target_domain: str) -> list[str]:
    if not isinstance(payload, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for row in payload[:500]:
        if not isinstance(row, Mapping):
            continue
        candidates: list[str] = []
        common_name = row.get("common_name")
        name_value = row.get("name_value")
        if isinstance(common_name, str):
            candidates.append(common_name)
        if isinstance(name_value, str):
            candidates.extend(name_value.splitlines())
        for candidate in candidates:
            domain = _valid_domain(candidate)
            if domain is None:
                continue
            if domain != target_domain and not domain.endswith(f".{target_domain}"):
                continue
            if domain in seen:
                continue
            seen.add(domain)
            names.append(domain)
            if len(names) >= 128:
                return names
    return names


def _crtsh_lookup(domain: str, timeout_seconds: float) -> dict[str, object]:
    target = _valid_domain(domain)
    if target is None:
        raise ValueError("crt.sh requires valid DOMAIN")
    query = urllib.parse.urlencode({"q": f"%.{target}", "output": "json"})
    endpoint = f"https://crt.sh/?{query}"
    payload = _http_json(endpoint, timeout_seconds)
    names = _parse_crtsh_names(payload, target)
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "crt.sh",
            "domain_count": len(names),
            "domains": names,
        },
        "pivots": [{"kind": "DOMAIN", "value": name} for name in names if name != target],
        "source_urls": [
            f"https://crt.sh/?q={urllib.parse.quote(name, safe='')}"
            for name in names[:64]
        ],
        "confidence": 0.95 if names else 0.2,
    }


def _latest_commoncrawl_index(timeout_seconds: float) -> tuple[str, str]:
    payload = _http_json("https://index.commoncrawl.org/collinfo.json", timeout_seconds)
    if not isinstance(payload, list):
        raise RuntimeError("Common Crawl collection list is not a list")
    for row in payload[:20]:
        if not isinstance(row, Mapping):
            continue
        index_id = row.get("id")
        cdx_api = row.get("cdx-api")
        if isinstance(index_id, str) and isinstance(cdx_api, str) and cdx_api.startswith("https://"):
            return index_id, cdx_api
    raise RuntimeError("Common Crawl did not expose a usable current index")


def _parse_commoncrawl_lines(text: str, target: str, kind: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    target_domain = _valid_domain(target) if kind == "DOMAIN" else None
    for line in text.splitlines()[:100]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, Mapping):
            continue
        url = row.get("url")
        if not isinstance(url, str):
            continue
        valid = _valid_url(url)
        if not valid:
            continue
        if target_domain:
            host = (urlsplit(valid).hostname or "").casefold()
            if host != target_domain and not host.endswith("." + target_domain):
                continue
        record = {
            key: str(row.get(key, ""))[:2048]
            for key in ("url", "timestamp", "status", "mime", "digest", "filename", "offset", "length")
            if row.get(key) is not None
        }
        records.append(record)
        if len(records) >= 75:
            break
    return records


def _commoncrawl_lookup(value: str, kind: str, timeout_seconds: float) -> dict[str, object]:
    if kind == "URL":
        target = _valid_url(value)
        if target is None:
            raise ValueError("Common Crawl requires valid URL")
        match_type = "exact"
    elif kind == "DOMAIN":
        target = _valid_domain(value)
        if target is None:
            raise ValueError("Common Crawl requires valid DOMAIN")
        match_type = "domain"
    else:
        raise ValueError("Common Crawl requires URL or DOMAIN")

    index_id, base = _latest_commoncrawl_index(timeout_seconds)
    query = urllib.parse.urlencode(
        {
            "url": target,
            "output": "json",
            "matchType": match_type,
            "filter": "status:200",
            "collapse": "urlkey",
            "limit": "75",
        }
    )
    endpoint = f"{base}?{query}"
    status, body = _http_text_response(
        endpoint,
        timeout_seconds,
        headers={"Accept": "application/x-ndjson, application/json;q=0.9"},
        allow_status=frozenset({404}),
    )
    records = [] if status == 404 else _parse_commoncrawl_lines(body, target, kind)
    pivots = [
        {"kind": "URL", "value": row["url"]}
        for row in records
        if "url" in row
    ][:75]
    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "commoncrawl",
            "index": index_id,
            "match_type": match_type,
            "capture_count": len(records),
            "captures": records,
        },
        "pivots": pivots,
        "source_urls": [endpoint],
        "confidence": 0.9 if records else 0.2,
    }


def _hibp_lookup(account: str, kind: str, timeout_seconds: float) -> dict[str, object]:
    if kind == "EMAIL":
        target = account.strip().casefold()
        if not EMAIL_RE.fullmatch(target):
            raise ValueError("HIBP requires valid EMAIL")
    elif kind == "PHONE":
        target = _valid_phone(account)
        if target is None:
            raise ValueError("HIBP requires E.164-like PHONE")
    else:
        raise ValueError("HIBP requires EMAIL or PHONE")

    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", api_key):
        raise ValueError("HIBP_API_KEY is missing or invalid")

    endpoint = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(target, safe="")
        + "?truncateResponse=false"
    )
    status, payload = _http_json_response(
        endpoint,
        timeout_seconds,
        headers={
            "hibp-api-key": api_key,
            "User-Agent": USER_AGENT,
        },
        allow_status=frozenset({404}),
    )

    if status == 404 or payload is None:
        breaches: list[dict[str, object]] = []
    elif isinstance(payload, list):
        breaches = [
            _jsonable(row)
            for row in payload[:100]
            if isinstance(row, Mapping)
        ]
    else:
        raise RuntimeError("HIBP breachedaccount response must be a list")

    return {
        "protocol": WORKER_PROTOCOL,
        "ok": True,
        "fields": {
            "provider": "haveibeenpwned",
            "breached": bool(breaches),
            "breach_count": len(breaches),
            "breaches": breaches,
        },
        "pivots": [],
        # Never expose the account-bearing API URL in evidence links.
        "source_urls": ["https://haveibeenpwned.com/PwnedWebsites"],
        "confidence": 0.98 if breaches else 0.8,
    }


def _emit(payload: Mapping[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def main() -> int:
    source = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        request = _read_request()
        value = str(request["value"])
        kind = str(request["kind"])
        timeout = float(request["timeout_seconds"])

        if source == "holehe.email":
            if kind != "EMAIL":
                raise ValueError("holehe requires EMAIL")
            payload = _holehe_lookup(value, timeout)
        elif source == "maigret.username":
            if kind != "USERNAME":
                raise ValueError("maigret requires USERNAME")
            payload = asyncio.run(_maigret_lookup(value, timeout))
        elif source == "gravatar.email":
            if kind != "EMAIL":
                raise ValueError("gravatar requires EMAIL")
            payload = _gravatar_lookup(value, timeout)
        elif source == "github.username":
            if kind != "USERNAME":
                raise ValueError("github requires USERNAME")
            payload = _github_lookup(value, timeout)
        elif source == "gitlab.username":
            if kind != "USERNAME":
                raise ValueError("gitlab requires USERNAME")
            payload = _gitlab_lookup(value, timeout)
        elif source == "hibp.account":
            payload = _hibp_lookup(value, kind, timeout)
        elif source == "rdap.domain":
            if kind != "DOMAIN":
                raise ValueError("rdap requires DOMAIN")
            payload = _rdap_lookup(value, timeout)
        elif source in {"wayback.url", "wayback.domain"}:
            payload = _wayback_lookup(value, kind, timeout)
        elif source == "crtsh.domain":
            if kind != "DOMAIN":
                raise ValueError("crt.sh requires DOMAIN")
            payload = _crtsh_lookup(value, timeout)
        elif source in {"commoncrawl.url", "commoncrawl.domain"}:
            payload = _commoncrawl_lookup(value, kind, timeout)
        else:
            raise ValueError("unknown source")

        _emit(payload)
        return 0
    except ModuleNotFoundError as exc:
        _emit(
            {
                "protocol": WORKER_PROTOCOL,
                "ok": False,
                "error_code": "DEPENDENCY_UNAVAILABLE",
                "dependency": str(exc.name or "unknown"),
            }
        )
        return 78
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
