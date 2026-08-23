from __future__ import annotations

import asyncio
import json
import logging
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
MAX_HTTP_BYTES = 2_000_000


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


def _extract_pivots(ids_data: object) -> list[dict[str, str]]:
    pivots: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        normalized = value.strip()
        if kind == "EMAIL":
            normalized = normalized.casefold()
            if len(normalized) > 320 or not EMAIL_RE.fullmatch(normalized):
                return
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
        if depth > 4 or len(pivots) >= 64:
            return
        if isinstance(value, Mapping):
            for key, item in list(value.items())[:64]:
                key_text = str(key).casefold()
                values = _candidate_values(item)
                if key_text in {"email", "emails", "mail", "mails"}:
                    for candidate in values:
                        add("EMAIL", candidate)
                elif key_text in {"username", "usernames", "nickname", "nick", "handle", "handles"}:
                    for candidate in values:
                        add("USERNAME", candidate)
                elif key_text in {"url", "urls", "website", "websites", "link", "links", "profile_url"}:
                    for candidate in values:
                        add("URL", candidate)
                else:
                    walk(item, key_text, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in list(value)[:64]:
                walk(item, parent_key, depth + 1)

    walk(ids_data)
    return pivots[:64]


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


def _http_json(url: str, timeout_seconds: float) -> object:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "sherlock-osa/0.3.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=max(1.0, min(timeout_seconds, 30.0))) as response:
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(MAX_HTTP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.read(1024)
        raise RuntimeError(f"source HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"source unavailable: {exc}") from exc
    if len(raw) > MAX_HTTP_BYTES:
        raise RuntimeError("source response too large")
    if "json" not in content_type.casefold() and not raw.lstrip().startswith((b"[", b"{")):
        raise RuntimeError("source did not return JSON")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("source returned invalid JSON") from exc


def _holehe_lookup(email: str, timeout_seconds: float) -> dict[str, object]:
    import httpx
    import trio
    from holehe.core import get_functions, import_submodules, launch_module

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
            registered.append(
                {
                    "service": str(result.get("name", ""))[:120],
                    "domain": str(result.get("domain", ""))[:253],
                }
            )
    registered = registered[:128]
    source_urls = [
        f"https://{item['domain']}"
        for item in registered
        if isinstance(item.get("domain"), str) and "." in str(item["domain"])
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
        "pivots": [],
        "source_urls": source_urls,
        "confidence": 0.9 if output else 0.0,
    }


async def _maigret_lookup(username: str, timeout_seconds: float) -> dict[str, object]:
    from maigret import search as maigret_search
    from maigret.sites import MaigretDatabase

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
        "source_urls": [f"https://crt.sh/?q={urllib.parse.quote(name, safe='')}" for name in names[:64]],
        "confidence": 0.95 if names else 0.2,
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
        elif source in {"wayback.url", "wayback.domain"}:
            payload = _wayback_lookup(value, kind, timeout)
        elif source == "crtsh.domain":
            if kind != "DOMAIN":
                raise ValueError("crt.sh requires DOMAIN")
            payload = _crtsh_lookup(value, timeout)
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
