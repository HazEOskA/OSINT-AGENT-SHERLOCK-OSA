from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from importlib.resources import files
from typing import Any, Mapping
from urllib.parse import urlsplit

from sherlock_osa.source_pack import WORKER_PROTOCOL


USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,253}$")


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
            try:
                parsed = urlsplit(normalized)
            except ValueError:
                return
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(normalized) > 2048:
                return
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

    resource = files("maigret").joinpath("resources", "data.json")
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
        if url_text.startswith(("http://", "https://")):
            source_urls.append(url_text[:2048])
            pivots.append({"kind": "URL", "value": url_text[:2048]})
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
