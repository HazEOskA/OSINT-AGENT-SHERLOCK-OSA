from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.source_registry import SOURCE_DESCRIPTORS


_CACHE_TTL_SECONDS = 900
_CACHE_LOCK = threading.Lock()
_CACHE_AT = 0.0
_CACHE_TOOLS: tuple["AtlasTool", ...] = ()

_SOURCES = (
    ("OSINT Framework", "tree", "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"),
    ("Awesome OSINT", "markdown", "https://raw.githubusercontent.com/jivoi/awesome-osint/master/README.md"),
    ("Awesome Threat Intelligence", "markdown", "https://raw.githubusercontent.com/hslatman/awesome-threat-intelligence/main/README.md"),
)

_KIND_TERMS = {
    "EMAIL": ("email", "mail", "breach", "account", "identity", "people", "person", "leak", "gravatar", "username"),
    "PHONE": ("phone", "telephone", "mobile", "number", "people", "person", "identity", "account", "messenger"),
    "USERNAME": ("username", "user name", "social", "profile", "account", "identity", "people", "person", "nickname", "handle"),
    "PERSON": ("people", "person", "social", "profile", "identity", "username", "email", "phone", "public records", "search engine"),
    "DOMAIN": ("domain", "dns", "subdomain", "certificate", "website", "web", "host", "infrastructure", "archive", "whois", "rdap"),
    "URL": ("url", "website", "web", "archive", "metadata", "domain", "page", "crawl", "historical"),
}

_OFFENSIVE_TERMS = (
    "password crack", "credential attack", "exploit", "masscan",
    "social engineering", "phishing", "brute force", "bruteforce",
    "malware", "payload", "ddos",
)

_MAX_HTTP_BYTES = 1_500_000


@dataclass(frozen=True, slots=True)
class AtlasTool:
    name: str
    url: str
    description: str
    category: str
    source: str
    api: bool = False
    local_install: bool = False
    registration: bool = False
    opsec: str = ""
    pricing: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "category": self.category,
            "source": self.source,
            "api": self.api,
            "local_install": self.local_install,
            "registration": self.registration,
            "opsec": self.opsec,
            "pricing": self.pricing,
            "execution_class": "CATALOG_ONLY_RESTRICTED" if _is_restricted(self) else "CATALOG_ONLY",
        }


def atlas_overview() -> dict[str, object]:
    tools, errors = _catalog()
    categories = sorted({tool.category.split(" / ", 1)[0] for tool in tools if tool.category})
    return {
        "version": "world-atlas.v1",
        "tool_count": len(tools),
        "category_count": len(categories),
        "sources": [
            {
                "name": name,
                "url": url,
                "status": "ERROR" if name in errors else "SYNCED",
                "error": errors.get(name),
            }
            for name, _, url in _SOURCES
        ],
        "runtime_adapter_count": len(SOURCE_DESCRIPTORS),
        "principle": "ATLAS_CONSIDERS_ALL; RUNTIME_EXECUTES_ONLY_ADAPTER_BACKED_SAFE_SOURCES",
    }


def build_world_tool_plan(
    *,
    kind: str,
    query: str,
    runtime_health: Mapping[str, object] | None = None,
    candidate_limit: int = 160,
) -> dict[str, object]:
    normalized_kind = str(kind).strip().upper()
    tools, errors = _catalog()
    terms = _KIND_TERMS.get(normalized_kind, _KIND_TERMS["PERSON"])

    ranked: list[tuple[int, AtlasTool]] = []
    for tool in tools:
        haystack = " ".join((tool.name, tool.description, tool.category, tool.source, tool.url)).casefold()
        category_text = tool.category.casefold()
        score = sum(3 if term in category_text else 1 for term in terms if term in haystack)
        if score:
            if tool.api:
                score += 2
            if tool.local_install:
                score += 1
            ranked.append((score, tool))
    ranked.sort(key=lambda item: (-item[0], item[1].name.casefold(), item[1].url))

    runtime_sources = _runtime_sources(runtime_health)
    compatible_runtime = []
    for descriptor in SOURCE_DESCRIPTORS:
        if normalized_kind not in {item.value for item in descriptor.supported_kinds}:
            continue
        source = runtime_sources.get(descriptor.name, {})
        ready = bool(source.get("ready", descriptor.credential_configured))
        compatible_runtime.append(
            {
                "name": descriptor.name,
                "family": descriptor.family,
                "supported_kinds": sorted(item.value for item in descriptor.supported_kinds),
                "ready": ready,
                "requires_key": descriptor.requires_key,
                "credential_configured": bool(source.get("credential_configured", descriptor.credential_configured)),
                "priority": descriptor.priority,
                "historical": descriptor.historical,
                "execution": "EXECUTE" if ready else "AUTH_OR_DEPENDENCY_REQUIRED",
            }
        )

    candidates = []
    for score, tool in ranked[:candidate_limit]:
        row = tool.to_dict()
        row["match_score"] = score
        candidates.append(row)

    restricted = sum(1 for _, tool in ranked if _is_restricted(tool))
    return {
        "version": "world-tool-plan.v1",
        "query": {"kind": normalized_kind, "value": query},
        "catalog": {
            "total_tools_considered": len(tools),
            "matching_tools": len(ranked),
            "candidate_tools_returned": len(candidates),
            "restricted_catalog_matches": restricted,
            "sync_errors": errors,
        },
        "runtime": {
            "compatible_adapters": len(compatible_runtime),
            "ready_adapters": sum(1 for item in compatible_runtime if item["execution"] == "EXECUTE"),
            "blocked_adapters": sum(1 for item in compatible_runtime if item["execution"] != "EXECUTE"),
            "plan": compatible_runtime,
        },
        "candidates": candidates,
        "truth": {
            "catalog_considered": True,
            "catalog_entries_auto_executed": False,
            "runtime_adapters_auto_executed": True,
            "reason": (
                "Atlas contains heterogeneous websites, manual tools, local binaries and "
                "credentialed services. Sherlock executes only sources with a real adapter "
                "and compatible authorization/dependency state."
            ),
        },
    }


def _runtime_sources(health: Mapping[str, object] | None) -> dict[str, Mapping[str, object]]:
    if not isinstance(health, Mapping):
        return {}
    rows = health.get("sources")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return {}
    result: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if isinstance(row, Mapping):
            name = row.get("name")
            if isinstance(name, str):
                result[name] = row
    return result


def _catalog() -> tuple[tuple[AtlasTool, ...], dict[str, str]]:
    global _CACHE_AT, _CACHE_TOOLS
    now = time.monotonic()
    with _CACHE_LOCK:
        if _CACHE_TOOLS and now - _CACHE_AT < _CACHE_TTL_SECONDS:
            return _CACHE_TOOLS, {}

    tools: list[AtlasTool] = []
    errors: dict[str, str] = {}
    for name, source_type, url in _SOURCES:
        try:
            body = _fetch_text(url)
            if source_type == "tree":
                tools.extend(_parse_tree(json.loads(body), name))
            else:
                tools.extend(_parse_markdown(body, name))
        except Exception as exc:
            errors[name] = f"{type(exc).__name__}: {exc}"[:300]

    deduped = _dedupe(tools)
    if deduped:
        with _CACHE_LOCK:
            _CACHE_TOOLS = deduped
            _CACHE_AT = now
    return deduped, errors


def _fetch_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json,text/plain;q=0.9,*/*;q=0.5",
            "User-Agent": "sherlock-osa-world-atlas/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(_MAX_HTTP_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"atlas source unavailable: {exc}") from exc
    if len(raw) > _MAX_HTTP_BYTES:
        raise RuntimeError("atlas source too large")
    return raw.decode("utf-8", errors="replace")


def _parse_tree(payload: object, source: str) -> list[AtlasTool]:
    if not isinstance(payload, Mapping):
        return []
    result: list[AtlasTool] = []

    def walk(node: object, path: tuple[str, ...] = ()) -> None:
        if not isinstance(node, Mapping):
            return
        name = str(node.get("name", "")).strip()
        node_type = str(node.get("type", "")).strip()
        current_path = path
        if node_type == "folder" and name and name != "OSINT Framework":
            current_path = (*path, name)
        if node_type == "url":
            url = _normalize_url(str(node.get("url", "")))
            if url:
                result.append(
                    AtlasTool(
                        name=name or urlsplit(url).hostname or url,
                        url=url,
                        description=str(node.get("description", "") or "")[:1200],
                        category=" / ".join(path) or "Uncategorized",
                        source=source,
                        api=bool(node.get("api")),
                        local_install=bool(node.get("localInstall")),
                        registration=bool(node.get("registration")),
                        opsec=str(node.get("opsec", "") or ""),
                        pricing=str(node.get("pricing", "") or ""),
                    )
                )
        children = node.get("children")
        if isinstance(children, Sequence) and not isinstance(children, (str, bytes, bytearray)):
            for child in children:
                walk(child, current_path)

    walk(payload)
    return result


_MD_LINK = re.compile(r"\[([^\]]{2,180})\]\((https?://[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\)")


def _parse_markdown(text: str, source: str) -> list[AtlasTool]:
    result: list[AtlasTool] = []
    heading = "Uncategorized"
    for line in text.splitlines():
        match = re.match(r"^#{2,4}\s+(.+)", line)
        if match:
            heading = re.sub(r"[*_\x60#↑]", "", match.group(1)).strip()[:240]
            continue
        for link in _MD_LINK.finditer(line):
            name = re.sub(r"[*_\x60]", "", link.group(1)).strip()
            if re.search(r"badge|table of contents|license|contributing", name, re.I):
                continue
            url = _normalize_url(link.group(2))
            if not url:
                continue
            description = line.replace(link.group(0), "")
            description = re.sub(r"^\s*[-*+]\s*", "", description)
            description = re.sub(r"^\s*[-–—:]\s*", "", description).strip()
            result.append(
                AtlasTool(
                    name=name,
                    url=url,
                    description=description[:1200],
                    category=heading,
                    source=source,
                )
            )
    return result


def _normalize_url(raw: str) -> str:
    candidate = raw.strip()
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return candidate.split("#", 1)[0].rstrip("/")


def _dedupe(tools: Sequence[AtlasTool]) -> tuple[AtlasTool, ...]:
    deduped: dict[str, AtlasTool] = {}
    for tool in tools:
        key = tool.url.casefold()
        current = deduped.get(key)
        if current is None:
            deduped[key] = tool
            continue
        if len(tool.description) > len(current.description):
            deduped[key] = tool
    return tuple(sorted(deduped.values(), key=lambda item: (item.name.casefold(), item.url)))


def _is_restricted(tool: AtlasTool) -> bool:
    text = " ".join((tool.name, tool.description, tool.category)).casefold()
    return any(term in text for term in _OFFENSIVE_TERMS)
