"""Read-only agent capability inventory. Discovery is never authorization."""
from __future__ import annotations

from hashlib import sha256
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from sherlock_osa.policy import MODE_CAPABILITIES
from sherlock_osa.source_registry import SOURCE_DESCRIPTORS, SourceDescriptor

REGISTRY_VERSION = "agent-capability-registry.v1"
_MAX_CATALOG_ENTRIES = 6000


def _allowed_modes(required_capability: str) -> list[str]:
    return sorted(
        mode.value
        for mode, capabilities in MODE_CAPABILITIES.items()
        if required_capability in capabilities
    )


def _catalog_key(raw_url: object) -> str:
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        return ""
    candidate = raw_url.strip()
    try:
        parsed = urlsplit(candidate)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return ""
    except ValueError:
        return ""
    # Remove fragment, query, trailing slash; catalog references are not credentials.
    return (
        f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        f"{parsed.path.rstrip('/')}"
    )


def build_capability_registry(
    *,
    catalog_tools: Sequence[Mapping[str, object]] = (),
    source_descriptors: Sequence[SourceDescriptor] | None = None,
) -> dict[str, object]:
    """Build a bounded, deterministic inventory; do not invoke any provider.

    This manifest cannot grant or route authority. Only the existing signed-scope
    CapabilityBroker may evaluate execution requests.
    """
    if len(catalog_tools) > _MAX_CATALOG_ENTRIES:
        raise ValueError("CATALOG_SIZE_LIMIT")

    descriptors = SOURCE_DESCRIPTORS if source_descriptors is None else source_descriptors
    entries: dict[str, dict[str, object]] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, SourceDescriptor):
            raise ValueError("INVALID_SOURCE_DESCRIPTOR")
        health = descriptor.health()
        required = descriptor.required_capability
        modes = _allowed_modes(required)
        ready = health.get("ready") is True and bool(modes)
        status = "ADAPTER_READY" if ready else "UNAVAILABLE"
        key = f"adapter.{descriptor.name}"
        if key in entries:
            raise ValueError("DUPLICATE_ADAPTER")
        entries[key] = {
            "capability_id": key,
            "version": "1.0.0",
            "name": descriptor.name,
            "kind": sorted(kind.value for kind in descriptor.supported_kinds),
            "provider": "Sherlock native",
            "sources": ["Sherlock native"],
            "type": "NATIVE_ADAPTER",
            "required_capability": required,
            "authorized_modes": modes,
            "requires_authorization": True,
            "authorization_granted": False,
            "adapter_bound": True,
            "adapter_ready": ready,
            "execution_class": status,
            "status": status,
            "cost": descriptor.cost.value,
            "cost_verified": False,
            "trust_class": descriptor.trust_class.value,
            "network_effect": descriptor.network_effect,
            "limitation": "Adapter readiness is not provider reachability or signed-scope authorization.",
        }

    deduped_catalog: dict[str, dict[str, object]] = {}
    for raw in catalog_tools:
        if not isinstance(raw, Mapping):
            raise ValueError("INVALID_CATALOG_ENTRY")
        key = _catalog_key(raw.get("url"))
        if not key:
            continue
        classification = raw.get("execution_class")
        if classification not in {"CATALOG_ONLY", "CATALOG_ONLY_RESTRICTED"}:
            # Unrecognized classes are never silently promoted or executed.
            classification = "CATALOG_ONLY_RESTRICTED"
        is_restricted = classification == "CATALOG_ONLY_RESTRICTED"
        raw_sources = raw.get("sources")
        if not isinstance(raw_sources, (list, tuple)):
            raw_sources = [raw.get("source", "UNKNOWN")]
        sources = {
            str(value).strip()[:120]
            for value in raw_sources
            if isinstance(value, str) and value.strip()
        } or {"UNKNOWN"}
        if key in deduped_catalog:
            prior = deduped_catalog[key]
            prior["sources"] = sorted(set(prior["sources"]) | sources)
            if is_restricted:
                prior["status"] = "RESTRICTED"
                prior["execution_class"] = "CATALOG_ONLY_RESTRICTED"
            continue
        cid = "catalog." + sha256(key.encode("utf-8")).hexdigest()[:24]
        deduped_catalog[key] = {
            "capability_id": cid,
            "version": "1.0.0",
            "name": str(raw.get("name") or "Unnamed resource")[:180],
            "kind": "UNKNOWN",
            "provider": "World Atlas",
            "sources": sorted(sources),
            "type": "CATALOG_RESOURCE",
            "required_capability": None,
            "authorized_modes": [],
            "requires_authorization": True,
            "authorization_granted": False,
            "adapter_bound": False,
            "adapter_ready": False,
            "execution_class": classification,
            "status": "RESTRICTED" if is_restricted else "CATALOG_ONLY",
            "cost": "UNKNOWN",
            "cost_verified": False,
            "network_effect": None,
            "limitation": "Discovery only. No adapter, implicit permission, or execution.",
        }

    for entry in deduped_catalog.values():
        cid = str(entry["capability_id"])
        if cid in entries:
            raise ValueError("CAPABILITY_ID_COLLISION")
        entries[cid] = entry
    ordered = [entries[key] for key in sorted(entries)]
    counts = {
        status: sum(item["status"] == status for item in ordered)
        for status in ("ADAPTER_READY", "UNAVAILABLE", "CATALOG_ONLY", "RESTRICTED")
    }
    return {
        "version": REGISTRY_VERSION,
        "default_policy": "DENY",
        "execution_authority": "EXISTING_SIGNED_SCOPE_CAPABILITY_BROKER_ONLY",
        "catalog_only_execution_allowed": False,
        "source_count": len(descriptors),
        "catalog_count": len(deduped_catalog),
        "total_count": len(ordered),
        "status_counts": counts,
        "capabilities": ordered,
    }
