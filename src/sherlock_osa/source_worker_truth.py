from __future__ import annotations

from typing import Mapping

from sherlock_osa import source_worker as base
from sherlock_osa.truth_engine import TruthVerdict, canary_username, confidence_for_presence


_BASE_HOLEHE = base._holehe_lookup
_BASE_MAIGRET = base._maigret_lookup


def _truth_holehe_lookup(email: str, timeout_seconds: float) -> dict[str, object]:
    payload = _BASE_HOLEHE(email, timeout_seconds)
    fields = payload.get("fields", {})
    if not isinstance(fields, Mapping):
        return payload

    checked = int(fields.get("checked", 0) or 0)
    registered = int(fields.get("registered_count", 0) or 0)
    errors = int(fields.get("error_count", 0) or 0)
    rate_limited = int(fields.get("rate_limited_count", 0) or 0)
    if registered > 0:
        verdict = TruthVerdict.FOUND
    elif checked > 0 and errors + rate_limited < checked:
        verdict = TruthVerdict.NOT_FOUND
    elif rate_limited > 0:
        verdict = TruthVerdict.RATE_LIMITED
    elif errors > 0:
        verdict = TruthVerdict.UNRELIABLE
    else:
        verdict = TruthVerdict.UNKNOWN

    updated_fields = dict(fields)
    updated_fields["truth_verdict"] = verdict.value
    updated_fields["truth_engine"] = "V4"
    updated_fields["transport_success_is_positive"] = False
    payload["fields"] = updated_fields
    payload["confidence"] = confidence_for_presence(
        verdict,
        base=0.9,
        error_count=errors,
        rate_limited_count=rate_limited,
        checked_count=checked,
    )
    return payload


async def _truth_maigret_lookup(username: str, timeout_seconds: float) -> dict[str, object]:
    primary = await _BASE_MAIGRET(username, timeout_seconds)
    fields = primary.get("fields", {})
    if not isinstance(fields, Mapping):
        return primary

    profiles = fields.get("profiles", [])
    if not isinstance(profiles, list) or not profiles:
        updated = dict(fields)
        updated.update(
            {
                "truth_verdict": TruthVerdict.NOT_FOUND.value,
                "truth_engine": "V4",
                "canary_checked": False,
                "quarantined_count": 0,
            }
        )
        primary["fields"] = updated
        primary["confidence"] = 0.25
        return primary

    # A deliberately impossible-looking username is sent through the same Maigret
    # detectors. Any service that also reports it as FOUND is quarantined.
    canary = canary_username(username)
    canary_timeout = max(3.0, min(timeout_seconds * 0.45, 18.0))
    canary_payload = await _BASE_MAIGRET(canary, canary_timeout)
    canary_fields = canary_payload.get("fields", {})
    canary_profiles = canary_fields.get("profiles", []) if isinstance(canary_fields, Mapping) else []
    bad_sites = {
        str(item.get("site", "")).casefold()
        for item in canary_profiles
        if isinstance(item, Mapping) and str(item.get("site", "")).strip()
    } if isinstance(canary_profiles, list) else set()

    verified_profiles = [
        item
        for item in profiles
        if isinstance(item, Mapping)
        and str(item.get("site", "")).casefold() not in bad_sites
    ]
    quarantined = [
        item
        for item in profiles
        if isinstance(item, Mapping)
        and str(item.get("site", "")).casefold() in bad_sites
    ]

    updated = dict(fields)
    updated["profiles"] = verified_profiles
    updated["found_count"] = len(verified_profiles)
    updated["canary_checked"] = True
    updated["canary_username_hash_only"] = True
    updated["quarantined_count"] = len(quarantined)
    updated["quarantined_sites"] = sorted(
        {str(item.get("site", "")) for item in quarantined if isinstance(item, Mapping)}
    )[:100]
    updated["truth_engine"] = "V4"
    updated["truth_verdict"] = (
        TruthVerdict.FOUND.value if verified_profiles else TruthVerdict.UNRELIABLE.value
    )
    primary["fields"] = updated

    valid_urls = {
        str(item.get("url", ""))
        for item in verified_profiles
        if isinstance(item, Mapping) and str(item.get("url", "")).startswith(("http://", "https://"))
    }
    primary["source_urls"] = [
        url for url in primary.get("source_urls", []) if isinstance(url, str) and url in valid_urls
    ]
    primary["confidence"] = (
        min(0.97, 0.72 + 0.015 * len(verified_profiles)) if verified_profiles else 0.1
    )
    return primary


def main() -> int:
    base._holehe_lookup = _truth_holehe_lookup  # type: ignore[assignment]
    base._maigret_lookup = _truth_maigret_lookup  # type: ignore[assignment]
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
