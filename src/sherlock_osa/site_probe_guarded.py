from __future__ import annotations

from dataclasses import replace

from sherlock_osa import site_probe
from sherlock_osa.site_probe import ProbeBatch, ProbeResult, ProbeVerdict, SiteDefinition
from sherlock_osa.truth_engine import canary_username, detect_interstitial


_BASE_LOADER = site_probe.load_site_definitions
_BASE_EVALUATE = site_probe._evaluate
_BASE_PROBE_ONE = site_probe._probe_one
WMN_TRUTH_COMMIT = "ea7dcef44ad5706650932347856855a21f6b99af"
WMN_TRUTH_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/"
    f"{WMN_TRUTH_COMMIT}/wmn-data.json"
)


def _sanitize_definition(definition: SiteDefinition) -> SiteDefinition:
    """Fail closed when a dataset rule cannot be represented safely."""

    missing = definition.missing_text.strip()
    if (
        definition.error_type == "message"
        and missing.startswith("[")
        and missing.endswith("]")
    ):
        return replace(
            definition,
            missing_text="",
            error_type="message_list_requires_site_specific_parser",
        )
    return definition


def load_guarded_definitions(
    timeout_seconds: float = 12.0,
) -> tuple[list[SiteDefinition], tuple[dict[str, object], ...]]:
    # Keep the runtime dataset on the upstream false-positive-fixed commit even if
    # the base module was imported with an older historical pin.
    previous_commit = site_probe.WMN_COMMIT
    previous_url = site_probe.WMN_DATA_URL
    try:
        site_probe.WMN_COMMIT = WMN_TRUTH_COMMIT
        site_probe.WMN_DATA_URL = WMN_TRUTH_URL
        definitions, datasets = _BASE_LOADER(timeout_seconds)
    finally:
        site_probe.WMN_COMMIT = previous_commit
        site_probe.WMN_DATA_URL = previous_url

    sanitized = [_sanitize_definition(definition) for definition in definitions]
    return sanitized, datasets


def _truth_evaluate(
    definition: SiteDefinition,
    status: int | None,
    final_url: str,
    body: str,
) -> tuple[ProbeVerdict, str]:
    interstitial = detect_interstitial(body)
    if interstitial:
        return ProbeVerdict.BLOCKED, f"INTERSTITIAL_{interstitial}"
    return _BASE_EVALUATE(definition, status, final_url, body)


def _truth_probe_one(
    definition: SiteDefinition,
    username: str,
    timeout_seconds: float,
) -> ProbeResult:
    result = _BASE_PROBE_ONE(definition, username, timeout_seconds)
    if result.verdict is not ProbeVerdict.FOUND:
        return result

    # Every positive must survive a negative-control request. This catches pages
    # that return the same 200/challenge/homepage for every username.
    negative = definition.known_negative or canary_username(
        f"{definition.stable_key}|{username}"
    )
    valid, _ = site_probe._valid_username(definition, negative)
    if not valid:
        return replace(
            result,
            verdict=ProbeVerdict.UNRELIABLE,
            reliability=min(result.reliability, 0.25),
            reason=f"{result.reason}+NEGATIVE_CANARY_UNREPRESENTABLE",
        )

    canary_timeout = max(1.0, min(timeout_seconds / 3.0, 3.0))
    canary = site_probe._canary_verdict(definition, negative, canary_timeout)
    if canary is not ProbeVerdict.NOT_FOUND:
        return replace(
            result,
            verdict=ProbeVerdict.UNRELIABLE,
            reliability=min(result.reliability, 0.2),
            reason=f"{result.reason}+NEGATIVE_CANARY_FAILED:{canary.value}",
        )

    return replace(
        result,
        reliability=min(0.99, max(result.reliability, 0.9)),
        reason=f"{result.reason}+NEGATIVE_CANARY_PASS",
    )


def run_username_probe_guarded(
    username: str,
    *,
    mode: str = "MAX",
    timeout_seconds: float = 50.0,
    concurrency: int = 48,
) -> ProbeBatch:
    """Run Social Mesh with Truth Engine V4 false-positive guards."""

    original_loader = site_probe.load_site_definitions
    original_limit = site_probe.MAX_RESULTS
    original_evaluate = site_probe._evaluate
    original_probe_one = site_probe._probe_one
    try:
        site_probe.load_site_definitions = load_guarded_definitions  # type: ignore[assignment]
        site_probe._evaluate = _truth_evaluate  # type: ignore[assignment]
        site_probe._probe_one = _truth_probe_one  # type: ignore[assignment]
        site_probe.MAX_RESULTS = 1200
        return site_probe.run_username_probe(
            username,
            mode=mode,
            timeout_seconds=timeout_seconds,
            concurrency=concurrency,
        )
    finally:
        site_probe.load_site_definitions = original_loader  # type: ignore[assignment]
        site_probe._evaluate = original_evaluate  # type: ignore[assignment]
        site_probe._probe_one = original_probe_one  # type: ignore[assignment]
        site_probe.MAX_RESULTS = original_limit
