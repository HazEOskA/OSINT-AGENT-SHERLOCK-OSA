from __future__ import annotations

from dataclasses import replace
from typing import Sequence

from sherlock_osa import site_probe
from sherlock_osa.site_probe import ProbeBatch, SiteDefinition


def _sanitize_definition(definition: SiteDefinition) -> SiteDefinition:
    """Fail closed when a dataset rule cannot be represented safely.

    Sherlock Project may expose multiple negative message signatures. The base V3
    normalized model has one `missing_text` field, so a Python string representation
    of a list must never be treated as a real missing-account signature. Keeping that
    value would turn an arbitrary HTTP 200 into a false positive.
    """

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
    definitions, datasets = site_probe.load_site_definitions(timeout_seconds)
    sanitized = [_sanitize_definition(definition) for definition in definitions]
    return sanitized, datasets


def run_username_probe_guarded(
    username: str,
    *,
    mode: str = "MAX",
    timeout_seconds: float = 50.0,
    concurrency: int = 48,
) -> ProbeBatch:
    """Run the base probe engine with V3 false-positive guards applied.

    This function executes in the dedicated Social Mesh subprocess, so the temporary
    module-level substitutions cannot leak into the main Sherlock process.
    """

    original_loader = site_probe.load_site_definitions
    original_limit = site_probe.MAX_RESULTS
    try:
        site_probe.load_site_definitions = load_guarded_definitions  # type: ignore[assignment]
        site_probe.MAX_RESULTS = 1200
        return site_probe.run_username_probe(
            username,
            mode=mode,
            timeout_seconds=timeout_seconds,
            concurrency=concurrency,
        )
    finally:
        site_probe.load_site_definitions = original_loader  # type: ignore[assignment]
        site_probe.MAX_RESULTS = original_limit
