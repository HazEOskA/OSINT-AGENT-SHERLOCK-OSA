from __future__ import annotations

from typing import Mapping, Sequence

from sherlock_osa.investigation import InvestigationResult


_EXECUTED = frozenset({"COMPLETED", "ERROR", "TIMEOUT"})
_SUCCESS = frozenset({"COMPLETED"})


def build_max2_report(
    *,
    investigation: InvestigationResult,
    world_tool_plan: Mapping[str, object],
    proof_report: Mapping[str, object],
) -> dict[str, object]:
    runtime = world_tool_plan.get("runtime")
    runtime = runtime if isinstance(runtime, Mapping) else {}
    plan_rows = runtime.get("plan")
    plan_rows = (
        list(plan_rows)
        if isinstance(plan_rows, Sequence) and not isinstance(plan_rows, (str, bytes, bytearray))
        else []
    )

    ready = {
        str(row.get("name"))
        for row in plan_rows
        if isinstance(row, Mapping)
        and row.get("execution") == "EXECUTE"
        and row.get("name")
    }
    blocked = [
        {
            "source": str(row.get("name")),
            "family": str(row.get("family", "")),
            "reason": "AUTH_OR_DEPENDENCY_REQUIRED",
            "requires_key": bool(row.get("requires_key")),
        }
        for row in plan_rows
        if isinstance(row, Mapping)
        and row.get("execution") != "EXECUTE"
        and row.get("name")
    ]

    runs = {run.source: run for run in investigation.source_runs}
    executed_ready = sorted(
        name for name in ready if name in runs and runs[name].status in _EXECUTED
    )
    successful_ready = sorted(
        name for name in ready if name in runs and runs[name].status in _SUCCESS
    )
    missing_ready = sorted(name for name in ready if name not in executed_ready)

    proof_summary = proof_report.get("summary")
    proof_summary = proof_summary if isinstance(proof_summary, Mapping) else {}
    claims = proof_report.get("claims")
    claims = (
        list(claims)
        if isinstance(claims, Sequence) and not isinstance(claims, (str, bytes, bytearray))
        else []
    )

    claims_total = int(proof_summary.get("claims", len(claims)) or 0)
    claims_with_links = int(proof_summary.get("claims_with_hard_links", 0) or 0)
    corroborated_claims = sum(
        1
        for claim in claims
        if isinstance(claim, Mapping)
        and int(claim.get("independent_source_count", 0) or 0) >= 2
    )
    conflicted_claims = sum(
        1
        for claim in claims
        if isinstance(claim, Mapping) and claim.get("status") == "CONFLICTED"
    )
    linkless_claims = [
        {
            "claim_id": str(claim.get("claim_id", "")),
            "kind": str(claim.get("kind", "")),
            "value": str(claim.get("value", "")),
            "reason": "NO_DIRECT_SOURCE_URL",
        }
        for claim in claims
        if isinstance(claim, Mapping)
        and not any(
            isinstance(evidence, Mapping) and bool(evidence.get("url"))
            for evidence in (
                claim.get("evidence")
                if isinstance(claim.get("evidence"), Sequence)
                and not isinstance(claim.get("evidence"), (str, bytes, bytearray))
                else []
            )
        )
    ]

    catalog = world_tool_plan.get("catalog")
    catalog = catalog if isinstance(catalog, Mapping) else {}
    candidates = world_tool_plan.get("candidates")
    candidates = (
        list(candidates)
        if isinstance(candidates, Sequence) and not isinstance(candidates, (str, bytes, bytearray))
        else []
    )

    next_best = []
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        execution_class = str(item.get("execution_class", "CATALOG_ONLY"))
        if execution_class == "CATALOG_ONLY_RESTRICTED":
            continue
        next_best.append(
            {
                "name": str(item.get("name", "")),
                "url": str(item.get("url", "")),
                "source": str(item.get("source", "")),
                "category": str(item.get("category", "")),
                "match_score": int(item.get("match_score", 0) or 0),
                "status": "ADAPTER_REQUIRED",
            }
        )
        if len(next_best) >= 24:
            break

    ready_count = len(ready)
    execution_ratio = _ratio(len(executed_ready), ready_count)
    success_ratio = _ratio(len(successful_ready), ready_count)
    hard_link_ratio = _ratio(claims_with_links, claims_total)
    corroboration_ratio = _ratio(corroborated_claims, claims_total)
    conflict_ratio = _ratio(conflicted_claims, claims_total)

    score = round(
        100
        * max(
            0.0,
            min(
                1.0,
                0.35 * execution_ratio
                + 0.20 * success_ratio
                + 0.25 * hard_link_ratio
                + 0.20 * corroboration_ratio
                - 0.15 * conflict_ratio,
            ),
        )
    )

    stop_reason = investigation.summary.stop_reason
    budget_limited = "BUDGET_EXHAUSTED" in str(stop_reason) or "DEADLINE" in str(stop_reason)
    if budget_limited:
        score = max(0, score - 5)

    gaps: list[dict[str, object]] = []
    gaps.extend(
        {
            "type": "READY_ADAPTER_NOT_EXECUTED",
            "source": name,
            "severity": "HIGH",
        }
        for name in missing_ready
    )
    gaps.extend(
        {
            "type": "AUTH_OR_DEPENDENCY_REQUIRED",
            "source": item["source"],
            "severity": "MEDIUM",
            "requires_key": item["requires_key"],
        }
        for item in blocked
    )
    gaps.extend(
        {
            "type": "CLAIM_WITHOUT_DIRECT_URL",
            "claim_id": item["claim_id"],
            "kind": item["kind"],
            "value": item["value"],
            "severity": "MEDIUM",
        }
        for item in linkless_claims
    )
    if budget_limited:
        gaps.append(
            {
                "type": "SEARCH_BUDGET_LIMIT",
                "severity": "MEDIUM",
                "stop_reason": stop_reason,
            }
        )

    return {
        "version": "max2.v1",
        "label": "SHERLOCK MAX²",
        "score": score,
        "grade": _grade(score),
        "coverage": {
            "atlas_tools_considered": int(catalog.get("total_tools_considered", 0) or 0),
            "atlas_matching_tools": int(catalog.get("matching_tools", 0) or 0),
            "runtime_ready": ready_count,
            "runtime_executed": len(executed_ready),
            "runtime_successful": len(successful_ready),
            "runtime_execution_ratio": execution_ratio,
            "runtime_success_ratio": success_ratio,
            "claims": claims_total,
            "claims_with_direct_links": claims_with_links,
            "hard_link_ratio": hard_link_ratio,
            "corroborated_claims": corroborated_claims,
            "corroboration_ratio": corroboration_ratio,
            "conflicted_claims": conflicted_claims,
            "source_errors": investigation.summary.source_errors,
            "stop_reason": stop_reason,
        },
        "gaps": gaps[:120],
        "gap_count": len(gaps),
        "blocked_runtime_sources": blocked,
        "ready_but_not_executed": missing_ready,
        "next_best_sources": next_best,
        "truth": {
            "score_is_completeness_metric_not_identity_probability": True,
            "catalog_presence_is_not_execution": True,
            "absence_of_result_is_not_proof_of_absence": True,
            "direct_link_required_for_strongest_proof": True,
        },
    }


def _ratio(value: int, total: int) -> float:
    if total <= 0:
        return 1.0 if value == 0 else 0.0
    return round(value / total, 4)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "E"
