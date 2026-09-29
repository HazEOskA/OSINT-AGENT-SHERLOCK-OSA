from types import SimpleNamespace

from sherlock_osa.findings import SourceRun
from sherlock_osa.max2 import build_max2_report


def test_max2_scores_runtime_execution_and_surfaces_gaps() -> None:
    investigation = SimpleNamespace(
        source_runs=(
            SourceRun(
                source="github.username",
                source_family="CODE_IDENTITY",
                status="COMPLETED",
                evidence_count=1,
                duration_ms=120,
            ),
        ),
        summary=SimpleNamespace(
            source_errors=0,
            stop_reason="NO_MORE_TRUSTED_PIVOTS",
        ),
    )
    world_tool_plan = {
        "catalog": {"total_tools_considered": 900, "matching_tools": 120},
        "runtime": {
            "plan": [
                {
                    "name": "github.username",
                    "family": "CODE_IDENTITY",
                    "execution": "EXECUTE",
                    "requires_key": False,
                },
                {
                    "name": "hibp.account",
                    "family": "EXPOSURE",
                    "execution": "AUTH_OR_DEPENDENCY_REQUIRED",
                    "requires_key": True,
                },
            ]
        },
        "candidates": [
            {
                "name": "Example passive source",
                "url": "https://example.com",
                "source": "OSINT Framework",
                "category": "Username",
                "match_score": 8,
                "execution_class": "CATALOG_ONLY",
            }
        ],
    }
    proof_report = {
        "summary": {"claims": 1, "claims_with_hard_links": 1},
        "claims": [
            {
                "claim_id": "claim-1",
                "kind": "USERNAME",
                "value": "octocat",
                "status": "CONFIRMED",
                "independent_source_count": 2,
                "evidence": [{"url": "https://github.com/octocat"}],
            }
        ],
    }

    report = build_max2_report(
        investigation=investigation,
        world_tool_plan=world_tool_plan,
        proof_report=proof_report,
    )

    assert report["version"] == "max2.v1"
    assert report["coverage"]["atlas_tools_considered"] == 900
    assert report["coverage"]["runtime_ready"] == 1
    assert report["coverage"]["runtime_executed"] == 1
    assert report["coverage"]["hard_link_ratio"] == 1.0
    assert report["coverage"]["corroboration_ratio"] == 1.0
    assert report["gap_count"] == 1
    assert report["gaps"][0]["type"] == "AUTH_OR_DEPENDENCY_REQUIRED"
    assert report["next_best_sources"][0]["status"] == "ADAPTER_REQUIRED"
    assert report["score"] >= 90
