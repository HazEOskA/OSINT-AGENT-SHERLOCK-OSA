from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.demo import PublicDemoService  # noqa: E402


def main() -> int:
    service = PublicDemoService()
    result = service.osint_investigate(
        {
            "query": "+48 500 600 700",
            "kind": "PHONE",
            "default_region": "PL",
            "purpose": "SELF_AUDIT",
            "include_darkweb": False,
            "consent": True,
        }
    )
    skills = {entry["skill_id"] for entry in result["execution_trace"]}
    summary = {
        "deployment_mode": result["deployment_mode"],
        "query_kind": result["query"]["kind"],
        "normalized": result["query"]["value"],
        "skills_executed": sorted(skills),
        "findings": result["summary"]["finding_count"],
        "ledger_valid": result["evidence"]["verification"]["valid"],
        "raw_query_persisted": result["evidence"]["raw_query_persisted"],
        "raw_breach_records_returned": result["truth"]["raw_breach_records_returned"],
        "tor_crawl_performed": result["truth"]["tor_crawl_performed"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    required = {
        "osint.query-classification",
        "osint.phone-intelligence",
        "osint.pivot-correlation",
        "osint.evidence-report",
    }
    return 0 if (
        summary["deployment_mode"] == "PUBLIC_PASSIVE_OSINT"
        and summary["query_kind"] == "PHONE"
        and summary["normalized"] == "+48500600700"
        and required <= skills
        and summary["findings"] >= 1
        and summary["ledger_valid"] is True
        and summary["raw_query_persisted"] is False
        and summary["raw_breach_records_returned"] is False
        and summary["tor_crawl_performed"] is False
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
