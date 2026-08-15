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
    payload = {
        "goal": "Verify the public replay policy and evidence chain for Juice Shop",
        "mode": "LAB_RANGE",
        "targets": [
            {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]}
        ],
        "allowed_capabilities": ["lab.http.probe"],
        "ttl_minutes": 15,
        "operator_id": "smoke-demo",
    }
    result = PublicDemoService().public_demo_replay(payload)
    evidence = result["evidence"]["verification"]
    receipt = result["execution"]["receipt"]
    summary = {
        "deployment_mode": result["deployment_mode"],
        "decision": result["decision"]["decision"]["effect"],
        "replay_valid": result["replay"]["valid"],
        "ledger_valid": evidence["valid"],
        "ledger_records": evidence["record_count"],
        "live_engine_called": result["truth"]["live_engine_called"],
        "network_effect": receipt["network_effect_performed"],
        "shell_effect": receipt["shell_effect_performed"],
    }
    print(json.dumps(summary, indent=2))
    expected = {
        "deployment_mode": "PUBLIC_PASSIVE_OSINT",
        "decision": "ALLOW",
        "replay_valid": True,
        "ledger_valid": True,
        "ledger_records": 5,
        "live_engine_called": False,
        "network_effect": False,
        "shell_effect": False,
    }
    return 0 if summary == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
