from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.support import build_test_service, lab_payload  # noqa: E402


def main() -> int:
    with TemporaryDirectory() as directory:
        service, engine = build_test_service(Path(directory))
        mission_response = service.create_mission(lab_payload())
        mission = mission_response["mission"]
        decision = service.decide(
            {
                "mission_id": mission["mission_id"],
                "capability": "lab.http.probe",
                "target": {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]},
                "route": "range-only",
                "port": 3000,
                "request_id": "smoke-v0.1",
            }
        )["decision"]
        execution = service.simulate({"decision_id": decision["decision_id"]})["receipt"]
        replay = service.replay(mission["mission_id"])
        result = {
            "engine_calls": len(engine.calls),
            "engine_state": mission["engine_state"],
            "signature_valid": service.get_mission(mission["mission_id"])["signature_valid"],
            "decision": decision["effect"],
            "network_effect_performed": execution["network_effect_performed"],
            "shell_effect_performed": execution["shell_effect_performed"],
            "replay_valid": replay["valid"],
            "ledger": service.verify_evidence(),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        expected = (
            result["engine_calls"] == 1
            and result["engine_state"] == "COMPLETED"
            and result["signature_valid"] is True
            and result["decision"] == "ALLOW"
            and result["network_effect_performed"] is False
            and result["shell_effect_performed"] is False
            and result["replay_valid"] is True
            and result["ledger"]["valid"] is True
        )
        return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
