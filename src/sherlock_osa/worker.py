from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

from sherlock_osa.contracts import (
    BackingStatus,
    CapabilityRequest,
    Decision,
    DecisionEffect,
    ExecutionReceipt,
    MissionScope,
    utc_iso,
)
from sherlock_osa.errors import SherlockError
from sherlock_osa.signing import sha256_json


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    adapter_id: str
    capabilities: tuple[str, ...]
    backing: BackingStatus
    network_effect: bool
    shell_effect: bool
    note: str

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "capabilities": list(self.capabilities),
            "backing": self.backing.value,
            "network_effect": self.network_effect,
            "shell_effect": self.shell_effect,
            "note": self.note,
        }


ADAPTERS = (
    AdapterDescriptor(
        "simulation.v0",
        (
            "osint.username.lookup",
            "osint.domain.passive",
            "intel.indicator.enrich",
            "lab.http.probe",
            "lab.network.scan",
            "lab.attack.simulate",
            "blue.telemetry.replay",
            "evidence.verify",
        ),
        BackingStatus.BACKED_SIMULATION,
        False,
        False,
        "Deterministic receipt only; performs no network or shell effect.",
    ),
    AdapterDescriptor(
        "research.tor-worker",
        ("osint.username.lookup", "osint.domain.passive", "intel.indicator.enrich"),
        BackingStatus.UNBACKED,
        True,
        False,
        "Planned: enforced gateway and passive-only source policy.",
    ),
    AdapterDescriptor(
        "range.microvm-worker",
        ("lab.http.probe", "lab.network.scan", "lab.attack.simulate"),
        BackingStatus.UNBACKED,
        True,
        True,
        "Planned: Firecracker boundary, optional gVisor and isolated range route.",
    ),
    AdapterDescriptor(
        "blue.zeek-wazuh",
        ("blue.telemetry.replay",),
        BackingStatus.UNBACKED,
        False,
        False,
        "Planned: mission-correlated network and endpoint telemetry.",
    ),
    AdapterDescriptor(
        "external.ownership-verifier",
        ("external.http.probe", "external.network.scan"),
        BackingStatus.UNBACKED,
        True,
        False,
        "Required before AUTHORIZED_EXTERNAL can leave fail-closed state.",
    ),
)


class SimulationWorker:
    adapter_id = "simulation.v0"

    def execute(
        self,
        *,
        scope: MissionScope,
        request: CapabilityRequest,
        decision: Decision,
    ) -> ExecutionReceipt:
        if decision.effect is not DecisionEffect.ALLOW:
            raise SherlockError("DECISION_DENIED", "Worker odmawia wykonania decyzji DENY.", status=409)
        if decision.request_sha256 != sha256_json(request.to_dict()):
            raise SherlockError(
                "DECISION_REQUEST_MISMATCH",
                "Request wykonania nie zgadza się z requestem zatwierdzonym przez broker.",
                status=409,
            )
        output: Mapping[str, Any] = {
            "status": "SIMULATED",
            "capability": request.capability,
            "target": request.target.to_dict(),
            "port": request.port,
            "route": request.route,
            "scope_sha256": sha256_json(scope.to_dict()),
            "truth": {
                "network_effect_performed": False,
                "shell_effect_performed": False,
                "security_tool_invoked": False,
            },
        }
        return ExecutionReceipt(
            execution_id=str(uuid4()),
            mission_id=scope.mission_id,
            decision_id=decision.decision_id,
            adapter_id=self.adapter_id,
            operation="DETERMINISTIC_SIMULATION",
            network_effect_performed=False,
            shell_effect_performed=False,
            result_sha256=sha256_json(output),
            created_at=utc_iso(),
            output=output,
        )
