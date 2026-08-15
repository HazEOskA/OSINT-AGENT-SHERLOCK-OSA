from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping

from sherlock_osa.errors import SherlockError


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_iso(value: datetime | None = None) -> str:
    return (value or utc_now()).astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise SherlockError("INVALID_TIMESTAMP", "Timestamp musi być niepustym stringiem.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SherlockError("INVALID_TIMESTAMP", f"Niepoprawny timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise SherlockError("INVALID_TIMESTAMP", "Timestamp musi zawierać strefę czasową.")
    return parsed.astimezone(UTC)


def require_mapping(value: object, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SherlockError("INVALID_PAYLOAD", f"{field_name} musi być obiektem JSON.")
    return value


def require_string(value: object, *, field_name: str, minimum: int = 1, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise SherlockError("INVALID_PAYLOAD", f"{field_name} musi być stringiem.")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise SherlockError(
            "INVALID_PAYLOAD",
            f"{field_name} musi mieć od {minimum} do {maximum} znaków.",
        )
    return normalized


def require_int(value: object, *, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SherlockError("INVALID_PAYLOAD", f"{field_name} musi być liczbą całkowitą.")
    if not minimum <= value <= maximum:
        raise SherlockError(
            "INVALID_PAYLOAD", f"{field_name} musi być w zakresie {minimum}..{maximum}."
        )
    return value


class MissionMode(StrEnum):
    RESEARCH_PASSIVE = "RESEARCH_PASSIVE"
    LAB_RANGE = "LAB_RANGE"
    AUTHORIZED_EXTERNAL = "AUTHORIZED_EXTERNAL"


class TargetKind(StrEnum):
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    INDICATOR = "INDICATOR"
    LAB_ASSET = "LAB_ASSET"
    IP = "IP"


class DecisionEffect(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class BackingStatus(StrEnum):
    BACKED_SIMULATION = "BACKED_SIMULATION"
    UNBACKED = "UNBACKED"


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    value: str
    ports: tuple[int, ...] = ()

    @classmethod
    def from_dict(cls, raw: object) -> "Target":
        data = require_mapping(raw, field_name="target")
        try:
            kind = TargetKind(require_string(data.get("kind"), field_name="target.kind", maximum=40))
        except ValueError as exc:
            raise SherlockError("INVALID_TARGET_KIND", "Nieznany target.kind.") from exc
        value = require_string(data.get("value"), field_name="target.value", maximum=253)
        raw_ports = data.get("ports", [])
        if not isinstance(raw_ports, list):
            raise SherlockError("INVALID_PORTS", "target.ports musi być listą.")
        ports = tuple(
            sorted(
                {
                    require_int(port, field_name="target.ports[]", minimum=1, maximum=65535)
                    for port in raw_ports
                }
            )
        )
        return cls(kind=kind, value=value, ports=ports)

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "value": self.value, "ports": list(self.ports)}


@dataclass(frozen=True, slots=True)
class OwnershipProof:
    method: str
    subject: str
    artifact_sha256: str
    verified: bool
    verified_at: str
    expires_at: str

    @classmethod
    def from_dict(cls, raw: object | None) -> "OwnershipProof | None":
        if raw is None:
            return None
        data = require_mapping(raw, field_name="ownership_proof")
        verified = data.get("verified")
        if not isinstance(verified, bool):
            raise SherlockError("INVALID_OWNERSHIP_PROOF", "ownership_proof.verified musi być boolean.")
        return cls(
            method=require_string(data.get("method"), field_name="ownership_proof.method", maximum=40),
            subject=require_string(data.get("subject"), field_name="ownership_proof.subject", maximum=253),
            artifact_sha256=require_string(
                data.get("artifact_sha256"), field_name="ownership_proof.artifact_sha256", minimum=64, maximum=64
            ).lower(),
            verified=verified,
            verified_at=require_string(
                data.get("verified_at"), field_name="ownership_proof.verified_at", maximum=40
            ),
            expires_at=require_string(
                data.get("expires_at"), field_name="ownership_proof.expires_at", maximum=40
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "subject": self.subject,
            "artifact_sha256": self.artifact_sha256,
            "verified": self.verified,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class MissionScope:
    mission_id: str
    goal: str
    mode: MissionMode
    targets: tuple[Target, ...]
    allowed_capabilities: tuple[str, ...]
    operator_id: str
    created_at: str
    expires_at: str
    engine_commit_sha: str
    engine_mission_id: str
    engine_execution_id: str
    engine_state: str
    engine_receipt_sha256: str
    ownership_proof: OwnershipProof | None = None
    signature: str = ""

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "mission_id": self.mission_id,
            "goal": self.goal,
            "mode": self.mode.value,
            "targets": [target.to_dict() for target in self.targets],
            "allowed_capabilities": list(self.allowed_capabilities),
            "operator_id": self.operator_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "engine_commit_sha": self.engine_commit_sha,
            "engine_mission_id": self.engine_mission_id,
            "engine_execution_id": self.engine_execution_id,
            "engine_state": self.engine_state,
            "engine_receipt_sha256": self.engine_receipt_sha256,
            "ownership_proof": self.ownership_proof.to_dict() if self.ownership_proof else None,
        }

    def to_dict(self) -> dict[str, object]:
        return self.unsigned_dict() | {"signature": self.signature}

    @classmethod
    def from_dict(cls, raw: object) -> "MissionScope":
        data = require_mapping(raw, field_name="mission_scope")
        raw_targets = data.get("targets")
        raw_capabilities = data.get("allowed_capabilities")
        if not isinstance(raw_targets, list) or not isinstance(raw_capabilities, list):
            raise SherlockError("INVALID_SCOPE", "Scope targets/capabilities muszą być listami.")
        try:
            mode = MissionMode(require_string(data.get("mode"), field_name="mode", maximum=40))
        except ValueError as exc:
            raise SherlockError("INVALID_MODE", "Nieznany tryb misji.") from exc
        capabilities = tuple(
            require_string(value, field_name="allowed_capabilities[]", maximum=120)
            for value in raw_capabilities
        )
        return cls(
            mission_id=require_string(data.get("mission_id"), field_name="mission_id", maximum=80),
            goal=require_string(data.get("goal"), field_name="goal", minimum=3, maximum=500),
            mode=mode,
            targets=tuple(Target.from_dict(item) for item in raw_targets),
            allowed_capabilities=capabilities,
            operator_id=require_string(data.get("operator_id"), field_name="operator_id", maximum=80),
            created_at=require_string(data.get("created_at"), field_name="created_at", maximum=40),
            expires_at=require_string(data.get("expires_at"), field_name="expires_at", maximum=40),
            engine_commit_sha=require_string(
                data.get("engine_commit_sha"), field_name="engine_commit_sha", minimum=40, maximum=40
            ),
            engine_mission_id=require_string(
                data.get("engine_mission_id"), field_name="engine_mission_id", maximum=100
            ),
            engine_execution_id=require_string(
                data.get("engine_execution_id"), field_name="engine_execution_id", maximum=100
            ),
            engine_state=require_string(data.get("engine_state"), field_name="engine_state", maximum=40),
            engine_receipt_sha256=require_string(
                data.get("engine_receipt_sha256"), field_name="engine_receipt_sha256", minimum=64, maximum=64
            ),
            ownership_proof=OwnershipProof.from_dict(data.get("ownership_proof")),
            signature=require_string(data.get("signature"), field_name="signature", minimum=64, maximum=64),
        )


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    mission_id: str
    capability: str
    target: Target
    route: str
    port: int | None = None
    request_id: str = ""

    @classmethod
    def from_dict(cls, raw: object) -> "CapabilityRequest":
        data = require_mapping(raw, field_name="capability_request")
        raw_port = data.get("port")
        port = None
        if raw_port is not None:
            port = require_int(raw_port, field_name="port", minimum=1, maximum=65535)
        return cls(
            mission_id=require_string(data.get("mission_id"), field_name="mission_id", maximum=80),
            capability=require_string(data.get("capability"), field_name="capability", maximum=120),
            target=Target.from_dict(data.get("target")),
            route=require_string(data.get("route"), field_name="route", maximum=80),
            port=port,
            request_id=require_string(
                data.get("request_id", "client-request"), field_name="request_id", maximum=100
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "mission_id": self.mission_id,
            "capability": self.capability,
            "target": self.target.to_dict(),
            "route": self.route,
            "port": self.port,
            "request_id": self.request_id,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: str
    effect: DecisionEffect
    reason_code: str
    reason: str
    evaluated_at: str
    request_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "decision_id": self.decision_id,
            "effect": self.effect.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at,
            "request_sha256": self.request_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    execution_id: str
    mission_id: str
    decision_id: str
    adapter_id: str
    operation: str
    network_effect_performed: bool
    shell_effect_performed: bool
    result_sha256: str
    created_at: str
    output: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_id": self.execution_id,
            "mission_id": self.mission_id,
            "decision_id": self.decision_id,
            "adapter_id": self.adapter_id,
            "operation": self.operation,
            "network_effect_performed": self.network_effect_performed,
            "shell_effect_performed": self.shell_effect_performed,
            "result_sha256": self.result_sha256,
            "created_at": self.created_at,
            "output": dict(self.output),
        }
