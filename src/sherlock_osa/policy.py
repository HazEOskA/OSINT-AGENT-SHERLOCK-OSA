from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from uuid import uuid4

from sherlock_osa.contracts import (
    CapabilityRequest,
    Decision,
    DecisionEffect,
    MissionMode,
    MissionScope,
    Target,
    TargetKind,
    parse_utc,
    utc_iso,
    utc_now,
)
from sherlock_osa.errors import SherlockError
from sherlock_osa.signing import sha256_json, verify_scope


LAB_ASSET_RE = re.compile(r"^lab://[a-z0-9](?:[a-z0-9._-]{0,62})$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MODE_CAPABILITIES: dict[MissionMode, frozenset[str]] = {
    MissionMode.RESEARCH_PASSIVE: frozenset(
        {
            "osint.username.lookup",
            "osint.domain.passive",
            "intel.indicator.enrich",
            "evidence.verify",
        }
    ),
    MissionMode.LAB_RANGE: frozenset(
        {
            "lab.http.probe",
            "lab.network.scan",
            "lab.attack.simulate",
            "blue.telemetry.replay",
            "evidence.verify",
        }
    ),
    MissionMode.AUTHORIZED_EXTERNAL: frozenset(
        {
            "external.http.probe",
            "external.network.scan",
            "evidence.verify",
        }
    ),
}

MODE_ROUTE: dict[MissionMode, str] = {
    MissionMode.RESEARCH_PASSIVE: "research-passive",
    MissionMode.LAB_RANGE: "range-only",
    MissionMode.AUTHORIZED_EXTERNAL: "external-allowlist",
}

PORT_CAPABILITIES = frozenset(
    {
        "lab.http.probe",
        "lab.network.scan",
        "external.http.probe",
        "external.network.scan",
    }
)


def _validate_domain(value: str) -> bool:
    lowered = value.rstrip(".").lower()
    if not DOMAIN_RE.fullmatch(lowered):
        return False
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        return True
    return False


def validate_target_for_mode(mode: MissionMode, target: Target) -> None:
    if mode is MissionMode.LAB_RANGE:
        if target.kind is not TargetKind.LAB_ASSET or not LAB_ASSET_RE.fullmatch(target.value):
            raise SherlockError(
                "LAB_TARGET_MUST_BE_ASSET_ID",
                "LAB_RANGE wymaga nieadresowalnego targetu LAB_ASSET w formacie lab://<id>.",
            )
        return
    if mode is MissionMode.RESEARCH_PASSIVE:
        if target.ports:
            raise SherlockError(
                "PASSIVE_TARGET_HAS_PORTS", "RESEARCH_PASSIVE nie przyjmuje portów targetu."
            )
        if target.kind is TargetKind.USERNAME and USERNAME_RE.fullmatch(target.value):
            return
        if target.kind is TargetKind.DOMAIN and _validate_domain(target.value):
            return
        if target.kind is TargetKind.INDICATOR:
            indicator = target.value.lower()
            if indicator.startswith("sha256:") and SHA256_RE.fullmatch(indicator.removeprefix("sha256:")):
                return
        raise SherlockError(
            "INVALID_PASSIVE_TARGET",
            "RESEARCH_PASSIVE akceptuje USERNAME, DOMAIN albo INDICATOR sha256:<hash>.",
        )
    if mode is MissionMode.AUTHORIZED_EXTERNAL:
        if target.kind is TargetKind.DOMAIN and _validate_domain(target.value):
            return
        if target.kind is TargetKind.IP:
            try:
                ipaddress.ip_address(target.value)
                return
            except ValueError:
                pass
        raise SherlockError(
            "INVALID_EXTERNAL_TARGET", "AUTHORIZED_EXTERNAL wymaga dokładnej domeny albo adresu IP."
        )


def validate_scope_definition(
    *,
    mode: MissionMode,
    targets: tuple[Target, ...],
    capabilities: tuple[str, ...],
    ownership_proof: object | None,
) -> None:
    if not targets:
        raise SherlockError("TARGET_REQUIRED", "Misja wymaga co najmniej jednego targetu.")
    if len(targets) > 25:
        raise SherlockError("TOO_MANY_TARGETS", "v0.1 obsługuje maksymalnie 25 targetów.")
    if not capabilities:
        raise SherlockError("CAPABILITY_REQUIRED", "Misja wymaga co najmniej jednej capability.")
    if len(capabilities) != len(set(capabilities)):
        raise SherlockError("DUPLICATE_CAPABILITY", "Capability nie mogą się powtarzać.")
    allowed = MODE_CAPABILITIES[mode]
    unknown = sorted(set(capabilities) - allowed)
    if unknown:
        raise SherlockError(
            "CAPABILITY_MODE_MISMATCH", f"Capability niedozwolone w {mode.value}: {', '.join(unknown)}"
        )
    serialized_targets = [(target.kind.value, target.value, target.ports) for target in targets]
    if len(serialized_targets) != len(set(serialized_targets)):
        raise SherlockError("DUPLICATE_TARGET", "Targety nie mogą się powtarzać.")
    for target in targets:
        validate_target_for_mode(mode, target)
    if mode is MissionMode.AUTHORIZED_EXTERNAL:
        # The schema exists now, but accepting self-asserted proof would be a false gate.
        raise SherlockError(
            "OWNERSHIP_VERIFIER_UNAVAILABLE",
            "AUTHORIZED_EXTERNAL jest fail-closed: niezależny ownership verifier pozostaje UNBACKED.",
            status=409,
        )
    if ownership_proof is not None:
        raise SherlockError(
            "OWNERSHIP_PROOF_NOT_APPLICABLE",
            "ownership_proof jest dozwolony wyłącznie dla AUTHORIZED_EXTERNAL.",
        )


class CapabilityBroker:
    def __init__(self, signing_secret: str) -> None:
        self._signing_secret = signing_secret

    def _decision(
        self,
        request: CapabilityRequest,
        effect: DecisionEffect,
        code: str,
        reason: str,
        evaluated_at: datetime,
    ) -> Decision:
        return Decision(
            decision_id=str(uuid4()),
            effect=effect,
            reason_code=code,
            reason=reason,
            evaluated_at=utc_iso(evaluated_at),
            request_sha256=sha256_json(request.to_dict()),
        )

    def evaluate(
        self,
        scope: MissionScope,
        request: CapabilityRequest,
        *,
        evaluated_at: datetime | None = None,
    ) -> Decision:
        at = evaluated_at or utc_now()
        deny = lambda code, reason: self._decision(request, DecisionEffect.DENY, code, reason, at)

        if not verify_scope(scope, self._signing_secret):
            return deny("SIGNATURE_INVALID", "Podpis scope'u nie zgadza się z jego treścią.")
        if scope.mission_id != request.mission_id:
            return deny("MISSION_ID_MISMATCH", "Request nie należy do podpisanej misji.")
        if parse_utc(scope.created_at) > at:
            return deny("MISSION_NOT_YET_VALID", "Misja pochodzi z przyszłości.")
        if parse_utc(scope.expires_at) <= at:
            return deny("MISSION_EXPIRED", "Misja wygasła.")
        if scope.engine_state != "COMPLETED":
            return deny(
                "ENGINE_MISSION_NOT_COMPLETED",
                f"OSA Engine nie zakończył misji: {scope.engine_state}.",
            )
        if request.capability not in scope.allowed_capabilities:
            return deny("CAPABILITY_OUT_OF_SCOPE", "Capability nie występuje w podpisanym scope.")
        if request.capability not in MODE_CAPABILITIES[scope.mode]:
            return deny("CAPABILITY_MODE_MISMATCH", "Capability nie pasuje do trybu misji.")
        if request.route != MODE_ROUTE[scope.mode]:
            return deny("ROUTE_DENIED", "Trasa wykonania nie pasuje do trybu misji.")
        matching_targets = [target for target in scope.targets if target == request.target]
        if not matching_targets:
            return deny("TARGET_OUT_OF_SCOPE", "Target nie występuje dokładnie w podpisanym scope.")
        target = matching_targets[0]
        if request.capability in PORT_CAPABILITIES:
            if request.port is None:
                return deny("PORT_REQUIRED", "Ta capability wymaga dokładnego portu.")
            if request.port not in target.ports:
                return deny("PORT_OUT_OF_SCOPE", "Port nie występuje w podpisanym scope.")
        elif request.port is not None:
            return deny("PORT_NOT_APPLICABLE", "Ta capability nie przyjmuje portu.")
        if scope.mode is MissionMode.AUTHORIZED_EXTERNAL:
            return deny(
                "OWNERSHIP_VERIFIER_UNAVAILABLE",
                "Realne targety external pozostają zablokowane w v0.1.",
            )
        return self._decision(
            request,
            DecisionEffect.ALLOW,
            "SCOPE_MATCH",
            "Request dokładnie spełnia podpisany scope i policy trybu.",
            at,
        )
