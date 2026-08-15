from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

from sherlock_osa.contracts import MissionScope


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sign_payload(payload: Mapping[str, Any], secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()


def sign_scope(scope: MissionScope, secret: str) -> MissionScope:
    signature = sign_payload(scope.unsigned_dict(), secret)
    return MissionScope(**(scope.unsigned_dict() | {"mode": scope.mode, "targets": scope.targets,
        "allowed_capabilities": scope.allowed_capabilities, "ownership_proof": scope.ownership_proof,
        "signature": signature}))


def verify_scope(scope: MissionScope, secret: str) -> bool:
    expected = sign_payload(scope.unsigned_dict(), secret)
    return hmac.compare_digest(expected, scope.signature)


SENSITIVE_FRAGMENTS = ("secret", "token", "password", "credential", "authorization", "api_key")


def redact(value: object) -> object:
    """Remove common secret-bearing fields before persistence or hashing."""
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for raw_key, nested in value.items():
            key = str(raw_key)
            lowered = key.lower()
            output[key] = "[REDACTED]" if any(fragment in lowered for fragment in SENSITIVE_FRAGMENTS) else redact(nested)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value
