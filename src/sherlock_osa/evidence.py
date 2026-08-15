from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from sherlock_osa.contracts import utc_iso
from sherlock_osa.signing import canonical_json, sha256_json


GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    valid: bool
    record_count: int
    head_hash: str
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "record_count": self.record_count,
            "head_hash": self.head_hash,
            "errors": list(self.errors),
        }


class EvidenceLedger:
    """Process-safe append ledger with deterministic SHA-256 chaining.

    This detects edits and reordering. It is not a WORM store and does not claim
    protection from an administrator who can rewrite and rehash the whole file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = threading.RLock()

    def _read_records_unlocked(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Niepoprawny JSON ledger line {line_number}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"Ledger line {line_number} nie jest obiektem")
                records.append(record)
        return records

    def records(self, *, mission_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            records = self._read_records_unlocked()
        if mission_id is None:
            return records
        return [
            record
            for record in records
            if isinstance(record.get("payload"), dict)
            and record["payload"].get("mission_id") == mission_id
        ]

    def append(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            verification = self._verify_unlocked()
            if not verification.valid:
                raise ValueError("Odmowa append: istniejący ledger nie przechodzi weryfikacji.")
            sequence = verification.record_count + 1
            record_without_hash: dict[str, Any] = {
                "sequence": sequence,
                "created_at": utc_iso(),
                "event_type": event_type,
                "payload": dict(payload),
                "previous_hash": verification.head_hash,
            }
            record = record_without_hash | {"hash": sha256_json(record_without_hash)}
            encoded = canonical_json(record) + b"\n"
            with self.path.open("ab", buffering=0) as handle:
                handle.write(encoded)
                os.fsync(handle.fileno())
            return record

    def _verify_unlocked(self) -> LedgerVerification:
        errors: list[str] = []
        previous = GENESIS_HASH
        try:
            records = self._read_records_unlocked()
        except ValueError as exc:
            return LedgerVerification(False, 0, GENESIS_HASH, (str(exc),))
        for index, record in enumerate(records, start=1):
            if record.get("sequence") != index:
                errors.append(f"sequence mismatch at {index}")
            if record.get("previous_hash") != previous:
                errors.append(f"previous_hash mismatch at {index}")
            claimed_hash = record.get("hash")
            unsigned = {key: value for key, value in record.items() if key != "hash"}
            expected_hash = sha256_json(unsigned)
            if claimed_hash != expected_hash:
                errors.append(f"hash mismatch at {index}")
            if isinstance(claimed_hash, str) and len(claimed_hash) == 64:
                previous = claimed_hash
            else:
                previous = expected_hash
        return LedgerVerification(not errors, len(records), previous, tuple(errors))

    def verify(self) -> LedgerVerification:
        with self._lock:
            return self._verify_unlocked()
