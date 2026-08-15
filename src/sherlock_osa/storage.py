from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping

from sherlock_osa.contracts import MissionScope
from sherlock_osa.errors import SherlockError
from sherlock_osa.signing import canonical_json


SCHEMA = """
CREATE TABLE IF NOT EXISTS missions (
    mission_id TEXT PRIMARY KEY,
    scope_json TEXT NOT NULL,
    engine_receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(mission_id),
    request_json TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decisions_mission_id ON decisions(mission_id);
"""


class MissionStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def create_mission(self, scope: MissionScope, engine_receipt: Mapping[str, Any]) -> None:
        with self._lock, self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO missions (mission_id, scope_json, engine_receipt_json, created_at) VALUES (?, ?, ?, ?)",
                    (
                        scope.mission_id,
                        canonical_json(scope.to_dict()).decode("utf-8"),
                        canonical_json(engine_receipt).decode("utf-8"),
                        scope.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SherlockError("MISSION_EXISTS", "Misja o tym ID już istnieje.", status=409) from exc

    def get_mission(self, mission_id: str) -> tuple[MissionScope, dict[str, Any]]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT scope_json, engine_receipt_json FROM missions WHERE mission_id = ?", (mission_id,)
            ).fetchone()
        if row is None:
            raise SherlockError("MISSION_NOT_FOUND", "Nie znaleziono misji.", status=404)
        scope = MissionScope.from_dict(json.loads(row["scope_json"]))
        receipt = json.loads(row["engine_receipt_json"])
        return scope, receipt

    def list_missions(self, *, limit: int = 100) -> list[MissionScope]:
        safe_limit = max(1, min(limit, 500))
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT scope_json FROM missions ORDER BY created_at DESC LIMIT ?", (safe_limit,)
            ).fetchall()
        return [MissionScope.from_dict(json.loads(row["scope_json"])) for row in rows]

    def save_decision(
        self,
        *,
        decision_id: str,
        mission_id: str,
        request: Mapping[str, Any],
        decision: Mapping[str, Any],
        created_at: str,
    ) -> None:
        with self._lock, self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO decisions (decision_id, mission_id, request_json, decision_json, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        decision_id,
                        mission_id,
                        canonical_json(request).decode("utf-8"),
                        canonical_json(decision).decode("utf-8"),
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SherlockError("DECISION_EXISTS", "Decyzja o tym ID już istnieje.", status=409) from exc

    def get_decision(self, decision_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT request_json, decision_json FROM decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone()
        if row is None:
            raise SherlockError("DECISION_NOT_FOUND", "Nie znaleziono decyzji.", status=404)
        return json.loads(row["request_json"]), json.loads(row["decision_json"])
