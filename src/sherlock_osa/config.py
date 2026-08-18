from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sherlock_osa import ENGINE_PIN
from sherlock_osa.errors import ConfigurationError


def load_env_file(path: str | Path) -> None:
    env_path = Path(path)
    if not env_path.exists():
        raise ConfigurationError("ENV_FILE_NOT_FOUND", f"Nie znaleziono pliku env: {env_path}")
    for line_number, raw_line in enumerate(env_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(
                "INVALID_ENV_FILE", f"Niepoprawna linia {line_number} w {env_path}."
            )
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _required(name: str, minimum: int) -> str:
    value = os.getenv(name, "").strip()
    if len(value) < minimum:
        raise ConfigurationError(
            "MISSING_SECRET", f"{name} musi mieć co najmniej {minimum} znaków."
        )
    return value


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError("INVALID_CONFIG", f"{name} musi być liczbą całkowitą.") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError("INVALID_CONFIG", f"{name} poza zakresem {minimum}..{maximum}.")
    return value


def _runtime_port_default() -> int:
    raw = os.getenv("PORT", "").strip()
    if not raw:
        return 8787
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError("INVALID_CONFIG", "PORT musi być liczbą całkowitą.") from exc
    if not 1 <= value <= 65535:
        raise ConfigurationError("INVALID_CONFIG", "PORT poza zakresem 1..65535.")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    api_key: str
    mission_signing_secret: str
    engine_url: str
    engine_api_key: str
    engine_commit_sha: str
    database_path: Path
    evidence_path: Path
    host: str = "127.0.0.1"
    port: int = 8787
    engine_timeout_seconds: int = 15
    max_body_bytes: int = 1_048_576
    max_mission_ttl_minutes: int = 1_440

    @classmethod
    def from_env(cls) -> "Settings":
        engine_sha = os.getenv("OSA_ENGINE_COMMIT_SHA", ENGINE_PIN).strip().lower()
        if len(engine_sha) != 40 or any(char not in "0123456789abcdef" for char in engine_sha):
            raise ConfigurationError("INVALID_ENGINE_SHA", "OSA_ENGINE_COMMIT_SHA musi być pełnym SHA-1.")
        engine_url = os.getenv("OSA_ENGINE_URL", "http://127.0.0.1:8643").strip().rstrip("/")
        if not engine_url.startswith(("http://", "https://")):
            raise ConfigurationError("INVALID_ENGINE_URL", "OSA_ENGINE_URL musi używać http:// lub https://.")
        runtime_port = _runtime_port_default()
        runtime_host = "0.0.0.0" if os.getenv("PORT", "").strip() else "127.0.0.1"
        return cls(
            api_key=_required("SHERLOCK_API_KEY", 24),
            mission_signing_secret=_required("SHERLOCK_MISSION_SIGNING_SECRET", 32),
            engine_url=engine_url,
            engine_api_key=_required("OSA_ACTIONS_API_KEY", 16),
            engine_commit_sha=engine_sha,
            database_path=Path(os.getenv("SHERLOCK_DATABASE_PATH", "./data/sherlock-osa.db")),
            evidence_path=Path(os.getenv("SHERLOCK_EVIDENCE_PATH", "./data/evidence.jsonl")),
            host=os.getenv("SHERLOCK_HOST", runtime_host).strip(),
            port=_integer("SHERLOCK_PORT", runtime_port, 1, 65535),
            engine_timeout_seconds=_integer("SHERLOCK_ENGINE_TIMEOUT_SECONDS", 15, 1, 120),
        )
