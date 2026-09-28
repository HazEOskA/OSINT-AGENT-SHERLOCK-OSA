from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa import ENGINE_PIN  # noqa: E402
from sherlock_osa.api import handler_factory  # noqa: E402
from sherlock_osa.cli import build_service  # noqa: E402
from sherlock_osa.config import Settings  # noqa: E402


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


_settings = Settings(
    api_key=os.getenv("SHERLOCK_API_KEY", "").strip(),
    mission_signing_secret=(
        os.getenv("SHERLOCK_MISSION_SIGNING_SECRET", "").strip()
        or secrets.token_urlsafe(48)
    ),
    engine_url=os.getenv("OSA_ENGINE_URL", "http://127.0.0.1:8643").strip().rstrip("/"),
    engine_api_key=(
        os.getenv("OSA_ACTIONS_API_KEY", "").strip()
        or secrets.token_urlsafe(24)
    ),
    engine_commit_sha=os.getenv("OSA_ENGINE_COMMIT_SHA", ENGINE_PIN).strip().lower(),
    database_path=Path("/tmp/sherlock-osa.db"),
    evidence_path=Path("/tmp/sherlock-evidence.jsonl"),
    emailosint_endpoint=os.getenv(
        "EMAILOSINT_ENDPOINT",
        "https://emailosint.org/v1/lookup/email",
    ).strip().rstrip("/"),
    emailosint_api_key=os.getenv("EMAILOSINT_API_KEY", "").strip(),
    emailosint_auth_header=os.getenv("EMAILOSINT_AUTH_HEADER", "Authorization").strip(),
    emailosint_auth_scheme=os.getenv("EMAILOSINT_AUTH_SCHEME", "Bearer").strip(),
    emailosint_timeout_seconds=_int_env("EMAILOSINT_TIMEOUT_SECONDS", 30),
)

_service = build_service(_settings)
_service.deployment_mode = "PUBLIC_LIVE_RESEARCH_V3"
_BaseHandler = handler_factory(_service)


class handler(_BaseHandler):
    def _authorised(self) -> bool:
        path, _ = self._request_target()
        if path in {"/api/v1/search", "/api/v1/search/stream"}:
            return True
        return super()._authorised()
