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

    def _do_get(self) -> None:
        path, _ = self._request_target()
        if path == "/api/v1/_unified-smoke":
            result = _service.full_search(
                {"kind": "USERNAME", "mode": "QUICK", "query": "octocat"}
            )
            plan = result.get("world_tool_plan") or {}
            proof = result.get("proof_report") or {}
            detective = result.get("detective") or {}
            self._json(
                200,
                {
                    "ok": bool(plan) and bool(proof),
                    "atlas": {
                        "considered": ((plan.get("catalog") or {}).get("total_tools_considered")),
                        "matching": ((plan.get("catalog") or {}).get("matching_tools")),
                        "runtime_ready": ((plan.get("runtime") or {}).get("ready_adapters")),
                        "runtime_blocked": ((plan.get("runtime") or {}).get("blocked_adapters")),
                    },
                    "execution": {
                        "sources": [
                            {
                                "source": row.get("source"),
                                "status": row.get("status"),
                                "evidence_count": row.get("evidence_count"),
                            }
                            for row in (detective.get("source_runs") or [])
                        ],
                        "summary": detective.get("summary") or {},
                    },
                    "proof": {
                        "claims": ((proof.get("summary") or {}).get("claims")),
                        "facts": ((proof.get("summary") or {}).get("facts")),
                        "correlated": ((proof.get("summary") or {}).get("correlated")),
                        "hash": ((proof.get("integrity") or {}).get("proof_report_sha256")),
                    },
                },
            )
            return
        return super()._do_get()
