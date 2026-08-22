from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from sherlock_osa.errors import EngineError


@dataclass(frozen=True, slots=True)
class EngineMissionReceipt:
    mission_id: str
    execution_id: str
    state: str
    body: Mapping[str, Any]


class EngineGateway(Protocol):
    commit_sha: str

    def run_mission(self, draft: Mapping[str, Any]) -> EngineMissionReceipt: ...

    def probe(self) -> Mapping[str, Any]: ...


class OsaEngineClient:
    """Narrow HTTP adapter; OSA Engine remains the only natural-language router."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        commit_sha: str,
        timeout_seconds: int = 15,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.commit_sha = commit_sha
        self.timeout_seconds = timeout_seconds

    def _request(self, method: str, path: str, payload: object | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "sherlock-osa/0.1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(2_000_000)
        except urllib.error.HTTPError as exc:
            # Consume a bounded body but do not reflect Engine internals to API clients.
            exc.read(1024)
            raise EngineError(
                "ENGINE_HTTP_ERROR",
                f"OSA Engine zwrócił HTTP {exc.code}.",
                status=502,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise EngineError("ENGINE_UNAVAILABLE", f"Brak połączenia z OSA Engine: {exc}") from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EngineError("ENGINE_INVALID_JSON", "OSA Engine zwrócił niepoprawny JSON.") from exc

    def run_mission(self, draft: Mapping[str, Any]) -> EngineMissionReceipt:
        targets = draft.get("targets", [])
        capabilities = draft.get("allowed_capabilities", [])
        is_osint = draft.get("mission_family") == "PASSIVE_OSINT"
        payload = {
            "task": (
                "Compile and govern a passive OSINT research mission; raw identifiers must not be "
                "persisted in the Engine and direct .onion retrieval requires the isolated Tor worker"
                if is_osint
                else "Compile and govern a controlled security-lab mission using the capability "
                "broker; missing scope evidence must block execution"
            ),
            "goal": str(draft.get("goal", "")),
            "context": {
                "requirements": [
                    f"mission_mode={draft.get('mode')}",
                    f"exact_targets={json.dumps(targets, sort_keys=True, separators=(',', ':'))}",
                    f"allowed_capabilities={json.dumps(capabilities, sort_keys=True, separators=(',', ':'))}",
                    "default_deny=true",
                    "no_scope_evidence_means_no_execution=true",
                    "external_targets_require_independent_ownership_proof=true",
                    f"raw_osint_identifier_forwarded={'false' if is_osint else 'not_applicable'}",
                ],
                "repository": "HazEOskA/osa-execution-force-skills",
                "branch": "main",
                "commit_sha": self.commit_sha,
            },
        }
        body = self._request("POST", "/api/v2/missions/run", payload)
        if not isinstance(body, dict):
            raise EngineError("ENGINE_RECEIPT_INVALID", "Receipt Engine nie jest obiektem JSON.")
        context = body.get("context")
        if not isinstance(context, dict):
            context = {}
        mission_id = context.get("mission_id") or body.get("mission_id")
        execution_id = context.get("execution_id") or body.get("execution_id")
        state = body.get("state")
        if not all(isinstance(item, str) and item for item in (mission_id, execution_id, state)):
            raise EngineError(
                "ENGINE_RECEIPT_INVALID",
                "Receipt Engine nie zawiera mission_id, execution_id i state.",
            )
        if context.get("commit_sha") != self.commit_sha:
            raise EngineError(
                "ENGINE_RECEIPT_PIN_MISMATCH",
                "Receipt Engine nie jest związany z wymaganym commit SHA.",
            )
        return EngineMissionReceipt(mission_id, execution_id, state, body)

    def probe(self) -> Mapping[str, Any]:
        body = self._request("GET", "/openapi.json")
        info = body.get("info", {}) if isinstance(body, dict) else {}
        return {
            "reachable": True,
            "title": info.get("title") if isinstance(info, dict) else None,
            "version": info.get("version") if isinstance(info, dict) else None,
            "commit_sha": self.commit_sha,
        }
