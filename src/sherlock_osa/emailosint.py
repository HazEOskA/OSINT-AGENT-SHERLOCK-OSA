from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from sherlock_osa.errors import SherlockError


DEFAULT_EMAILOSINT_ENDPOINT = "https://www.emailosint.org/v1/lookup/email"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "credential",
    "secret",
    "token",
    "cookie",
    "session",
    "authorization",
)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            normalized = re.sub(r"[^a-z0-9]", "", name.lower())
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                cleaned[name] = "[REDACTED]"
            else:
                cleaned[name] = _redact(item)
        return cleaned
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value


def _find_first(value: Any, names: set[str]) -> Any:
    wanted = {name.lower() for name in names}
    queue = [value]
    while queue:
        current = queue.pop(0)
        if isinstance(current, Mapping):
            for key, item in current.items():
                if str(key).lower() in wanted:
                    return item
                if isinstance(item, (Mapping, list, tuple)):
                    queue.append(item)
        elif isinstance(current, (list, tuple)):
            queue.extend(item for item in current if isinstance(item, (Mapping, list, tuple)))
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, Mapping):
        for key in ("items", "results", "data", "records", "accounts", "breaches", "logs"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
        return [dict(value)]
    return [value]


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, Mapping):
        for key in ("summary", "text", "message", "reason", "description"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
    return None


def _parse_sse(raw: bytes) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    event_name = "message"
    data_lines: list[str] = []
    for line in raw.decode("utf-8", errors="replace").splitlines() + [""]:
        if not line:
            if data_lines:
                payload_text = "\n".join(data_lines)
                try:
                    payload: Any = json.loads(payload_text)
                except json.JSONDecodeError:
                    payload = payload_text
                events.append({"event": event_name, "data": payload})
            event_name = "message"
            data_lines = []
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip() or "message"
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    return {"events": events}


def _event_payloads(provider: Any, event_names: set[str]) -> list[Any]:
    events = provider.get("events", []) if isinstance(provider, Mapping) else []
    found: list[Any] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        name = str(event.get("event", "")).lower()
        if name in event_names:
            data = event.get("data")
            found.extend(_as_list(data))
    return found


def _actions(accounts: list[Any], breaches: list[Any], stealer: list[Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if stealer:
        actions.append(
            {
                "priority": "CRITICAL",
                "title": "Unieważnij aktywne sesje i zmień hasła",
                "reason": "Wynik zawiera sygnały infostealera.",
                "steps": [
                    "Wyloguj wszystkie aktywne sesje na dotkniętych usługach.",
                    "Zmień hasła zaczynając od poczty i kont odzyskiwania.",
                    "Włącz MFA i przeskanuj urządzenia, z których korzystałeś.",
                ],
            }
        )
    if breaches:
        actions.append(
            {
                "priority": "HIGH",
                "title": "Usuń skutki wycieków",
                "reason": "Adres pojawia się w danych breach.",
                "steps": [
                    "Zmień każde hasło, które mogło być używane ponownie.",
                    "Włącz MFA na ważnych kontach.",
                    "Sprawdź recovery email, numery telefonu i aktywne urządzenia.",
                ],
            }
        )
    if accounts:
        actions.append(
            {
                "priority": "MEDIUM",
                "title": "Przejrzyj połączone konta",
                "reason": "Znaleziono publiczne sygnały kont powiązanych z adresem.",
                "steps": [
                    "Usuń konta, których już nie używasz.",
                    "Ogranicz widoczność profilu i indeksowanie przez wyszukiwarki.",
                    "Odłącz stare integracje i aplikacje zewnętrzne.",
                ],
            }
        )
    actions.append(
        {
            "priority": "BASELINE",
            "title": "Zmniejsz ślad publiczny",
            "reason": "Warstwa privacy po lookupie.",
            "steps": [
                "Usuń niepotrzebne wyniki z profili i stron, którymi zarządzasz.",
                "Użyj formularzy opt-out brokerów danych, gdy pojawią się w wynikach.",
                "Po zmianach uruchom lookup ponownie i porównaj ekspozycję.",
            ],
        }
    )
    return actions


def _normalise(email: str, provider: Any) -> dict[str, Any]:
    linked = _as_list(
        _find_first(
            provider,
            {"linked_accounts", "accounts", "identifiers", "profiles", "identifier_results"},
        )
    )
    breaches = _as_list(
        _find_first(provider, {"data_breaches", "breaches", "breach_results", "breach_data"})
    )
    stealer = _as_list(
        _find_first(
            provider,
            {"infostealer", "infostealer_logs", "stealer_logs", "stealer_results", "stealer"},
        )
    )

    if isinstance(provider, Mapping) and provider.get("events"):
        linked.extend(_event_payloads(provider, {"identifier_result", "identifier", "account"}))
        breaches.extend(_event_payloads(provider, {"data_breaches", "breaches", "breach_result"}))
        stealer.extend(_event_payloads(provider, {"infostealer", "infostealer_logs", "stealer_logs"}))

    summary_raw = _find_first(provider, {"ai_summary", "profile_summary", "summary", "synthesis"})
    if isinstance(provider, Mapping) and provider.get("events"):
        event_summaries = _event_payloads(provider, {"ai_summary", "summary", "profile_summary"})
        if event_summaries:
            summary_raw = event_summaries[-1]
    summary = _text(summary_raw)

    risk_raw = _find_first(provider, {"risk", "risk_score", "risk_level", "severity"})
    risk_level: str | None = None
    risk_reason: str | None = None
    if isinstance(risk_raw, str):
        risk_level = risk_raw
    elif isinstance(risk_raw, (int, float)):
        risk_level = str(risk_raw)
    elif isinstance(risk_raw, Mapping):
        risk_level = _text(
            {
                "text": risk_raw.get("level")
                or risk_raw.get("risk")
                or risk_raw.get("score")
                or risk_raw.get("severity")
            }
        )
        risk_reason = _text(risk_raw)

    if risk_level is None:
        if stealer:
            risk_level = "critical"
        elif breaches:
            risk_level = "high"
        elif linked:
            risk_level = "medium"
        else:
            risk_level = "low"

    return {
        "engine": "EMAILOSINT",
        "query": {"type": "EMAIL", "value": email},
        "identity": {
            "summary": summary,
            "linked_accounts": linked,
        },
        "exposure": {
            "linked_accounts": linked,
            "breaches": breaches,
            "infostealer": stealer,
            "counts": {
                "linked_accounts": len(linked),
                "breaches": len(breaches),
                "infostealer": len(stealer),
            },
        },
        "risk": {
            "level": risk_level,
            "reason": risk_reason,
        },
        "removal": {
            "actions": _actions(linked, breaches, stealer),
        },
        "verification": {
            "lookup_completed": True,
            "provider": "EmailOSINT",
            "raw_provider_attached": True,
        },
        "provider": {
            "name": "EmailOSINT",
            "raw": _redact(provider),
        },
    }


@dataclass(frozen=True, slots=True)
class EmailOsintClient:
    endpoint: str = DEFAULT_EMAILOSINT_ENDPOINT
    api_key: str = ""
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    timeout_seconds: int = 30

    @classmethod
    def from_settings(cls, settings: Any) -> "EmailOsintClient":
        return cls(
            endpoint=str(getattr(settings, "emailosint_endpoint", DEFAULT_EMAILOSINT_ENDPOINT)),
            api_key=str(getattr(settings, "emailosint_api_key", "")),
            auth_header=str(getattr(settings, "emailosint_auth_header", "Authorization")),
            auth_scheme=str(getattr(settings, "emailosint_auth_scheme", "Bearer")),
            timeout_seconds=int(getattr(settings, "emailosint_timeout_seconds", 30)),
        )

    def lookup(self, raw: object) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise SherlockError("INVALID_PAYLOAD", "Lookup body musi być obiektem JSON.")
        email = raw.get("email")
        if not isinstance(email, str) or not EMAIL_PATTERN.fullmatch(email.strip()):
            raise SherlockError("INVALID_EMAIL", "Podaj poprawny adres email.")
        email = email.strip()

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "sherlock-osa/0.4.0",
        }
        if self.api_key:
            value = f"{self.auth_scheme} {self.api_key}".strip() if self.auth_scheme else self.api_key
            headers[self.auth_header] = value

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps({"email": email}, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read(5_000_000)
                content_type = response.headers.get("Content-Type", "").lower()
        except urllib.error.HTTPError as exc:
            exc.read(2048)
            raise SherlockError(
                "EMAILOSINT_HTTP_ERROR",
                f"EmailOSINT zwrócił HTTP {exc.code}.",
                status=502,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SherlockError(
                "EMAILOSINT_UNAVAILABLE",
                f"Brak połączenia z EmailOSINT: {exc}",
                status=502,
            ) from exc

        try:
            if "text/event-stream" in content_type:
                provider = _parse_sse(body)
            else:
                provider = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SherlockError(
                "EMAILOSINT_INVALID_RESPONSE",
                "EmailOSINT zwrócił niepoprawną odpowiedź.",
                status=502,
            ) from exc

        return _normalise(email, provider)
