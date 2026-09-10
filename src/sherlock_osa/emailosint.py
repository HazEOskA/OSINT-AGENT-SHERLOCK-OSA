from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sherlock_osa.errors import SherlockError


DEFAULT_EMAILOSINT_ENDPOINT = "https://api.emailosint.org/v1/lookup/email"
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
    "apikey",
    "accesskey",
    "privatekey",
    "clientsecret",
)
IDENTIFIER_EVENT_NAMES = frozenset(
    {
        "identifier_result",
        "identifier",
        "account",
        "account_result",
        "profile",
        "profile_result",
    }
)
BREACH_EVENT_NAMES = frozenset(
    {
        "data_breaches",
        "breaches",
        "breach_result",
        "breach_results",
    }
)
STEALER_EVENT_NAMES = frozenset(
    {
        "infostealer",
        "infostealer_logs",
        "stealer",
        "stealer_logs",
        "stealer_results",
    }
)
AI_EVENT_NAMES = frozenset(
    {
        "ai_summary",
        "summary",
        "profile_summary",
        "synthesis",
    }
)
DONE_EVENT_NAMES = frozenset({"done", "complete", "completed"})


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
            queue.extend(
                item
                for item in current
                if isinstance(item, (Mapping, list, tuple))
            )
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, Mapping):
        for key in (
            "items",
            "results",
            "data",
            "records",
            "accounts",
            "breaches",
            "logs",
            "profiles",
            "identifiers",
        ):
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
        for key in (
            "summary",
            "headline",
            "text",
            "message",
            "reason",
            "reasoning",
            "description",
            "explanation",
        ):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip()
    return None


def _parse_sse(raw: bytes) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    event_name = "message"
    data_lines: list[str] = []
    event_id: str | None = None

    for line in raw.decode("utf-8", errors="replace").splitlines() + [""]:
        if not line:
            if data_lines:
                payload_text = "\n".join(data_lines)
                try:
                    payload: Any = json.loads(payload_text)
                except json.JSONDecodeError:
                    payload = payload_text
                event: dict[str, Any] = {
                    "event": event_name,
                    "data": payload,
                    "index": len(events),
                }
                if event_id:
                    event["id"] = event_id
                events.append(event)
            event_name = "message"
            data_lines = []
            event_id = None
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip() or "message"
        elif line.startswith("id:"):
            event_id = line[3:].strip() or None
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())

    return {"transport": "sse", "events": events}


def _events(provider: Any) -> list[Mapping[str, Any]]:
    if not isinstance(provider, Mapping):
        return []
    raw = provider.get("events", [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _event_payloads(provider: Any, event_names: set[str] | frozenset[str]) -> list[Any]:
    wanted = {name.lower() for name in event_names}
    found: list[Any] = []
    for event in _events(provider):
        name = str(event.get("event", "")).lower()
        if name in wanted:
            found.append(event.get("data"))
    return found


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(value)


def _dedupe(items: Sequence[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for item in items:
        key = _canonical(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _extract_urls(value: Any, *, limit: int = 64) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 6 or len(urls) >= limit:
            return
        if isinstance(node, str):
            candidate = node.strip()
            if candidate.startswith(("http://", "https://")) and candidate not in seen:
                seen.add(candidate)
                urls.append(candidate[:2048])
            return
        if isinstance(node, Mapping):
            for child in list(node.values())[:128]:
                walk(child, depth + 1)
            return
        if isinstance(node, (list, tuple)):
            for child in list(node)[:128]:
                walk(child, depth + 1)

    walk(value)
    return urls


def _module_name(value: Any) -> str:
    if isinstance(value, Mapping):
        module = value.get("module")
        if isinstance(module, str) and module.strip():
            return module.strip()
        if isinstance(module, Mapping):
            name = module.get("name") or module.get("id") or module.get("module")
            if isinstance(name, str) and name.strip():
                return name.strip()
        for key in ("source", "provider", "platform", "service", "site", "name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        nested = value.get("data")
        if isinstance(nested, Mapping):
            nested_name = _module_name(nested)
            if nested_name != "unknown":
                return nested_name
    return "unknown"


def _fields_from_identifier_payload(payload: Any) -> Any:
    if not isinstance(payload, Mapping):
        return payload
    nested = payload.get("data")
    if isinstance(nested, Mapping) and "fields" in nested:
        return nested.get("fields")
    if "fields" in payload:
        return payload.get("fields")
    if isinstance(nested, Mapping):
        return nested
    return payload


def _presence_status(fields: Any) -> str:
    if not isinstance(fields, Mapping):
        return "OBSERVED"
    positives = []
    negatives = []
    for key in (
        "exists",
        "registered",
        "found",
        "account_exists",
        "valid",
        "present",
    ):
        value = fields.get(key)
        if value is True:
            positives.append(key)
        elif value is False:
            negatives.append(key)
    if positives:
        return "FOUND"
    if negatives:
        return "NOT_FOUND"
    if _extract_urls(fields, limit=1):
        return "OBSERVED"
    return "OBSERVED"


def _identity_signals(provider: Any) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    for index, event in enumerate(_events(provider)):
        event_name = str(event.get("event", "")).lower()
        if event_name not in IDENTIFIER_EVENT_NAMES:
            continue
        payload = event.get("data")
        fields = _fields_from_identifier_payload(payload)
        signal = {
            "source": _module_name(payload),
            "event": event_name,
            "event_index": int(event.get("index", index)),
            "status": _presence_status(fields),
            "fields": fields,
            "urls": _extract_urls(payload),
            "provider_payload": payload,
        }
        signals.append(signal)

    if not signals:
        raw_candidates = _find_first(
            provider,
            {
                "linked_accounts",
                "accounts",
                "identifiers",
                "profiles",
                "identifier_results",
            },
        )
        for index, payload in enumerate(_as_list(raw_candidates)):
            fields = _fields_from_identifier_payload(payload)
            signals.append(
                {
                    "source": _module_name(payload),
                    "event": "json_identifier",
                    "event_index": index,
                    "status": _presence_status(fields),
                    "fields": fields,
                    "urls": _extract_urls(payload),
                    "provider_payload": payload,
                }
            )

    return _dedupe(signals)


def _aggregate_event_results(
    provider: Any,
    event_names: set[str] | frozenset[str],
    fallback_names: set[str],
) -> tuple[list[Any], dict[str, Any]]:
    results: list[Any] = []
    summary: dict[str, Any] = {}

    for payload in _event_payloads(provider, event_names):
        if isinstance(payload, Mapping):
            for key in (
                "amount",
                "count",
                "total",
                "sources",
                "source_count",
                "first_seen",
                "last_seen",
            ):
                if key in payload and payload.get(key) is not None:
                    summary[key] = payload.get(key)
            nested = None
            for key in ("results", "items", "records", "data", "breaches", "logs"):
                candidate = payload.get(key)
                if isinstance(candidate, list):
                    nested = candidate
                    break
            if nested is not None:
                results.extend(nested)
            else:
                results.append(dict(payload))
        else:
            results.extend(_as_list(payload))

    if not results:
        fallback = _find_first(provider, fallback_names)
        results.extend(_as_list(fallback))

    return _dedupe(results), summary


def _ai_profile(provider: Any) -> dict[str, Any]:
    payload: Any = None
    event_payloads = _event_payloads(provider, AI_EVENT_NAMES)
    if event_payloads:
        payload = event_payloads[-1]
    if payload is None:
        payload = _find_first(
            provider,
            {
                "ai_summary",
                "profile_summary",
                "summary",
                "synthesis",
            },
        )

    if isinstance(payload, str):
        payload_map: dict[str, Any] = {"summary": payload}
    elif isinstance(payload, Mapping):
        payload_map = dict(payload)
    elif payload is None:
        payload_map = {}
    else:
        payload_map = {"value": payload}

    headline = _text(
        {
            "headline": payload_map.get("headline"),
            "summary": payload_map.get("summary"),
            "text": payload_map.get("text"),
        }
    )
    summary = _text(
        {
            "summary": payload_map.get("summary"),
            "text": payload_map.get("text"),
            "headline": payload_map.get("headline"),
        }
    )

    risk = payload_map.get("risk") or payload_map.get("risk_level") or payload_map.get("severity")
    reason = (
        payload_map.get("reason")
        or payload_map.get("reasoning")
        or payload_map.get("risk_reason")
        or payload_map.get("explanation")
    )

    return {
        "headline": headline,
        "summary": summary,
        "risk": risk,
        "reason": reason,
        "payload": payload_map,
    }


def _meta(provider: Any) -> dict[str, Any]:
    merged: dict[str, Any] = {}

    if isinstance(provider, Mapping):
        root_meta = provider.get("meta")
        if isinstance(root_meta, Mapping):
            merged.update(root_meta)

    for payload in _event_payloads(provider, DONE_EVENT_NAMES):
        if not isinstance(payload, Mapping):
            continue
        nested = payload.get("meta")
        if isinstance(nested, Mapping):
            merged.update(nested)
        else:
            for key, value in payload.items():
                if key in {
                    "first_seen",
                    "last_seen",
                    "duration_ms",
                    "lookup_id",
                    "sources",
                    "source_count",
                    "completed_at",
                }:
                    merged[key] = value

    first_seen = _find_first(merged, {"first_seen", "firstseen"})
    last_seen = _find_first(merged, {"last_seen", "lastseen"})
    return {
        **merged,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _event_counts(provider: Any) -> dict[str, int]:
    counts = Counter(str(event.get("event", "message")).lower() for event in _events(provider))
    return dict(sorted(counts.items()))


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
    safe_provider = _redact(provider)
    signals = _identity_signals(safe_provider)
    linked = [signal for signal in signals if signal.get("status") != "NOT_FOUND"]

    breaches, breach_summary = _aggregate_event_results(
        safe_provider,
        BREACH_EVENT_NAMES,
        {"data_breaches", "breaches", "breach_results", "breach_data"},
    )
    stealer, stealer_summary = _aggregate_event_results(
        safe_provider,
        STEALER_EVENT_NAMES,
        {"infostealer", "infostealer_logs", "stealer_logs", "stealer_results", "stealer"},
    )

    ai = _ai_profile(safe_provider)
    meta = _meta(safe_provider)

    risk_level = ai.get("risk")
    risk_reason = ai.get("reason")
    if risk_level is None:
        risk_raw = _find_first(
            safe_provider,
            {"risk", "risk_score", "risk_level", "severity"},
        )
        if isinstance(risk_raw, Mapping):
            risk_level = (
                risk_raw.get("level")
                or risk_raw.get("risk")
                or risk_raw.get("score")
                or risk_raw.get("severity")
            )
            risk_reason = risk_reason or _text(risk_raw)
        elif isinstance(risk_raw, (str, int, float)):
            risk_level = risk_raw

    if risk_level is None:
        if stealer:
            risk_level = "critical"
        elif breaches:
            risk_level = "high"
        elif linked:
            risk_level = "medium"
        else:
            risk_level = "low"

    event_counts = _event_counts(safe_provider)
    events = _events(safe_provider)
    summary_text = ai.get("summary") or ai.get("headline")

    return {
        "engine": "EMAILOSINT",
        "query": {"type": "EMAIL", "value": email},
        "identity": {
            "summary": summary_text,
            "ai_profile": ai,
            "signals": signals,
            "linked_accounts": linked,
            "counts": {
                "signals": len(signals),
                "linked_accounts": len(linked),
                "not_found": sum(1 for signal in signals if signal.get("status") == "NOT_FOUND"),
            },
        },
        "exposure": {
            "linked_accounts": linked,
            "breaches": breaches,
            "infostealer": stealer,
            "breach_summary": breach_summary,
            "infostealer_summary": stealer_summary,
            "counts": {
                "identity_signals": len(signals),
                "linked_accounts": len(linked),
                "breaches": len(breaches),
                "infostealer": len(stealer),
            },
        },
        "risk": {
            "level": risk_level,
            "reason": risk_reason,
            "provider_payload": ai.get("payload", {}),
        },
        "timeline": {
            "first_seen": meta.get("first_seen"),
            "last_seen": meta.get("last_seen"),
            "meta": meta,
        },
        "provenance": {
            "sources": sorted(
                {
                    str(signal.get("source", "unknown"))
                    for signal in signals
                    if signal.get("source")
                }
            ),
            "event_counts": event_counts,
            "events_total": len(events),
            "transport": (
                safe_provider.get("transport", "json")
                if isinstance(safe_provider, Mapping)
                else "json"
            ),
        },
        "removal": {
            "actions": _actions(linked, breaches, stealer),
        },
        "verification": {
            "lookup_completed": True,
            "provider": "EmailOSINT",
            "raw_provider_attached": True,
            "safe_provider_payload_preserved": True,
            "credential_values_redacted": True,
            "normalizer": "EMAILOSINT_PARITY_PLUS_V1",
        },
        "parity": {
            "safe_provider_payload_preserved": True,
            "events_total": len(events),
            "event_counts": event_counts,
            "identity_signal_count": len(signals),
            "linked_account_count": len(linked),
            "breach_result_count": len(breaches),
            "infostealer_result_count": len(stealer),
            "provider_source_count": len(
                {
                    str(signal.get("source", "unknown"))
                    for signal in signals
                    if signal.get("source")
                }
            ),
            "redaction": "CREDENTIAL_SECRET_TOKEN_COOKIE_SESSION_VALUES",
        },
        "provider": {
            "name": "EmailOSINT",
            "events": list(events),
            "raw": safe_provider,
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
            endpoint=str(
                getattr(settings, "emailosint_endpoint", DEFAULT_EMAILOSINT_ENDPOINT)
            ),
            api_key=str(getattr(settings, "emailosint_api_key", "")),
            auth_header=str(
                getattr(settings, "emailosint_auth_header", "Authorization")
            ),
            auth_scheme=str(getattr(settings, "emailosint_auth_scheme", "Bearer")),
            timeout_seconds=int(getattr(settings, "emailosint_timeout_seconds", 30)),
        )

    def lookup(self, raw: object) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise SherlockError(
                "INVALID_PAYLOAD",
                "Lookup body musi być obiektem JSON.",
            )
        email = raw.get("email")
        if not isinstance(email, str) or not EMAIL_PATTERN.fullmatch(email.strip()):
            raise SherlockError("INVALID_EMAIL", "Podaj poprawny adres email.")
        email = email.strip()

        headers = {
            "Accept": "text/event-stream, application/json;q=0.9",
            "Content-Type": "application/json",
            "User-Agent": "sherlock-osa/0.7.0",
        }
        if self.api_key:
            value = (
                f"{self.auth_scheme} {self.api_key}".strip()
                if self.auth_scheme
                else self.api_key
            )
            headers[self.auth_header] = value

        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps({"email": email}, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
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
