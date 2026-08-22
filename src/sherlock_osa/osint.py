from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from html.parser import HTMLParser
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
from uuid import uuid4

from sherlock_osa.contracts import require_mapping, require_string, utc_iso
from sherlock_osa.errors import SherlockError
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.signing import sha256_json


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", re.IGNORECASE)
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
PHONE_CHARS_RE = re.compile(r"^[+()\d\s.-]{7,32}$")
ALLOWED_PURPOSES = frozenset(
    {"SELF_AUDIT", "CONSENTED_RESEARCH", "JOURNALISM_PUBLIC_INTEREST", "CORPORATE_DEFENSE"}
)


class QueryKind(StrEnum):
    AUTO = "AUTO"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PERSON = "PERSON"
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    IP = "IP"


class AdapterStatus(StrEnum):
    COMPLETED = "COMPLETED"
    NO_MATCH = "NO_MATCH"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"
    PRIVATE_WORKER_REQUIRED = "PRIVATE_WORKER_REQUIRED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"


@dataclass(frozen=True, slots=True)
class OsintQuery:
    kind: QueryKind
    raw: str
    normalized: str
    masked: str
    default_region: str

    def public_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "value": self.normalized,
            "masked": self.masked,
            "default_region": self.default_region,
        }

    def evidence_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "masked": self.masked,
            "query_sha256": hashlib.sha256(self.normalized.encode("utf-8")).hexdigest(),
        }


@dataclass(frozen=True, slots=True)
class PreparedInvestigation:
    query: OsintQuery
    purpose: str
    include_darkweb: bool


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    skill_id: str
    version: str
    title: str
    accepts: tuple[QueryKind, ...]
    adapters: tuple[str, ...]
    effect: str
    description: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.skill_id,
            "version": self.version,
            "title": self.title,
            "accepts": [item.value for item in self.accepts],
            "adapters": list(self.adapters),
            "effect": self.effect,
            "description": self.description,
        }


@dataclass(slots=True)
class AdapterResult:
    adapter_id: str
    skill_id: str
    status: AdapterStatus
    message: str
    live: bool
    network_effect: bool
    findings: list[dict[str, object]] = field(default_factory=list)
    pivots: list[dict[str, object]] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "skill_id": self.skill_id,
            "status": self.status.value,
            "message": self.message,
            "live": self.live,
            "network_effect": self.network_effect,
            "duration_ms": self.duration_ms,
            "finding_count": len(self.findings),
            "pivot_count": len(self.pivots),
        }


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes
    content_type: str

    def json(self) -> object:
        return json.loads(self.body.decode("utf-8"))


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class FixedEgressHttpClient:
    """Small HTTP client that cannot be turned into an arbitrary URL fetcher."""

    allowed_hosts = frozenset(
        {
            "api.github.com",
            "api.xposedornot.com",
            "ahmia.fi",
            "leakcheck.io",
            "rdap.org",
            "www.wikidata.org",
        }
    )

    def __init__(self, *, timeout_seconds: float = 4.0, max_bytes: int = 1_500_000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.opener = build_opener(_NoRedirectHandler())

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            raise SherlockError("EGRESS_TARGET_DENIED", "Adapter próbował wyjść poza stałą allowlistę.")
        request_headers = {
            "Accept": "application/json,text/html;q=0.9",
            "User-Agent": "Sherlock-OSA/0.2 (+https://github.com/HazEOskA/OSINT-AGENT-SHERLOCK-OSA)",
            **dict(headers or {}),
        }
        request = Request(url, headers=request_headers, method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise SherlockError("SOURCE_RESPONSE_TOO_LARGE", "Źródło przekroczyło limit odpowiedzi.")
                return HttpResponse(
                    status=response.status,
                    body=body,
                    content_type=response.headers.get("Content-Type", ""),
                )
        except HTTPError as exc:
            body = exc.read(self.max_bytes)
            return HttpResponse(
                status=exc.code,
                body=body,
                content_type=exc.headers.get("Content-Type", "") if exc.headers else "",
            )


class SkillRegistry:
    def __init__(self, raw: Mapping[str, object]) -> None:
        skills_raw = raw.get("skills")
        if not isinstance(skills_raw, list):
            raise ValueError("Skill registry does not contain a skills list")
        skills: list[SkillDefinition] = []
        for entry in skills_raw:
            if not isinstance(entry, Mapping):
                raise ValueError("Invalid skill entry")
            accepts_raw = entry.get("accepts")
            adapters_raw = entry.get("adapters")
            if not isinstance(accepts_raw, list) or not isinstance(adapters_raw, list):
                raise ValueError("Invalid skill accepts/adapters")
            skills.append(
                SkillDefinition(
                    skill_id=str(entry["id"]),
                    version=str(entry["version"]),
                    title=str(entry["title"]),
                    accepts=tuple(QueryKind(str(value)) for value in accepts_raw),
                    adapters=tuple(str(value) for value in adapters_raw),
                    effect=str(entry["effect"]),
                    description=str(entry["description"]),
                )
            )
        if len({skill.skill_id for skill in skills}) != len(skills):
            raise ValueError("Duplicate skill ID")
        self.schema_version = str(raw.get("schema_version", ""))
        self.name = str(raw.get("registry", ""))
        self.source_of_truth = str(raw.get("source_of_truth", ""))
        self._skills = tuple(skills)
        self._by_id = {skill.skill_id: skill for skill in skills}

    @classmethod
    def load(cls) -> "SkillRegistry":
        from importlib.resources import files

        resource = files("sherlock_osa").joinpath("osint_skills.json")
        return cls(json.loads(resource.read_text(encoding="utf-8")))

    def get(self, skill_id: str) -> SkillDefinition:
        try:
            return self._by_id[skill_id]
        except KeyError as exc:
            raise SherlockError("SKILL_NOT_FOUND", f"Brak skilla: {skill_id}", status=500) from exc

    def all(self) -> tuple[SkillDefinition, ...]:
        return self._skills

    def resolve(self, kind: QueryKind, *, include_darkweb: bool) -> tuple[SkillDefinition, ...]:
        ordered = ["osint.query-classification"]
        ordered.extend(
            {
                QueryKind.EMAIL: ["osint.email-exposure"],
                QueryKind.PHONE: ["osint.phone-intelligence"],
                QueryKind.PERSON: ["osint.person-discovery"],
                QueryKind.USERNAME: ["osint.username-discovery"],
                QueryKind.DOMAIN: ["osint.domain-intelligence"],
                QueryKind.IP: ["osint.ip-intelligence"],
            }[kind]
        )
        if include_darkweb:
            ordered.append("osint.darkweb-index-search")
        ordered.extend(["osint.pivot-correlation", "osint.evidence-report"])
        return tuple(self.get(skill_id) for skill_id in ordered)


COUNTRY_CALLING_CODES: tuple[tuple[str, str, str], ...] = (
    ("1", "US/CA", "United States / Canada"),
    ("7", "RU/KZ", "Russia / Kazakhstan"),
    ("20", "EG", "Egypt"),
    ("27", "ZA", "South Africa"),
    ("30", "GR", "Greece"),
    ("31", "NL", "Netherlands"),
    ("32", "BE", "Belgium"),
    ("33", "FR", "France"),
    ("34", "ES", "Spain"),
    ("36", "HU", "Hungary"),
    ("39", "IT", "Italy / Vatican City"),
    ("40", "RO", "Romania"),
    ("41", "CH", "Switzerland"),
    ("43", "AT", "Austria"),
    ("44", "GB", "United Kingdom"),
    ("45", "DK", "Denmark"),
    ("46", "SE", "Sweden"),
    ("47", "NO", "Norway"),
    ("48", "PL", "Poland"),
    ("49", "DE", "Germany"),
    ("51", "PE", "Peru"),
    ("52", "MX", "Mexico"),
    ("53", "CU", "Cuba"),
    ("54", "AR", "Argentina"),
    ("55", "BR", "Brazil"),
    ("56", "CL", "Chile"),
    ("57", "CO", "Colombia"),
    ("58", "VE", "Venezuela"),
    ("60", "MY", "Malaysia"),
    ("61", "AU", "Australia"),
    ("62", "ID", "Indonesia"),
    ("63", "PH", "Philippines"),
    ("64", "NZ", "New Zealand"),
    ("65", "SG", "Singapore"),
    ("66", "TH", "Thailand"),
    ("81", "JP", "Japan"),
    ("82", "KR", "South Korea"),
    ("84", "VN", "Vietnam"),
    ("86", "CN", "China"),
    ("90", "TR", "Turkey"),
    ("91", "IN", "India"),
    ("92", "PK", "Pakistan"),
    ("93", "AF", "Afghanistan"),
    ("94", "LK", "Sri Lanka"),
    ("95", "MM", "Myanmar"),
    ("98", "IR", "Iran"),
    ("351", "PT", "Portugal"),
    ("352", "LU", "Luxembourg"),
    ("353", "IE", "Ireland"),
    ("354", "IS", "Iceland"),
    ("358", "FI", "Finland"),
    ("380", "UA", "Ukraine"),
    ("420", "CZ", "Czechia"),
    ("421", "SK", "Slovakia"),
)
REGION_PREFIX = {
    **{region: code for code, region, _ in COUNTRY_CALLING_CODES if "/" not in region},
    "US": "1",
    "CA": "1",
}


def _mask(value: str, kind: QueryKind) -> str:
    if kind is QueryKind.EMAIL:
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    if kind is QueryKind.PHONE:
        return f"{value[:3]}{'*' * max(3, len(value) - 6)}{value[-3:]}"
    if kind is QueryKind.PERSON:
        return " ".join(f"{part[:1]}***" for part in value.split())
    if kind is QueryKind.USERNAME:
        return f"{value[:2]}***" if len(value) > 2 else "***"
    return value


def _normalize_phone(value: str, default_region: str) -> str:
    if not PHONE_CHARS_RE.fullmatch(value):
        raise SherlockError("INVALID_PHONE", "Numer telefonu zawiera niedozwolone znaki.")
    compact = value.strip()
    starts_international = compact.startswith("+") or compact.startswith("00")
    digits = "".join(character for character in compact if character.isdigit())
    if compact.startswith("00"):
        digits = digits[2:]
    if not starts_international:
        prefix = REGION_PREFIX.get(default_region)
        if not prefix:
            raise SherlockError(
                "PHONE_COUNTRY_CODE_REQUIRED",
                "Podaj numer z prefiksem + albo obsługiwany region domyślny.",
            )
        digits = digits.lstrip("0")
        digits = prefix + digits
    if not 7 <= len(digits) <= 15 or digits.startswith("0"):
        raise SherlockError("INVALID_PHONE", "Numer nie spełnia zakresu E.164 (7–15 cyfr).")
    return f"+{digits}"


def _normalize_person(value: str) -> str:
    normalized = " ".join(value.split())
    parts = normalized.split(" ")
    if len(parts) < 2 or len(parts) > 8:
        raise SherlockError("INVALID_PERSON", "Imię i nazwisko musi mieć od 2 do 8 członów.")
    if any(not all(character.isalpha() or character in "-'" for character in part) for part in parts):
        raise SherlockError("INVALID_PERSON", "Imię i nazwisko zawiera niedozwolone znaki.")
    return normalized


def classify_query(value: str, requested: QueryKind, default_region: str) -> OsintQuery:
    raw = value.strip()
    if not raw or len(raw) > 253:
        raise SherlockError("INVALID_QUERY", "Zapytanie musi mieć od 1 do 253 znaków.")
    kind = requested
    if kind is QueryKind.AUTO:
        lowered = raw.lower().rstrip(".")
        if EMAIL_RE.fullmatch(raw):
            kind = QueryKind.EMAIL
        else:
            try:
                ipaddress.ip_address(raw)
                kind = QueryKind.IP
            except ValueError:
                if PHONE_CHARS_RE.fullmatch(raw) and len(re.sub(r"\D", "", raw)) >= 7:
                    kind = QueryKind.PHONE
                elif DOMAIN_RE.fullmatch(lowered):
                    kind = QueryKind.DOMAIN
                elif " " in raw:
                    kind = QueryKind.PERSON
                elif USERNAME_RE.fullmatch(raw):
                    kind = QueryKind.USERNAME
                else:
                    raise SherlockError(
                        "AMBIGUOUS_QUERY",
                        "Nie udało się rozpoznać typu. Wybierz go ręcznie.",
                    )

    if kind is QueryKind.EMAIL:
        normalized = raw.lower()
        if not EMAIL_RE.fullmatch(normalized):
            raise SherlockError("INVALID_EMAIL", "Niepoprawny adres e-mail.")
    elif kind is QueryKind.PHONE:
        normalized = _normalize_phone(raw, default_region)
    elif kind is QueryKind.PERSON:
        normalized = _normalize_person(raw)
    elif kind is QueryKind.USERNAME:
        normalized = raw
        if not USERNAME_RE.fullmatch(normalized):
            raise SherlockError("INVALID_USERNAME", "Username ma niepoprawny format.")
    elif kind is QueryKind.DOMAIN:
        try:
            normalized = raw.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SherlockError("INVALID_DOMAIN", "Domena ma niepoprawny format.") from exc
        if not DOMAIN_RE.fullmatch(normalized):
            raise SherlockError("INVALID_DOMAIN", "Domena ma niepoprawny format.")
    elif kind is QueryKind.IP:
        try:
            normalized = str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise SherlockError("INVALID_IP", "Adres IP ma niepoprawny format.") from exc
    else:
        raise SherlockError("INVALID_QUERY_KIND", "Nieobsługiwany typ zapytania.")
    return OsintQuery(
        kind=kind,
        raw=raw,
        normalized=normalized,
        masked=_mask(normalized, kind),
        default_region=default_region,
    )


def prepare_investigation(raw: object) -> PreparedInvestigation:
    """Validate a request before any provider, Engine or worker side effect."""

    data = require_mapping(raw, field_name="osint_investigation")
    if data.get("consent") is not True:
        raise SherlockError(
            "CONSENT_REQUIRED",
            "Potwierdź legalny cel i uprawnienie do przeprowadzenia researchu.",
            status=409,
        )
    purpose = require_string(data.get("purpose"), field_name="purpose", maximum=60)
    if purpose not in ALLOWED_PURPOSES:
        raise SherlockError("INVALID_PURPOSE", "Nieobsługiwany cel misji.")
    requested_raw = require_string(data.get("kind", "AUTO"), field_name="kind", maximum=20)
    try:
        requested = QueryKind(requested_raw)
    except ValueError as exc:
        raise SherlockError("INVALID_QUERY_KIND", "Nieobsługiwany typ zapytania.") from exc
    default_region = require_string(
        data.get("default_region", "PL"), field_name="default_region", maximum=12
    ).upper()
    query = classify_query(
        require_string(data.get("query"), field_name="query", maximum=253),
        requested,
        default_region,
    )
    include_darkweb = data.get("include_darkweb", True)
    if not isinstance(include_darkweb, bool):
        raise SherlockError("INVALID_PAYLOAD", "include_darkweb musi być boolean.")
    return PreparedInvestigation(query=query, purpose=purpose, include_darkweb=include_darkweb)


def _finding(
    *,
    category: str,
    title: str,
    value: str,
    source: str,
    source_url: str,
    confidence: str,
    verification: str,
    severity: str = "INFO",
    metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "category": category,
        "title": title,
        "value": value,
        "source": source,
        "source_url": source_url,
        "confidence": confidence,
        "verification": verification,
        "severity": severity,
        "observed_at": utc_iso(),
        "metadata": dict(metadata or {}),
    }
    payload["evidence_sha256"] = sha256_json(payload)
    payload["finding_id"] = payload["evidence_sha256"][:16]
    return payload


def _pivot(label: str, url: str, *, kind: str = "SEARCH") -> dict[str, object]:
    return {"label": label, "url": url, "kind": kind, "verified": False}


def _timed(adapter: Callable[[OsintQuery], AdapterResult], query: OsintQuery) -> AdapterResult:
    started = time.monotonic()
    try:
        result = adapter(query)
    except (TimeoutError, socket.timeout, URLError) as exc:
        result = AdapterResult(
            adapter_id=getattr(adapter, "adapter_id", adapter.__class__.__name__),
            skill_id=getattr(adapter, "skill_id", "unknown"),
            status=AdapterStatus.SOURCE_UNAVAILABLE,
            message=f"Źródło nie odpowiedziało: {exc.__class__.__name__}.",
            live=True,
            network_effect=True,
        )
    except SherlockError as exc:
        result = AdapterResult(
            adapter_id=getattr(adapter, "adapter_id", adapter.__class__.__name__),
            skill_id=getattr(adapter, "skill_id", "unknown"),
            status=AdapterStatus.SOURCE_UNAVAILABLE,
            message=f"{exc.code}: {exc.message}",
            live=True,
            network_effect=True,
        )
    result.duration_ms = max(0, round((time.monotonic() - started) * 1000))
    return result


class PhoneMetadataAdapter:
    adapter_id = "local.phone-metadata"
    skill_id = "osint.phone-intelligence"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        digits = query.normalized.removeprefix("+")
        match = next(
            (
                (code, region, country)
                for code, region, country in sorted(
                    COUNTRY_CALLING_CODES, key=lambda item: len(item[0]), reverse=True
                )
                if digits.startswith(code)
            ),
            None,
        )
        code, region, country = match or ("UNKNOWN", "UNKNOWN", "Unknown")
        finding = _finding(
            category="PHONE_METADATA",
            title="Znormalizowany numer",
            value=query.normalized,
            source="Sherlock OSA / E.164",
            source_url="https://www.itu.int/rec/T-REC-E.164",
            confidence="HIGH" if match else "MEDIUM",
            verification="MECHANICALLY_VERIFIED",
            metadata={
                "calling_code": f"+{code}" if code != "UNKNOWN" else code,
                "region": region,
                "country": country,
                "digit_count": len(digits),
                "valid_length": 7 <= len(digits) <= 15,
            },
        )
        encoded = quote(query.normalized)
        pivots = [
            _pivot("Google — dokładny numer", f"https://www.google.com/search?q=%22{encoded}%22"),
            _pivot("Bing — dokładny numer", f"https://www.bing.com/search?q=%22{encoded}%22"),
            _pivot("DuckDuckGo — dokładny numer", f"https://duckduckgo.com/?q=%22{encoded}%22"),
        ]
        return AdapterResult(
            adapter_id=self.adapter_id,
            skill_id=self.skill_id,
            status=AdapterStatus.COMPLETED,
            message="Numer znormalizowany lokalnie; carrier/owner nie są zgadywane.",
            live=True,
            network_effect=False,
            findings=[finding],
            pivots=pivots,
        )


class XposedOrNotAdapter:
    adapter_id = "xposedornot.community"
    skill_id = "osint.email-exposure"

    def __init__(self, http: FixedEgressHttpClient) -> None:
        self.http = http

    def __call__(self, query: OsintQuery) -> AdapterResult:
        url = f"https://api.xposedornot.com/v1/check-email/{quote(query.normalized, safe='')}?details=true"
        response = self.http.get(url)
        if response.status == 429:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.RATE_LIMITED,
                "XposedOrNot zwrócił limit zapytań.",
                True,
                True,
            )
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"XposedOrNot zwrócił niepoprawną odpowiedź HTTP {response.status}.",
                True,
                True,
            )
        if response.status == 404 or (isinstance(payload, Mapping) and payload.get("Error")):
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.NO_MATCH,
                "Brak dopasowania w indeksie XposedOrNot; to nie dowodzi braku innych wycieków.",
                True,
                True,
            )
        if response.status != 200 or not isinstance(payload, Mapping):
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"XposedOrNot zwrócił HTTP {response.status}.",
                True,
                True,
            )
        names: set[str] = set()

        def collect(value: object) -> None:
            if isinstance(value, str) and 1 <= len(value) <= 120:
                names.add(value)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(payload.get("breaches", []))
        findings = [
            _finding(
                category="BREACH_EXPOSURE",
                title="Znany wyciek danych",
                value=name,
                source="XposedOrNot",
                source_url="https://xposedornot.com/api_doc",
                confidence="HIGH",
                verification="SOURCE_REPORTED",
                severity="HIGH",
                metadata={"raw_record_returned": False},
            )
            for name in sorted(names)[:100]
        ]
        status = AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH
        message = (
            f"XposedOrNot wskazał {len(findings)} źródeł ekspozycji."
            if findings
            else "Źródło odpowiedziało, ale nie zwróciło nazw wycieków."
        )
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            status,
            message,
            True,
            True,
            findings=findings,
        )


class LeakCheckAdapter:
    adapter_id = "leakcheck.v2"

    def __init__(self, http: FixedEgressHttpClient, api_key: str) -> None:
        self.http = http
        self.api_key = api_key.strip()
        self.skill_id = "osint.phone-intelligence"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        self.skill_id = {
            QueryKind.EMAIL: "osint.email-exposure",
            QueryKind.PHONE: "osint.phone-intelligence",
            QueryKind.USERNAME: "osint.username-discovery",
        }[query.kind]
        if not self.api_key:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.REQUIRES_CONFIGURATION,
                "Wyszukiwanie wycieków e-mail/telefon/username wymaga LEAKCHECK_API_KEY.",
                False,
                False,
            )
        query_type = query.kind.value.lower()
        url = (
            f"https://leakcheck.io/api/v2/query/{quote(query.normalized, safe='')}?"
            + urlencode({"type": query_type, "limit": 100, "offset": 0})
        )
        response = self.http.get(url, headers={"X-API-Key": self.api_key})
        if response.status == 429:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.RATE_LIMITED,
                "LeakCheck zwrócił limit zapytań.",
                True,
                True,
            )
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        if response.status != 200 or not isinstance(payload, Mapping):
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"LeakCheck zwrócił HTTP {response.status}; surowe dane nie zostały zapisane.",
                True,
                True,
            )
        result_rows = payload.get("result", [])
        rows = result_rows if isinstance(result_rows, list) else []
        sources: set[str] = set()
        exposed_fields: set[str] = set()
        for row in rows[:1000]:
            if not isinstance(row, Mapping):
                continue
            source = row.get("source")
            if isinstance(source, Mapping):
                name = source.get("name")
                if isinstance(name, str) and name:
                    sources.add(name[:120])
            elif isinstance(source, str) and source:
                sources.add(source[:120])
            fields = row.get("fields")
            if isinstance(fields, list):
                exposed_fields.update(str(value)[:80] for value in fields if value)
        found_raw = payload.get("found", len(rows))
        found = found_raw if isinstance(found_raw, int) else len(rows)
        findings = [
            _finding(
                category="BREACH_EXPOSURE",
                title="Źródło wycieku",
                value=name,
                source="LeakCheck",
                source_url="https://leakcheck.io/",
                confidence="HIGH",
                verification="SOURCE_REPORTED",
                severity="HIGH",
                metadata={
                    "exposed_field_names": sorted(exposed_fields),
                    "raw_record_returned": False,
                },
            )
            for name in sorted(sources)[:100]
        ]
        status = AdapterStatus.COMPLETED if found or findings else AdapterStatus.NO_MATCH
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            status,
            (
                f"LeakCheck zgłosił {found} dopasowań w {len(sources)} źródłach; "
                "zwrócono wyłącznie metadane."
                if found or findings
                else "Brak dopasowania w skonfigurowanym indeksie LeakCheck."
            ),
            True,
            True,
            findings=findings,
        )


class PersonSearchPackAdapter:
    adapter_id = "local.search-pack"
    skill_id = "osint.person-discovery"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        exact = quote(f'"{query.normalized}"')
        parts = query.normalized.split()
        reversed_name = " ".join([parts[-1], *parts[:-1]])
        initial_name = " ".join([f"{parts[0][0]}.", *parts[1:]])
        reversed_exact = quote(f'"{reversed_name}"')
        initial_exact = quote(f'"{initial_name}"')
        github = quote(query.normalized)
        pivots = [
            _pivot("Google — dokładne imię i nazwisko", f"https://www.google.com/search?q={exact}"),
            _pivot("Bing — dokładne imię i nazwisko", f"https://www.bing.com/search?q={exact}"),
            _pivot("DuckDuckGo — dokładne imię i nazwisko", f"https://duckduckgo.com/?q={exact}"),
            _pivot(
                "Google — nazwisko, imię",
                f"https://www.google.com/search?q={reversed_exact}",
            ),
            _pivot(
                "Google — inicjał i nazwisko",
                f"https://www.google.com/search?q={initial_exact}",
            ),
            _pivot("GitHub — użytkownicy", f"https://github.com/search?q={github}&type=users"),
            _pivot("LinkedIn — publiczne profile", f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+{exact}"),
        ]
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED,
            "Wygenerowano kontrolowane pivoty; nie są oznaczane jako potwierdzone osoby.",
            True,
            False,
            pivots=pivots,
        )


class WikidataAdapter:
    adapter_id = "wikidata.search"
    skill_id = "osint.person-discovery"

    def __init__(self, http: FixedEgressHttpClient) -> None:
        self.http = http

    def __call__(self, query: OsintQuery) -> AdapterResult:
        params = urlencode(
            {
                "action": "wbsearchentities",
                "search": query.normalized,
                "language": "pl",
                "uselang": "pl",
                "format": "json",
                "limit": 5,
            }
        )
        response = self.http.get(f"https://www.wikidata.org/w/api.php?{params}")
        if response.status != 200:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"Wikidata zwróciła HTTP {response.status}.",
                True,
                True,
            )
        payload = response.json()
        search = payload.get("search", []) if isinstance(payload, Mapping) else []
        findings: list[dict[str, object]] = []
        if isinstance(search, list):
            for item in search[:5]:
                if not isinstance(item, Mapping):
                    continue
                entity_id = str(item.get("id", ""))
                label = str(item.get("label", query.normalized))
                description = str(item.get("description", "publiczna encja"))
                if entity_id:
                    findings.append(
                        _finding(
                            category="PERSON_CANDIDATE",
                            title=label,
                            value=description,
                            source="Wikidata",
                            source_url=f"https://www.wikidata.org/wiki/{quote(entity_id)}",
                            confidence="LOW",
                            verification="CANDIDATE_REQUIRES_CORRELATION",
                            metadata={"entity_id": entity_id},
                        )
                    )
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH,
            f"Wikidata zwróciła {len(findings)} kandydatów publicznych.",
            True,
            True,
            findings=findings,
        )


PROFILE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("GitHub", "https://github.com/{username}"),
    ("GitLab", "https://gitlab.com/{username}"),
    ("Reddit", "https://www.reddit.com/user/{username}"),
    ("Keybase", "https://keybase.io/{username}"),
    ("Medium", "https://medium.com/@{username}"),
    ("Twitch", "https://www.twitch.tv/{username}"),
    ("Vimeo", "https://vimeo.com/{username}"),
    ("Pinterest", "https://www.pinterest.com/{username}"),
    ("Hacker News", "https://news.ycombinator.com/user?id={username}"),
)


class ProfileMapAdapter:
    adapter_id = "local.profile-map"
    skill_id = "osint.username-discovery"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        encoded = quote(query.normalized)
        pivots = [
            _pivot(name, pattern.format(username=encoded), kind="PROFILE_CANDIDATE")
            for name, pattern in PROFILE_PATTERNS
        ]
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED,
            "Wygenerowano kandydatów; obecność kont potwierdzają live adaptery lub worker Sherlock/Maigret.",
            True,
            False,
            pivots=pivots,
        )


class GitHubProfileAdapter:
    adapter_id = "github.public-profile"
    skill_id = "osint.username-discovery"

    def __init__(self, http: FixedEgressHttpClient) -> None:
        self.http = http

    def __call__(self, query: OsintQuery) -> AdapterResult:
        response = self.http.get(f"https://api.github.com/users/{quote(query.normalized)}")
        if response.status == 404:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.NO_MATCH,
                "GitHub nie zwrócił publicznego profilu.",
                True,
                True,
            )
        if response.status != 200:
            status = AdapterStatus.RATE_LIMITED if response.status == 403 else AdapterStatus.SOURCE_UNAVAILABLE
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                status,
                f"GitHub API zwróciło HTTP {response.status}.",
                True,
                True,
            )
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise SherlockError("INVALID_SOURCE_RESPONSE", "GitHub API zwróciło niepoprawny JSON.")
        profile_url = str(payload.get("html_url", f"https://github.com/{quote(query.normalized)}"))
        finding = _finding(
            category="PUBLIC_PROFILE",
            title="Potwierdzony profil GitHub",
            value=str(payload.get("login", query.normalized)),
            source="GitHub public API",
            source_url=profile_url,
            confidence="HIGH",
            verification="LIVE_SOURCE_CONFIRMED",
            metadata={
                "display_name": payload.get("name"),
                "bio": payload.get("bio"),
                "company": payload.get("company"),
                "location": payload.get("location"),
                "public_repos": payload.get("public_repos"),
                "created_at": payload.get("created_at"),
            },
        )
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED,
            "GitHub potwierdził publiczny profil.",
            True,
            True,
            findings=[finding],
        )


class DnsAdapter:
    adapter_id = "local.dns"
    skill_id = "osint.domain-intelligence"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        try:
            rows = socket.getaddrinfo(query.normalized, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            rows = []
        addresses = sorted({str(row[4][0]) for row in rows})
        findings = [
            _finding(
                category="DNS_ADDRESS",
                title="Adres z resolvera DNS",
                value=address,
                source="System DNS resolver",
                source_url=f"https://rdap.org/ip/{quote(address)}",
                confidence="HIGH",
                verification="LIVE_DNS_RESOLUTION",
            )
            for address in addresses[:20]
        ]
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH,
            f"Resolver DNS zwrócił {len(findings)} unikalnych adresów.",
            True,
            True,
            findings=findings,
        )


class ReverseDnsAdapter:
    adapter_id = "local.reverse-dns"
    skill_id = "osint.ip-intelligence"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(query.normalized)
            names = sorted({hostname, *aliases})
        except (socket.herror, socket.gaierror):
            names = []
        findings = [
            _finding(
                category="REVERSE_DNS",
                title="Reverse DNS",
                value=name,
                source="System DNS resolver",
                source_url=f"https://rdap.org/ip/{quote(query.normalized)}",
                confidence="MEDIUM",
                verification="LIVE_DNS_RESOLUTION",
            )
            for name in names[:20]
        ]
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH,
            f"Reverse DNS zwrócił {len(findings)} nazw.",
            True,
            True,
            findings=findings,
        )


class RdapAdapter:
    adapter_id = "rdap.bootstrap"

    def __init__(self, http: FixedEgressHttpClient) -> None:
        self.http = http
        self.skill_id = "osint.domain-intelligence"

    def __call__(self, query: OsintQuery) -> AdapterResult:
        resource = "domain" if query.kind is QueryKind.DOMAIN else "ip"
        self.skill_id = (
            "osint.domain-intelligence" if resource == "domain" else "osint.ip-intelligence"
        )
        response = self.http.get(f"https://rdap.org/{resource}/{quote(query.normalized)}")
        if response.status == 404:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.NO_MATCH,
                "RDAP nie zwrócił rekordu.",
                True,
                True,
            )
        if response.status != 200:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"RDAP zwrócił HTTP {response.status}.",
                True,
                True,
            )
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise SherlockError("INVALID_SOURCE_RESPONSE", "RDAP zwrócił niepoprawny JSON.")
        statuses = payload.get("status", [])
        status_list = [str(item) for item in statuses] if isinstance(statuses, list) else []
        events_raw = payload.get("events", [])
        events: list[dict[str, object]] = []
        if isinstance(events_raw, list):
            for event in events_raw[:12]:
                if isinstance(event, Mapping):
                    events.append(
                        {
                            "action": event.get("eventAction"),
                            "date": event.get("eventDate"),
                        }
                    )
        label = str(payload.get("ldhName") or payload.get("name") or query.normalized)
        finding = _finding(
            category="RDAP_RECORD",
            title="Rekord RDAP",
            value=label,
            source="RDAP bootstrap",
            source_url=f"https://rdap.org/{resource}/{quote(query.normalized)}",
            confidence="HIGH",
            verification="LIVE_SOURCE_CONFIRMED",
            metadata={
                "handle": payload.get("handle"),
                "statuses": status_list,
                "events": events,
                "personal_contacts_omitted": True,
            },
        )
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED,
            "RDAP odpowiedział; dane kontaktowe rejestranta są celowo pomijane.",
            True,
            True,
            findings=[finding],
        )


class _AhmiaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href and (".onion" in href or "redirect_url=" in href):
            self._href = href
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href:
            href = self._href
            if "redirect_url=" in href:
                redirect = parse_qs(urlparse(href).query).get("redirect_url", [])
                if redirect:
                    href = redirect[0]
            title = " ".join("".join(self._text).split()) or "Wynik .onion"
            self.links.append((title[:160], href))
            self._href = None
            self._text = []


class AhmiaAdapter:
    adapter_id = "ahmia.clearnet-index"
    skill_id = "osint.darkweb-index-search"

    def __init__(self, http: FixedEgressHttpClient, *, enabled: bool) -> None:
        self.http = http
        self.enabled = enabled

    def __call__(self, query: OsintQuery) -> AdapterResult:
        if not self.enabled:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.REQUIRES_CONFIGURATION,
                "Indeks Ahmia jest wyłączony przez SHERLOCK_ENABLE_AHMIA.",
                False,
                False,
            )
        response = self.http.get(f"https://ahmia.fi/search/?{urlencode({'q': query.normalized})}")
        if response.status == 429:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.RATE_LIMITED,
                "Ahmia zwróciła limit zapytań.",
                True,
                True,
            )
        if response.status != 200:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"Ahmia zwróciła HTTP {response.status}.",
                True,
                True,
            )
        parser = _AhmiaParser()
        parser.feed(response.body.decode("utf-8", errors="replace"))
        unique: list[tuple[str, str]] = []
        seen: set[str] = set()
        for title, url in parser.links:
            if url in seen:
                continue
            seen.add(url)
            unique.append((title, url))
        findings = [
            _finding(
                category="DARKWEB_INDEX_MATCH",
                title=title,
                value=url,
                source="Ahmia clearnet index",
                source_url="https://ahmia.fi/",
                confidence="LOW",
                verification="INDEX_MATCH_NOT_CONTENT_VERIFIED",
                severity="MEDIUM",
                metadata={"tor_connection_used": False, "content_fetched": False},
            )
            for title, url in unique[:10]
        ]
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH,
            (
                f"Ahmia zwróciła {len(findings)} indeksowanych wyników; treść .onion nie była otwierana."
            ),
            True,
            True,
            findings=findings,
        )


class PrivateWorkerStatusAdapter:
    adapter_id = "worker.tor-research"
    skill_id = "osint.darkweb-index-search"

    def __init__(self, worker_url: str) -> None:
        self.worker_url = worker_url.strip()

    def __call__(self, query: OsintQuery) -> AdapterResult:
        if not self.worker_url:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.PRIVATE_WORKER_REQUIRED,
                "Bezpośredni crawl .onion wymaga prywatnego research workera za bramą Tor.",
                False,
                False,
            )
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.PRIVATE_WORKER_REQUIRED,
            "Worker jest skonfigurowany, ale publiczny endpoint nie deleguje crawl-a bez podpisanej misji OSA.",
            False,
            False,
        )


class TorResearchWorkerAdapter:
    adapter_id = "worker.tor-research"
    skill_id = "osint.darkweb-index-search"

    def __init__(
        self,
        *,
        worker_url: str,
        worker_token: str,
        execution_context: Mapping[str, object],
        timeout_seconds: float = 25.0,
        max_bytes: int = 1_000_000,
    ) -> None:
        self.worker_url = worker_url.rstrip("/")
        self.worker_token = worker_token
        self.execution_context = dict(execution_context)
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def __call__(self, query: OsintQuery) -> AdapterResult:
        if self.execution_context.get("engine_state") != "COMPLETED":
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.PRIVATE_WORKER_REQUIRED,
                "Worker Tor odmówił delegacji bez COMPLETED receipt z OSA Engine.",
                False,
                False,
            )
        if not self.worker_url or not self.worker_token:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.REQUIRES_CONFIGURATION,
                "Worker Tor wymaga OSA_RESEARCH_WORKER_URL i OSA_RESEARCH_WORKER_TOKEN.",
                False,
                False,
            )
        parsed = urlparse(self.worker_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query or parsed.fragment:
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.REQUIRES_CONFIGURATION,
                "OSA_RESEARCH_WORKER_URL ma niepoprawny format.",
                False,
                False,
            )
        payload = {
            "query": query.normalized,
            "kind": query.kind.value,
            "max_results": 5,
            "mission": {
                "engine_state": "COMPLETED",
                "engine_mission_id": self.execution_context.get("engine_mission_id"),
                "engine_execution_id": self.execution_context.get("engine_execution_id"),
                "engine_receipt_sha256": self.execution_context.get("engine_receipt_sha256"),
            },
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"{self.worker_url}/v1/search",
            data=body,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.worker_token}",
                "Content-Type": "application/json",
                "User-Agent": "Sherlock-OSA-Control-Plane/0.2",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_bytes + 1)
                status = response.status
        except HTTPError as exc:
            exc.read(1024)
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"Worker Tor zwrócił HTTP {exc.code}.",
                True,
                True,
            )
        if len(raw) > self.max_bytes:
            raise SherlockError("WORKER_RESPONSE_TOO_LARGE", "Worker Tor przekroczył limit odpowiedzi.")
        try:
            response_payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            response_payload = {}
        if status != 200 or not isinstance(response_payload, Mapping):
            return AdapterResult(
                self.adapter_id,
                self.skill_id,
                AdapterStatus.SOURCE_UNAVAILABLE,
                f"Worker Tor zwrócił niepoprawną odpowiedź HTTP {status}.",
                True,
                True,
            )
        matches_raw = response_payload.get("matches", [])
        matches = matches_raw if isinstance(matches_raw, list) else []
        findings: list[dict[str, object]] = []
        for item in matches[:5]:
            if not isinstance(item, Mapping):
                continue
            onion_url = str(item.get("url", ""))
            onion = urlparse(onion_url)
            content_sha = str(item.get("content_sha256", ""))
            if (
                onion.scheme not in {"http", "https"}
                or not onion.hostname
                or not onion.hostname.endswith(".onion")
                or not re.fullmatch(r"[0-9a-f]{64}", content_sha)
            ):
                continue
            content_bytes = item.get("content_bytes", 0)
            if not isinstance(content_bytes, int) or content_bytes < 0:
                content_bytes = 0
            findings.append(
                _finding(
                    category="DARKWEB_CONTENT_MATCH",
                    title=str(item.get("title", "Zweryfikowane dopasowanie .onion"))[:160],
                    value=onion_url,
                    source="Sherlock OSA private Tor worker",
                    source_url=onion_url,
                    confidence="MEDIUM",
                    verification="TOR_CONTENT_HASH_VERIFIED",
                    severity="HIGH",
                    metadata={
                        "content_sha256": content_sha,
                        "content_bytes": content_bytes,
                        "raw_content_returned": False,
                        "tor_route_reported": response_payload.get("transport") == "TOR_SOCKS5H",
                    },
                )
            )
        fetched = response_payload.get("pages_fetched", 0)
        status_value = AdapterStatus.COMPLETED if findings else AdapterStatus.NO_MATCH
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            status_value,
            f"Worker pobrał przez Tor {fetched} stron .onion i potwierdził {len(findings)} dopasowań.",
            True,
            True,
            findings=findings,
        )


class PrivateCliWorkerAdapter:
    adapter_id = "worker.private-cli"

    def __init__(self, skill_id: str, tools: Iterable[str]) -> None:
        self.skill_id = skill_id
        self.tools = tuple(tools)

    def __call__(self, query: OsintQuery) -> AdapterResult:
        return AdapterResult(
            self.adapter_id,
            self.skill_id,
            AdapterStatus.PRIVATE_WORKER_REQUIRED,
            "Pełna enumeracja jest dostępna w prywatnym workerze: " + ", ".join(self.tools) + ".",
            False,
            False,
        )


class OsintAgent:
    """Deterministic skill runner for passive, evidence-first OSINT."""

    def __init__(
        self,
        *,
        registry: SkillRegistry | None = None,
        http: FixedEgressHttpClient | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.registry = registry or SkillRegistry.load()
        self.http = http or FixedEgressHttpClient()
        self.environment = dict(os.environ if environment is None else environment)

    def capabilities(self) -> dict[str, object]:
        return {
            "registry": self.registry.name,
            "schema_version": self.registry.schema_version,
            "source_of_truth": self.registry.source_of_truth,
            "query_kinds": [kind.value for kind in QueryKind if kind is not QueryKind.AUTO],
            "purposes": sorted(ALLOWED_PURPOSES),
            "skills": [skill.to_dict() for skill in self.registry.all()],
            "providers": {
                "xposedornot.community": "READY",
                "leakcheck.v2": (
                    "READY" if self.environment.get("LEAKCHECK_API_KEY", "").strip() else "NEEDS_API_KEY"
                ),
                "ahmia.clearnet-index": (
                    "READY" if self._flag("SHERLOCK_ENABLE_AHMIA", True) else "DISABLED"
                ),
                "worker.tor-research": (
                    "CONFIGURED"
                    if self.environment.get("OSA_RESEARCH_WORKER_URL", "").strip()
                    and self.environment.get("OSA_RESEARCH_WORKER_TOKEN", "").strip()
                    else "PRIVATE_WORKER_REQUIRED"
                ),
            },
        }

    def _flag(self, name: str, default: bool) -> bool:
        raw = self.environment.get(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _adapters(
        self,
        query: OsintQuery,
        include_darkweb: bool,
        execution_context: Mapping[str, object] | None,
    ) -> list[Callable[[OsintQuery], AdapterResult]]:
        adapters: list[Callable[[OsintQuery], AdapterResult]] = []
        if query.kind is QueryKind.EMAIL:
            adapters.extend(
                [
                    XposedOrNotAdapter(self.http),
                    LeakCheckAdapter(self.http, self.environment.get("LEAKCHECK_API_KEY", "")),
                    PrivateCliWorkerAdapter("osint.email-exposure", ("Holehe",)),
                ]
            )
        elif query.kind is QueryKind.PHONE:
            adapters.extend(
                [
                    PhoneMetadataAdapter(),
                    LeakCheckAdapter(self.http, self.environment.get("LEAKCHECK_API_KEY", "")),
                    PrivateCliWorkerAdapter("osint.phone-intelligence", ("PhoneInfoga", "Ignorant")),
                ]
            )
        elif query.kind is QueryKind.PERSON:
            adapters.extend([PersonSearchPackAdapter(), WikidataAdapter(self.http)])
        elif query.kind is QueryKind.USERNAME:
            adapters.extend(
                [
                    ProfileMapAdapter(),
                    GitHubProfileAdapter(self.http),
                    LeakCheckAdapter(self.http, self.environment.get("LEAKCHECK_API_KEY", "")),
                    PrivateCliWorkerAdapter(
                        "osint.username-discovery", ("Sherlock", "Maigret", "WhatsMyName")
                    ),
                ]
            )
        elif query.kind is QueryKind.DOMAIN:
            adapters.extend(
                [
                    DnsAdapter(),
                    RdapAdapter(self.http),
                    PrivateCliWorkerAdapter(
                        "osint.domain-intelligence", ("Amass", "SpiderFoot", "Recon-ng")
                    ),
                ]
            )
        elif query.kind is QueryKind.IP:
            adapters.extend([ReverseDnsAdapter(), RdapAdapter(self.http)])
        if include_darkweb:
            adapters.append(
                AhmiaAdapter(self.http, enabled=self._flag("SHERLOCK_ENABLE_AHMIA", True))
            )
            worker_url = self.environment.get("OSA_RESEARCH_WORKER_URL", "").strip()
            worker_token = self.environment.get("OSA_RESEARCH_WORKER_TOKEN", "").strip()
            if execution_context and execution_context.get("engine_state") == "COMPLETED":
                adapters.append(
                    TorResearchWorkerAdapter(
                        worker_url=worker_url,
                        worker_token=worker_token,
                        execution_context=execution_context,
                    )
                )
            else:
                adapters.append(PrivateWorkerStatusAdapter(worker_url))
        return adapters

    def investigate(
        self,
        raw: object,
        *,
        execution_context: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        prepared = prepare_investigation(raw)
        return self.run_prepared(prepared, execution_context=execution_context)

    def run_prepared(
        self,
        prepared: PreparedInvestigation,
        *,
        execution_context: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        query = prepared.query
        purpose = prepared.purpose
        include_darkweb = prepared.include_darkweb
        investigation_id = str(uuid4())
        skills = self.registry.resolve(query.kind, include_darkweb=include_darkweb)
        adapters = self._adapters(query, include_darkweb, execution_context)

        with TemporaryDirectory(prefix="sherlock-osa-osint-") as temp_dir:
            ledger = EvidenceLedger(f"{temp_dir}/evidence.jsonl")
            ledger.append(
                "OSINT_QUERY_ACCEPTED",
                {
                    "investigation_id": investigation_id,
                    "query": query.evidence_dict(),
                    "purpose": purpose,
                    "consent": True,
                },
            )
            ledger.append(
                "OSINT_SKILL_PLAN_RESOLVED",
                {
                    "investigation_id": investigation_id,
                    "skills": [skill.skill_id for skill in skills],
                    "adapter_ids": [getattr(adapter, "adapter_id", "unknown") for adapter in adapters],
                },
            )
            results: list[AdapterResult] = []
            with ThreadPoolExecutor(max_workers=min(6, max(1, len(adapters)))) as pool:
                futures = {pool.submit(_timed, adapter, query): adapter for adapter in adapters}
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as exc:  # defensive isolation between optional sources
                        adapter = futures[future]
                        results.append(
                            AdapterResult(
                                adapter_id=getattr(adapter, "adapter_id", "unknown"),
                                skill_id=getattr(adapter, "skill_id", "unknown"),
                                status=AdapterStatus.SOURCE_UNAVAILABLE,
                                message=f"Adapter przerwał pracę: {exc.__class__.__name__}.",
                                live=True,
                                network_effect=True,
                            )
                        )
            results.sort(key=lambda item: (item.skill_id, item.adapter_id))
            findings = [finding for result in results for finding in result.findings]
            pivots = self._deduplicate_pivots(
                [pivot for result in results for pivot in result.pivots]
            )
            for result in results:
                ledger.append(
                    "OSINT_ADAPTER_FINISHED",
                    {
                        "investigation_id": investigation_id,
                        "adapter_id": result.adapter_id,
                        "skill_id": result.skill_id,
                        "status": result.status.value,
                        "finding_count": len(result.findings),
                        "result_sha256": sha256_json(
                            {
                                "status": result.status.value,
                                "findings": result.findings,
                                "pivots": result.pivots,
                            }
                        ),
                    },
                )
            summary = self._summary(findings, results)
            ledger.append(
                "OSINT_REPORT_CREATED",
                {
                    "investigation_id": investigation_id,
                    "summary": summary,
                    "finding_hashes": [str(item["evidence_sha256"]) for item in findings],
                },
            )
            verification = ledger.verify()
            records = ledger.records()

        trace = [
            {
                "skill_id": "osint.query-classification",
                "adapter_id": "local.identifier-normalizer",
                "status": "COMPLETED",
                "message": f"Rozpoznano {query.kind.value} i znormalizowano wejście.",
                "live": True,
                "network_effect": False,
                "duration_ms": 0,
                "finding_count": 0,
                "pivot_count": 0,
            },
            *[result.to_dict() for result in results],
            {
                "skill_id": "osint.pivot-correlation",
                "adapter_id": "local.entity-graph",
                "status": "COMPLETED",
                "message": f"Skorelowano {len(findings)} findings i {len(pivots)} pivotów bez zgadywania relacji.",
                "live": True,
                "network_effect": False,
                "duration_ms": 0,
                "finding_count": len(findings),
                "pivot_count": len(pivots),
            },
            {
                "skill_id": "osint.evidence-report",
                "adapter_id": "local.sha256-ledger",
                "status": "COMPLETED" if verification.valid else "SOURCE_UNAVAILABLE",
                "message": f"Ledger {'VALID' if verification.valid else 'INVALID'}: {verification.record_count} rekordów.",
                "live": True,
                "network_effect": False,
                "duration_ms": 0,
                "finding_count": 0,
                "pivot_count": 0,
            },
        ]
        return {
            "investigation_id": investigation_id,
            "created_at": utc_iso(),
            "deployment_mode": "PRIVATE_OSA_RUNTIME" if execution_context else "PUBLIC_PASSIVE_OSINT",
            "query": query.public_dict(),
            "purpose": purpose,
            "plan": {
                "resolver": "DETERMINISTIC_OSINT_SKILL_RESOLVER",
                "upstream_orchestrator": "OSA_EXECUTION_FORCE_ENGINE",
                "skills": [skill.to_dict() for skill in skills],
            },
            "summary": summary,
            "findings": findings,
            "pivots": pivots,
            "execution_trace": trace,
            "evidence": {
                "verification": verification.to_dict(),
                "records": records,
                "persistence": "PER_REQUEST",
                "raw_query_persisted": False,
            },
            "truth": {
                "agent_kind": "DETERMINISTIC_SKILL_RUNNER",
                "llm_used": False,
                "live_network_sources_called": sorted(
                    result.adapter_id for result in results if result.network_effect
                ),
                "raw_breach_records_returned": False,
                "passwords_returned": False,
                "tor_crawl_performed": any(
                    result.adapter_id == "worker.tor-research"
                    and result.status in {AdapterStatus.COMPLETED, AdapterStatus.NO_MATCH}
                    and result.network_effect
                    for result in results
                ),
                "deepweb_index_queried": any(
                    result.adapter_id == "ahmia.clearnet-index" and result.live for result in results
                ),
                "private_worker_required_for_onion_crawl": not any(
                    result.adapter_id == "worker.tor-research"
                    and result.status in {AdapterStatus.COMPLETED, AdapterStatus.NO_MATCH}
                    for result in results
                ),
            },
        }

    @staticmethod
    def _deduplicate_pivots(pivots: Iterable[dict[str, object]]) -> list[dict[str, object]]:
        unique: list[dict[str, object]] = []
        seen: set[str] = set()
        for pivot in pivots:
            url = str(pivot.get("url", ""))
            if not url or url in seen:
                continue
            seen.add(url)
            unique.append(pivot)
        return unique[:50]

    @staticmethod
    def _summary(
        findings: list[dict[str, object]], results: list[AdapterResult]
    ) -> dict[str, object]:
        breach_count = sum(item.get("category") == "BREACH_EXPOSURE" for item in findings)
        darkweb_index_count = sum(
            item.get("category") == "DARKWEB_INDEX_MATCH" for item in findings
        )
        darkweb_content_count = sum(
            item.get("category") == "DARKWEB_CONTENT_MATCH" for item in findings
        )
        confirmed_count = sum(
            item.get("verification") in {"LIVE_SOURCE_CONFIRMED", "LIVE_DNS_RESOLUTION"}
            for item in findings
        )
        if breach_count or darkweb_content_count:
            risk = "HIGH"
        elif darkweb_index_count:
            risk = "MEDIUM"
        elif findings:
            risk = "INFO"
        else:
            risk = "UNKNOWN"
        return {
            "risk": risk,
            "finding_count": len(findings),
            "breach_source_count": breach_count,
            "darkweb_match_count": darkweb_index_count + darkweb_content_count,
            "darkweb_index_match_count": darkweb_index_count,
            "darkweb_content_match_count": darkweb_content_count,
            "live_confirmed_count": confirmed_count,
            "sources_completed": sum(
                result.status in {AdapterStatus.COMPLETED, AdapterStatus.NO_MATCH}
                for result in results
            ),
            "sources_blocked_or_unavailable": sum(
                result.status
                not in {AdapterStatus.COMPLETED, AdapterStatus.NO_MATCH}
                for result in results
            ),
        }
