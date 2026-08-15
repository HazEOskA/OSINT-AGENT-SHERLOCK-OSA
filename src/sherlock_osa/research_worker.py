from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
from dataclasses import dataclass
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Protocol
from urllib.parse import urlencode, urlparse, urlunparse

from sherlock_osa.contracts import require_string
from sherlock_osa.errors import SherlockError
from sherlock_osa.osint import QueryKind, _AhmiaParser, classify_query


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class Fetcher(Protocol):
    def fetch(self, url: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    token: str
    tor_proxy: str = "socks5h://tor-gateway:9050"
    host: str = "0.0.0.0"
    port: int = 8790
    timeout_seconds: int = 15
    max_page_bytes: int = 500_000

    @classmethod
    def from_env(cls) -> "WorkerSettings":
        token = os.getenv("OSA_RESEARCH_WORKER_TOKEN", "").strip()
        if len(token) < 24:
            raise SherlockError(
                "MISSING_WORKER_TOKEN",
                "OSA_RESEARCH_WORKER_TOKEN musi mieć co najmniej 24 znaki.",
                status=500,
            )
        proxy = os.getenv("TOR_SOCKS_PROXY", "socks5h://tor-gateway:9050").strip()
        parsed = urlparse(proxy)
        if parsed.scheme != "socks5h" or not parsed.hostname or parsed.username or parsed.password:
            raise SherlockError("INVALID_TOR_PROXY", "TOR_SOCKS_PROXY musi używać socks5h://.")
        try:
            port = int(os.getenv("OSA_RESEARCH_WORKER_PORT", "8790"))
            timeout = int(os.getenv("OSA_RESEARCH_TIMEOUT_SECONDS", "15"))
        except ValueError as exc:
            raise SherlockError("INVALID_WORKER_CONFIG", "Port i timeout muszą być liczbami.") from exc
        if not 1 <= port <= 65535 or not 3 <= timeout <= 60:
            raise SherlockError("INVALID_WORKER_CONFIG", "Port lub timeout jest poza zakresem.")
        return cls(
            token=token,
            tor_proxy=proxy,
            host=os.getenv("OSA_RESEARCH_WORKER_HOST", "0.0.0.0").strip(),
            port=port,
            timeout_seconds=timeout,
        )


class TorCurlFetcher:
    """Fixed-argv curl transport. It accepts only Ahmia or a v3 onion host."""

    def __init__(self, settings: WorkerSettings) -> None:
        self.settings = settings

    @staticmethod
    def _validate_url(url: str) -> str:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        is_ahmia = parsed.scheme == "https" and hostname == "ahmia.fi"
        is_onion = (
            parsed.scheme in {"http", "https"}
            and hostname.endswith(".onion")
            and len(hostname.removesuffix(".onion")) == 56
            and all(character in "abcdefghijklmnopqrstuvwxyz234567" for character in hostname.removesuffix(".onion"))
            and parsed.port in {None, 80, 443}
        )
        if parsed.username or parsed.password or not (is_ahmia or is_onion):
            raise SherlockError("WORKER_TARGET_DENIED", "Worker akceptuje tylko Ahmia i v3 .onion.")
        return urlunparse(parsed._replace(fragment=""))

    def fetch(self, url: str) -> bytes:
        safe_url = self._validate_url(url)
        completed = subprocess.run(
            [
                "/usr/bin/curl",
                "--disable",
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--proxy",
                self.settings.tor_proxy,
                "--connect-timeout",
                "8",
                "--max-time",
                str(self.settings.timeout_seconds),
                "--max-filesize",
                str(self.settings.max_page_bytes),
                "--proto",
                "=http,https",
                "--proto-redir",
                "=http,https",
                "--user-agent",
                "Sherlock-OSA-Research-Worker/0.2",
                safe_url,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=self.settings.timeout_seconds + 3,
        )
        if completed.returncode != 0:
            raise SherlockError("TOR_FETCH_FAILED", "Pobranie przez Tor nie powiodło się.", status=502)
        if len(completed.stdout) > self.settings.max_page_bytes:
            raise SherlockError("TOR_RESPONSE_TOO_LARGE", "Strona .onion przekroczyła limit.")
        return completed.stdout


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._inside_title = True

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self.parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._inside_title = False

    def title(self) -> str:
        return " ".join("".join(self.parts).split())[:160]


class TorResearchWorker:
    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    @staticmethod
    def _match(content: bytes, query: str, kind: QueryKind) -> bool:
        text = content.decode("utf-8", errors="ignore").casefold()
        candidates = {query.casefold()}
        if kind is QueryKind.PHONE:
            candidates.add("".join(character for character in query if character.isdigit()))
        return any(candidate and candidate in text for candidate in candidates)

    def search(self, raw: object) -> dict[str, object]:
        if not isinstance(raw, Mapping):
            raise SherlockError("INVALID_PAYLOAD", "Payload workera musi być obiektem JSON.")
        mission = raw.get("mission")
        if not isinstance(mission, Mapping) or mission.get("engine_state") != "COMPLETED":
            raise SherlockError(
                "ENGINE_RECEIPT_REQUIRED",
                "Worker wymaga COMPLETED receipt z OSA Engine.",
                status=409,
            )
        receipt_sha = str(mission.get("engine_receipt_sha256", ""))
        if not SHA256_RE.fullmatch(receipt_sha):
            raise SherlockError("INVALID_ENGINE_RECEIPT", "Brak poprawnego hash receiptu.", status=409)
        try:
            requested_kind = QueryKind(str(raw.get("kind", "AUTO")))
        except ValueError as exc:
            raise SherlockError("INVALID_QUERY_KIND", "Worker dostał nieobsługiwany typ.") from exc
        query = classify_query(
            require_string(raw.get("query"), field_name="query", maximum=253),
            requested_kind,
            "PL",
        )
        max_results = raw.get("max_results", 5)
        if type(max_results) is not int or not 1 <= max_results <= 5:
            raise SherlockError("INVALID_MAX_RESULTS", "max_results musi należeć do 1..5.")

        search_url = f"https://ahmia.fi/search/?{urlencode({'q': query.normalized})}"
        search_html = self.fetcher.fetch(search_url)
        parser = _AhmiaParser()
        parser.feed(search_html.decode("utf-8", errors="replace"))
        candidates: list[tuple[str, str]] = []
        seen: set[str] = set()
        for indexed_title, indexed_url in parser.links:
            try:
                safe_url = TorCurlFetcher._validate_url(indexed_url)
            except (SherlockError, ValueError):
                continue
            if safe_url in seen:
                continue
            seen.add(safe_url)
            candidates.append((indexed_title, safe_url))
            if len(candidates) >= max_results:
                break

        matches: list[dict[str, object]] = []
        pages_fetched = 0
        for indexed_title, onion_url in candidates:
            try:
                content = self.fetcher.fetch(onion_url)
            except (SherlockError, subprocess.TimeoutExpired):
                continue
            pages_fetched += 1
            if not self._match(content, query.normalized, query.kind):
                continue
            title_parser = _TitleParser()
            title_parser.feed(content.decode("utf-8", errors="replace"))
            matches.append(
                {
                    "url": onion_url,
                    "title": title_parser.title() or indexed_title or "Dopasowanie .onion",
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                    "content_bytes": len(content),
                    "raw_content_returned": False,
                }
            )
        return {
            "transport": "TOR_SOCKS5H",
            "direct_egress": False,
            "engine_receipt_sha256": receipt_sha,
            "candidates": len(candidates),
            "pages_fetched": pages_fetched,
            "matches": matches,
            "raw_content_returned": False,
        }


def handler_factory(settings: WorkerSettings, worker: TorResearchWorker) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SherlockOSAResearchWorker/0.2"
        sys_version = ""

        def log_message(self, format_string: str, *args: object) -> None:
            # Never log request bodies because they contain the transient identifier.
            return

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._json(200, {"status": "OK", "transport": "TOR_SOCKS5H"})
            else:
                self._json(404, {"error": {"code": "NOT_FOUND"}})

        def do_POST(self) -> None:  # noqa: N802
            try:
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied, f"Bearer {settings.token}"):
                    raise SherlockError("UNAUTHORIZED", "Niepoprawny token workera.", status=401)
                if self.path != "/v1/search":
                    raise SherlockError("NOT_FOUND", "Endpoint nie istnieje.", status=404)
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                    raise SherlockError("JSON_REQUIRED", "Wymagany application/json.", status=415)
                raw_length = self.headers.get("Content-Length", "")
                if not raw_length.isdigit() or not 1 <= int(raw_length) <= 32_768:
                    raise SherlockError("INVALID_CONTENT_LENGTH", "Niepoprawny rozmiar body.", status=413)
                try:
                    payload = json.loads(self.rfile.read(int(raw_length)))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise SherlockError("INVALID_JSON", "Niepoprawny JSON.") from exc
                self._json(200, worker.search(payload))
            except SherlockError as exc:
                self._json(exc.status, exc.as_dict())
            except Exception:
                self._json(500, {"error": {"code": "INTERNAL_ERROR", "message": "Błąd workera."}})

    return Handler


def main() -> int:
    settings = WorkerSettings.from_env()
    worker = TorResearchWorker(TorCurlFetcher(settings))
    server = ThreadingHTTPServer((settings.host, settings.port), handler_factory(settings, worker))
    server.daemon_threads = True
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
