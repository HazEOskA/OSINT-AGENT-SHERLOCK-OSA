from __future__ import annotations

import hmac
import json
import mimetypes
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from sherlock_osa.errors import SherlockError
from sherlock_osa.service import MissionService


MISSION_PATH = re.compile(r"^/api/v1/missions/([0-9a-f-]{36})$")
REPLAY_PATH = re.compile(r"^/api/v1/missions/([0-9a-f-]{36})/replay$")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def handler_factory(service: Any) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SherlockOSA/0.2.0"
        sys_version = ""

        def log_message(self, format_string: str, *args: object) -> None:
            # Never log headers or request bodies; stdlib access-line fields only.
            super().log_message(format_string, *args)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            self.send_header("Cache-Control", "no-store")

        def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_bytes(status, body, "application/json; charset=utf-8")

        def _authorised(self) -> bool:
            expected = f"Bearer {service.settings.api_key}"
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(expected, supplied)

        def _require_auth(self) -> None:
            if not self._authorised():
                raise SherlockError("UNAUTHORIZED", "Wymagany poprawny operator Bearer token.", status=401)

        def _body_json(self) -> object:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise SherlockError("CONTENT_LENGTH_REQUIRED", "Brak Content-Length.", status=411)
            try:
                length = int(raw_length)
            except ValueError as exc:
                raise SherlockError("INVALID_CONTENT_LENGTH", "Niepoprawny Content-Length.") from exc
            if length < 0 or length > service.settings.max_body_bytes:
                raise SherlockError("BODY_TOO_LARGE", "Request body przekracza limit.", status=413)
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if content_type != "application/json":
                raise SherlockError("JSON_REQUIRED", "Content-Type musi być application/json.", status=415)
            raw = self.rfile.read(length)
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise SherlockError("INVALID_JSON", "Request body nie jest poprawnym JSON.") from exc

        def _request_target(self) -> tuple[str, dict[str, list[str]]]:
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            routed_path = query.get("__osa_path")
            if parsed.path in {"/api/index.py", "/api/index"} and routed_path:
                return "/" + routed_path[0].lstrip("/"), query
            return parsed.path, query

        def _route(self, callback: Callable[[], None]) -> None:
            try:
                callback()
            except SherlockError as exc:
                if exc.status == 401:
                    self.send_response(exc.status)
                    self._security_headers()
                    self.send_header("WWW-Authenticate", 'Bearer realm="sherlock-osa"')
                    body = json.dumps(exc.as_dict(), ensure_ascii=False).encode("utf-8")
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self._json(exc.status, exc.as_dict())
            except Exception:
                self._json(500, {"error": {"code": "INTERNAL_ERROR", "message": "Błąd wewnętrzny."}})

        def do_GET(self) -> None:  # noqa: N802
            self._route(self._do_get)

        def _do_get(self) -> None:
            path, query = self._request_target()
            if path in ASSETS:
                filename, content_type = ASSETS[path]
                resource = files("sherlock_osa").joinpath("web", filename)
                self._send_bytes(200, resource.read_bytes(), content_type)
                return
            if path == "/api/v1/health":
                probe = query.get("probe_engine", ["false"])[0].lower() == "true"
                if probe:
                    self._require_auth()
                self._json(200, service.health(probe_engine=probe))
                return
            if path == "/api/v1/reference-repos":
                self._json(200, service.reference_repositories())
                return
            if path == "/api/v1/osint/capabilities":
                self._json(200, service.osint_capabilities())
                return
            self._require_auth()
            if path == "/api/v1/capabilities":
                self._json(200, service.capabilities())
                return
            if path == "/api/v1/missions":
                self._json(200, service.list_missions())
                return
            if path == "/api/v1/evidence/verify":
                self._json(200, service.verify_evidence())
                return
            match = MISSION_PATH.fullmatch(path)
            if match:
                self._json(200, service.get_mission(match.group(1)))
                return
            raise SherlockError("NOT_FOUND", "Endpoint nie istnieje.", status=404)

        def do_POST(self) -> None:  # noqa: N802
            self._route(self._do_post)

        def _do_post(self) -> None:
            path, _ = self._request_target()
            if path == "/api/v1/demo/replay":
                demo_replay = getattr(service, "public_demo_replay", None)
                if not callable(demo_replay):
                    raise SherlockError("NOT_FOUND", "Endpoint nie istnieje.", status=404)
                self._json(200, demo_replay(self._body_json()))
                return
            if path == "/api/v1/osint/investigate":
                if not bool(getattr(service, "public_osint_access", False)):
                    self._require_auth()
                self._json(200, service.osint_investigate(self._body_json()))
                return
            self._require_auth()
            if path == "/api/v1/missions":
                self._json(201, service.create_mission(self._body_json()))
                return
            if path == "/api/v1/decisions":
                self._json(200, service.decide(self._body_json()))
                return
            if path == "/api/v1/executions/simulate":
                self._json(201, service.simulate(self._body_json()))
                return
            match = REPLAY_PATH.fullmatch(path)
            if match:
                # Require an explicit JSON object even though replay has no free parameters.
                body = self._body_json()
                if not isinstance(body, dict) or body:
                    raise SherlockError("EMPTY_OBJECT_REQUIRED", "Replay body musi być pustym obiektem JSON.")
                self._json(200, service.replay(match.group(1)))
                return
            raise SherlockError("NOT_FOUND", "Endpoint nie istnieje.", status=404)

    return Handler


def create_server(service: MissionService, host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), handler_factory(service))
    server.daemon_threads = True
    return server
