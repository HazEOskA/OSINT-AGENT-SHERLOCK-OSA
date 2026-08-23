from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.standalone import StandaloneResearchService  # noqa: E402

SERVICE = StandaloneResearchService()
CANARY_EMAIL = "test@microsoft.com"


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/v1/canary/emailosint":
            self.send_response(404)
            self.end_headers()
            return
        try:
            result = SERVICE.search({"kind": "EMAIL", "query": CANARY_EMAIL})
            payload = {
                "canary": CANARY_EMAIL,
                "result": result,
            }
            status = 200
        except Exception as exc:
            payload = {
                "canary": CANARY_EMAIL,
                "error": {"type": type(exc).__name__, "message": str(exc)[:500]},
            }
            status = 500
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
