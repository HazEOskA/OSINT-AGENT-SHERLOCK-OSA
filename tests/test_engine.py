from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sherlock_osa import ENGINE_PIN
from sherlock_osa.engine import OsaEngineClient
from sherlock_osa.errors import EngineError


class EngineStubHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"info": {"title": "OSA Stub", "version": "2"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        payload = json.loads(self.rfile.read(length))
        self.server.last_payload = payload  # type: ignore[attr-defined]
        self.server.last_authorization = self.headers.get("Authorization")  # type: ignore[attr-defined]
        commit_sha = self.server.receipt_commit_sha  # type: ignore[attr-defined]
        response: dict[str, Any] = {
            "state": "COMPLETED",
            "context": {
                "mission_id": "engine-mission",
                "execution_id": "engine-execution",
                "commit_sha": commit_sha,
            },
        }
        body = json.dumps(response).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EngineClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), EngineStubHandler)
        self.server.receipt_commit_sha = ENGINE_PIN  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.client = OsaEngineClient(
            base_url=f"http://{host}:{port}",
            api_key="engine-secret-test-key",
            commit_sha=ENGINE_PIN,
            timeout_seconds=2,
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_receipt_is_bound_to_pin_and_auth_header(self) -> None:
        receipt = self.client.run_mission(
            {
                "goal": "test goal",
                "mode": "LAB_RANGE",
                "targets": [],
                "allowed_capabilities": [],
            }
        )
        self.assertEqual(receipt.state, "COMPLETED")
        self.assertEqual(self.server.last_authorization, "Bearer engine-secret-test-key")  # type: ignore[attr-defined]
        context = self.server.last_payload["context"]  # type: ignore[attr-defined]
        self.assertEqual(context["commit_sha"], ENGINE_PIN)
        self.assertEqual(self.client.probe()["title"], "OSA Stub")

    def test_mismatched_receipt_pin_is_rejected(self) -> None:
        self.server.receipt_commit_sha = "0" * 40  # type: ignore[attr-defined]
        with self.assertRaises(EngineError) as raised:
            self.client.run_mission(
                {
                    "goal": "test goal",
                    "mode": "LAB_RANGE",
                    "targets": [],
                    "allowed_capabilities": [],
                }
            )
        self.assertEqual(raised.exception.code, "ENGINE_RECEIPT_PIN_MISMATCH")


if __name__ == "__main__":
    unittest.main()
