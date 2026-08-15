from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from sherlock_osa.api import create_server
from tests.support import build_test_service, lab_payload


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.service, _ = build_test_service(Path(self.temp.name))
        self.server = create_server(self.service, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method: str, path: str, payload: object | None = None, *, auth: bool = True):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"Bearer {self.service.settings.api_key}"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())

    def request_bytes(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=3) as response:
            return response.status, response.headers, response.read()

    def test_public_health_and_reference_benchmark(self) -> None:
        status, health = self.request("GET", "/api/v1/health", auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(health["execution_backing"], "SIMULATION_ONLY")
        status, benchmark = self.request("GET", "/api/v1/reference-repos", auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(len(benchmark["repositories"]), 20)

    def test_static_panel_and_assets_are_served_with_security_headers(self) -> None:
        status, headers, body = self.request_bytes("/")
        self.assertEqual(status, 200)
        self.assertIn(b"SHERLOCK OSA", body)
        self.assertIn(b'id="mission-form"', body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        for path, marker in (("/assets/styles.css", b"--green"), ("/assets/app.js", b"runFlow")):
            asset_status, _, asset_body = self.request_bytes(path)
            self.assertEqual(asset_status, 200)
            self.assertIn(marker, asset_body)

    def test_private_endpoint_requires_bearer(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("GET", "/api/v1/missions", auth=False)
        self.assertEqual(raised.exception.code, 401)
        body = json.loads(raised.exception.read())
        self.assertEqual(body["error"]["code"], "UNAUTHORIZED")

    def test_live_http_vertical_slice(self) -> None:
        _, created = self.request("POST", "/api/v1/missions", lab_payload())
        mission = created["mission"]
        decision_payload = {
            "mission_id": mission["mission_id"],
            "capability": "lab.http.probe",
            "target": {"kind": "LAB_ASSET", "value": "lab://juice-shop", "ports": [3000]},
            "route": "range-only",
            "port": 3000,
            "request_id": "api-live-test",
        }
        _, decided = self.request("POST", "/api/v1/decisions", decision_payload)
        self.assertEqual(decided["decision"]["effect"], "ALLOW")
        _, executed = self.request(
            "POST",
            "/api/v1/executions/simulate",
            {"decision_id": decided["decision"]["decision_id"]},
        )
        self.assertFalse(executed["receipt"]["network_effect_performed"])
        _, replay = self.request("POST", f"/api/v1/missions/{mission['mission_id']}/replay", {})
        self.assertTrue(replay["valid"])
        _, ledger = self.request("GET", "/api/v1/evidence/verify")
        self.assertTrue(ledger["valid"])
        self.assertGreaterEqual(ledger["record_count"], 5)


if __name__ == "__main__":
    unittest.main()
