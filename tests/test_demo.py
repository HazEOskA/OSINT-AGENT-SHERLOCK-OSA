from __future__ import annotations

import importlib.util
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from sherlock_osa.api import create_server
from sherlock_osa.demo import PublicDemoService
from sherlock_osa.errors import SherlockError
from tests.support import lab_payload


ROOT = Path(__file__).resolve().parents[1]


class PublicDemoServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PublicDemoService()

    def test_replay_runs_real_policy_worker_and_hash_chain_without_effects(self) -> None:
        result = self.service.public_demo_replay(lab_payload())
        self.assertEqual(result["deployment_mode"], "PUBLIC_REPLAY_DEMO")
        self.assertEqual(result["decision"]["decision"]["effect"], "ALLOW")
        self.assertTrue(result["replay"]["valid"])
        self.assertTrue(result["replay"]["scope_signature_valid"])
        self.assertTrue(result["evidence"]["verification"]["valid"])
        self.assertEqual(result["evidence"]["verification"]["record_count"], 5)
        self.assertEqual(len(result["evidence"]["records"]), 5)
        self.assertFalse(result["truth"]["live_engine_called"])
        self.assertFalse(result["truth"]["network_effect_performed"])
        self.assertFalse(result["execution"]["receipt"]["shell_effect_performed"])
        self.assertEqual(result["truth"]["receipt_source"], "BUNDLED_OSA_TEST_VECTOR")

    def test_replay_is_lab_only_and_rejects_addressable_targets(self) -> None:
        passive = lab_payload() | {"mode": "RESEARCH_PASSIVE"}
        with self.assertRaises(SherlockError) as mode_error:
            self.service.public_demo_replay(passive)
        self.assertEqual(mode_error.exception.code, "PUBLIC_DEMO_LAB_ONLY")

        addressable = lab_payload()
        addressable["targets"] = [
            {"kind": "IP", "value": "127.0.0.1", "ports": [3000]}
        ]
        with self.assertRaises(SherlockError) as target_error:
            self.service.public_demo_replay(addressable)
        self.assertEqual(target_error.exception.code, "LAB_TARGET_MUST_BE_ASSET_ID")

    def test_health_tells_the_truth_about_public_runtime(self) -> None:
        health = self.service.health()
        self.assertEqual(health["deployment_mode"], "PUBLIC_REPLAY_DEMO")
        self.assertFalse(health["truth"]["live_engine_called"])
        self.assertFalse(health["truth"]["network_effect_possible"])


class PublicDemoHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PublicDemoService()
        self.server = create_server(self.service, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, payload: object | None = None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())

    def test_public_replay_endpoint_needs_no_operator_secret(self) -> None:
        status, result = self.request("POST", "/api/v1/demo/replay", lab_payload())
        self.assertEqual(status, 200)
        self.assertTrue(result["replay"]["valid"])

    def test_vercel_route_marker_preserves_the_original_path(self) -> None:
        status, health = self.request(
            "GET", "/api/index.py?__osa_path=api/v1/health"
        )
        self.assertEqual(status, 200)
        self.assertEqual(health["deployment_mode"], "PUBLIC_REPLAY_DEMO")
        status, result = self.request(
            "POST",
            "/api/index.py?__osa_path=api/v1/demo/replay",
            lab_payload(),
        )
        self.assertEqual(status, 200)
        self.assertTrue(result["replay"]["valid"])

    def test_private_runtime_endpoints_stay_closed(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("GET", "/api/v1/missions")
        self.assertEqual(raised.exception.code, 401)


class VercelContractTests(unittest.TestCase):
    def test_entrypoint_exports_http_handler_and_config_is_catch_all(self) -> None:
        entrypoint = ROOT / "api" / "index.py"
        spec = importlib.util.spec_from_file_location("sherlock_vercel_entrypoint", entrypoint)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(issubclass(module.handler, BaseHTTPRequestHandler))

        config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
        self.assertEqual(config["builds"][0]["src"], "api/index.py")
        self.assertEqual(
            config["routes"][0],
            {"src": "/.*", "dest": "/api/index.py?__osa_path=$1"},
        )


if __name__ == "__main__":
    unittest.main()
