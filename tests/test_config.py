from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sherlock_osa.config import Settings


BASE_ENV = {
    "SHERLOCK_API_KEY": "operator-key-that-is-long-enough",
    "SHERLOCK_MISSION_SIGNING_SECRET": "mission-secret-that-is-definitely-long-enough",
    "OSA_ACTIONS_API_KEY": "engine-key-long-enough",
}


class ConfigTests(unittest.TestCase):
    def test_local_defaults_are_preserved(self) -> None:
        with patch.dict(os.environ, BASE_ENV, clear=True):
            settings = Settings.from_env()

        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 8787)

    def test_cloud_run_port_and_host_are_used(self) -> None:
        with patch.dict(os.environ, {**BASE_ENV, "PORT": "8080"}, clear=True):
            settings = Settings.from_env()

        self.assertEqual(settings.host, "0.0.0.0")
        self.assertEqual(settings.port, 8080)

    def test_explicit_sherlock_network_settings_override_runtime_defaults(self) -> None:
        env = {
            **BASE_ENV,
            "PORT": "8080",
            "SHERLOCK_HOST": "127.0.0.1",
            "SHERLOCK_PORT": "9000",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()

        self.assertEqual(settings.host, "127.0.0.1")
        self.assertEqual(settings.port, 9000)


if __name__ == "__main__":
    unittest.main()
