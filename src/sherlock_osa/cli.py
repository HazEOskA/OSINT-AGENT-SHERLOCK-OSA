from __future__ import annotations

import argparse
import sys

from sherlock_osa.api import create_server
from sherlock_osa.config import Settings, load_env_file
from sherlock_osa.engine import OsaEngineClient
from sherlock_osa.errors import SherlockError
from sherlock_osa.evidence import EvidenceLedger
from sherlock_osa.policy import CapabilityBroker
from sherlock_osa.service import MissionService
from sherlock_osa.storage import MissionStore
from sherlock_osa.worker import SimulationWorker


def build_service(settings: Settings) -> MissionService:
    return MissionService(
        settings=settings,
        store=MissionStore(settings.database_path),
        ledger=EvidenceLedger(settings.evidence_path),
        engine=OsaEngineClient(
            base_url=settings.engine_url,
            api_key=settings.engine_api_key,
            commit_sha=settings.engine_commit_sha,
            timeout_seconds=settings.engine_timeout_seconds,
        ),
        broker=CapabilityBroker(settings.mission_signing_secret),
        worker=SimulationWorker(),
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sherlock-osa")
    subcommands = root.add_subparsers(dest="command")
    serve = subcommands.add_parser("serve", help="Uruchom panel i API")
    serve.add_argument("--env-file", default=None)
    verify = subcommands.add_parser("verify-ledger", help="Zweryfikuj evidence ledger")
    verify.add_argument("--env-file", default=None)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    command = args.command or "serve"
    try:
        if getattr(args, "env_file", None):
            load_env_file(args.env_file)
        settings = Settings.from_env()
        service = build_service(settings)
        if command == "verify-ledger":
            result = service.verify_evidence()
            print(result)
            return 0 if result["valid"] else 1
        server = create_server(service, settings.host, settings.port)
        print(f"Sherlock OSA v0.1.0: http://{settings.host}:{settings.port}")
        print(f"OSA Engine pin: {settings.engine_commit_sha}")
        server.serve_forever()
        return 0
    except KeyboardInterrupt:
        return 130
    except SherlockError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
