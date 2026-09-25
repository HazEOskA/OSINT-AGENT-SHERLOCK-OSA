from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.api import handler_factory  # noqa: E402
from sherlock_osa.emailosint import DEFAULT_EMAILOSINT_ENDPOINT  # noqa: E402
from sherlock_osa.vercel_search import VercelSearchService  # noqa: E402


_service = VercelSearchService()
_base = _service.settings
_service.settings = SimpleNamespace(
    max_body_bytes=_base.max_body_bytes,
    emailosint_endpoint=os.getenv(
        "EMAILOSINT_ENDPOINT",
        DEFAULT_EMAILOSINT_ENDPOINT,
    ).strip().rstrip("/"),
    emailosint_api_key=os.getenv("EMAILOSINT_API_KEY", "").strip(),
    emailosint_auth_header=os.getenv("EMAILOSINT_AUTH_HEADER", "Authorization").strip(),
    emailosint_auth_scheme=os.getenv("EMAILOSINT_AUTH_SCHEME", "Bearer").strip(),
    emailosint_timeout_seconds=int(os.getenv("EMAILOSINT_TIMEOUT_SECONDS", "30")),
)

_BaseHandler = handler_factory(_service)


class handler(_BaseHandler):
    pass
