from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.api import handler_factory  # noqa: E402
from sherlock_osa.standalone import StandaloneResearchService  # noqa: E402


# Preview-only laboratory service. This branch is not eligible for merge while
# it bypasses the external OSA Execution Force control plane.
_SERVICE = StandaloneResearchService()
_BaseHandler = handler_factory(_SERVICE)


class handler(_BaseHandler):
    def _do_get(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path in {"/", "/api/index.py", "/api/index"} and query.get("canary") == ["emailosint"]:
            self._json(
                200,
                {
                    "canary": "test@microsoft.com",
                    "result": _SERVICE.search({"kind": "EMAIL", "query": "test@microsoft.com"}),
                },
            )
            return
        super()._do_get()
