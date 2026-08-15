from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.api import handler_factory  # noqa: E402
from sherlock_osa.demo import PublicDemoService  # noqa: E402


# Vercel's builder discovers a top-level class named ``handler`` through static
# analysis; exporting a class through a plain assignment is not sufficient.
_BaseHandler = handler_factory(PublicDemoService())


class handler(_BaseHandler):
    pass
