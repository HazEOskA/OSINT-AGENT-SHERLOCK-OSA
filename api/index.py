from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sherlock_osa.api import handler_factory  # noqa: E402
from sherlock_osa.demo import PublicDemoService  # noqa: E402


# Vercel's Python runtime discovers the exported BaseHTTPRequestHandler class.
handler = handler_factory(PublicDemoService())
