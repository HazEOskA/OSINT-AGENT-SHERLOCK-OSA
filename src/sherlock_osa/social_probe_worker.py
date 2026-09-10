from __future__ import annotations

import json
import sys

from sherlock_osa.site_probe_guarded import run_username_probe_guarded


PROTOCOL = "sherlock-social-mesh.v3"


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(131_072)
        if not raw:
            raise ValueError("empty request")
        request = json.loads(raw)
        if not isinstance(request, dict) or request.get("protocol") != PROTOCOL:
            raise ValueError("protocol mismatch")

        username = request.get("username")
        mode = request.get("mode", "MAX")
        timeout_seconds = request.get("timeout_seconds", 50.0)
        if not isinstance(username, str):
            raise ValueError("username required")
        if not isinstance(mode, str):
            raise ValueError("mode required")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid timeout") from exc

        batch = run_username_probe_guarded(
            username,
            mode=mode,
            timeout_seconds=max(5.0, min(timeout, 55.0)),
        )
        sys.stdout.write(
            json.dumps(
                {
                    "protocol": PROTOCOL,
                    "ok": True,
                    "batch": batch.to_dict(),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
