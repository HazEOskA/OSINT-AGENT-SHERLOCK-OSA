from __future__ import annotations

import json

from sherlock_osa.source_pack import source_health


def main() -> int:
    health = source_health()
    print(json.dumps(health, sort_keys=True))
    if not health["all_dependencies_available"]:
        return 1
    if not health["all_versions_pinned"]:
        return 1
    sources = {item["name"]: item for item in health["sources"]}
    required = {
        "holehe.email",
        "maigret.username",
        "wayback.url",
        "wayback.domain",
        "crtsh.domain",
    }
    return 0 if required <= sources.keys() else 1


if __name__ == "__main__":
    raise SystemExit(main())
