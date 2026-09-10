from __future__ import annotations

import importlib.metadata
import json

from sherlock_osa.source_pack import source_health


PHONE_NUMBERS_VERSION = "9.0.38"


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
        "socialmesh.username",
    }
    if not required <= sources.keys():
        return 1
    try:
        phone_version = importlib.metadata.version("phonenumbers")
    except importlib.metadata.PackageNotFoundError:
        return 1
    return 0 if phone_version == PHONE_NUMBERS_VERSION else 1


if __name__ == "__main__":
    raise SystemExit(main())
