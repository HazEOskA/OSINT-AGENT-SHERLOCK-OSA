from __future__ import annotations

from urllib.parse import urlsplit

_BLOCKED_SERVICE_TOKENS = frozenset({"postcrossing"})

def is_blocked_public_source(*, name: object = "", url: object = "") -> bool:
    name_text = str(name or "").casefold()
    url_text = str(url or "").casefold()
    if any(token in name_text for token in _BLOCKED_SERVICE_TOKENS):
        return True
    if any(token in url_text for token in _BLOCKED_SERVICE_TOKENS):
        return True
    try:
        host = (urlsplit(str(url or "")).hostname or "").casefold()
    except ValueError:
        host = ""
    return any(token in host for token in _BLOCKED_SERVICE_TOKENS)

__all__ = ["is_blocked_public_source"]
