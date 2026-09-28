from __future__ import annotations

import re
from collections import Counter
from typing import Any, Mapping, Sequence


SOCIAL_CATEGORIES = (
    "GOOGLE",
    "SOCIAL",
    "DATING",
    "MESSAGING",
    "DEVELOPER",
    "GAMING",
    "MUSIC",
    "VIDEO",
    "SHOPPING",
    "FINANCE",
    "FORUMS",
    "ADULT",
    "OTHER",
)

NSFW_BUCKETS = (
    "CREATOR_PLATFORMS",
    "ADULT_COMMUNITIES",
    "DATING_SEXUAL_OVERLAP",
    "LINK_IN_BIO_MONETIZATION",
    "HISTORICAL_ARCHIVE",
    "OTHER_ADULT",
)

_HINT_MAP = {
    "social": "SOCIAL",
    "dating": "DATING",
    "coding": "DEVELOPER",
    "gaming": "GAMING",
    "music": "MUSIC",
    "video": "VIDEO",
    "shopping": "SHOPPING",
    "finance": "FINANCE",
    "blog": "SOCIAL",
    "business": "SOCIAL",
    "images": "SOCIAL",
    "news": "SOCIAL",
    "tech": "DEVELOPER",
    "xx nsfw xx": "ADULT",
}

_KEYWORDS = {
    "GOOGLE": (
        "google",
        "gmail",
        "youtube",
        "blogger",
        "google play",
        "google maps",
        "google drive",
        "google photos",
        "google scholar",
    ),
    "DATING": (
        "tinder",
        "bumble",
        "badoo",
        "hinge",
        "okcupid",
        "plentyoffish",
        "pof",
        "happn",
        "grindr",
        "her dating",
        "taimi",
        "feeld",
        "match.com",
        "match ",
        "dating",
        "friendfinder",
        "lovoo",
        "zoosk",
        "meetme",
        "skout",
        "mamba",
        "eharmony",
        "coffee meets bagel",
        "boo dating",
    ),
    "MESSAGING": (
        "whatsapp",
        "telegram",
        "signal",
        "discord",
        "skype",
        "slack",
        "microsoft teams",
        "kik",
        "line",
        "viber",
        "wechat",
        "messenger",
        "snapchat",
        "matrix",
    ),
    "SOCIAL": (
        "instagram",
        "facebook",
        "twitter",
        "x.com",
        "threads",
        "tiktok",
        "reddit",
        "pinterest",
        "linkedin",
        "mastodon",
        "bluesky",
        "bsky",
        "vk.com",
        "tumblr",
        "medium",
        "quora",
        "flickr",
        "about.me",
        "allmylinks",
    ),
    "DEVELOPER": (
        "github",
        "gitlab",
        "bitbucket",
        "stackoverflow",
        "stack overflow",
        "docker hub",
        "dockerhub",
        "npm",
        "pypi",
        "dev.to",
        "replit",
        "codepen",
        "kaggle",
        "hackerrank",
        "leetcode",
        "sourceforge",
    ),
    "GAMING": (
        "steam",
        "xbox",
        "playstation",
        "psn",
        "epic games",
        "battle.net",
        "battlenet",
        "roblox",
        "twitch",
        "minecraft",
        "chess.com",
    ),
    "MUSIC": (
        "spotify",
        "soundcloud",
        "last.fm",
        "lastfm",
        "bandcamp",
        "mixcloud",
        "airbit",
    ),
    "VIDEO": (
        "vimeo",
        "dailymotion",
        "kick.com",
        "rumble",
    ),
    "SHOPPING": (
        "amazon",
        "ebay",
        "etsy",
        "aliexpress",
        "vinted",
        "depop",
        "mercari",
    ),
    "FINANCE": (
        "paypal",
        "venmo",
        "cash app",
        "cashapp",
        "revolut",
        "coinbase",
        "binance",
        "kraken",
    ),
    "FORUMS": (
        "forum",
        "discourse",
        "hacker news",
        "lobste.rs",
        "4chan",
    ),
    "ADULT": (
        "onlyfans",
        "fansly",
        "fanvue",
        "loyalfans",
        "fancentro",
        "manyvids",
        "clips4sale",
        "pornhub",
        "xhamster",
        "redgifs",
        "erome",
        "imagefap",
        "fetlife",
        "porn",
        "nsfw",
        "adult",
        "admireme",
        "all things worn",
        "allthingsworn",
        "apclips",
    ),
}

_NSFW_BUCKET_KEYWORDS = {
    "CREATOR_PLATFORMS": (
        "onlyfans",
        "fansly",
        "fanvue",
        "loyalfans",
        "fancentro",
        "manyvids",
        "clips4sale",
        "admireme",
        "apclips",
    ),
    "ADULT_COMMUNITIES": (
        "pornhub",
        "xhamster",
        "redgifs",
        "erome",
        "imagefap",
        "fetlife",
        "adult forum",
        "nsfw forum",
    ),
    "DATING_SEXUAL_OVERLAP": (
        "adultfriendfinder",
        "friendfinder",
        "fetlife",
        "feeld",
        "grindr",
        "taimi",
    ),
    "LINK_IN_BIO_MONETIZATION": (
        "allmylinks",
        "linktree",
        "beacons",
        "link in bio",
        "monetization",
        "tip link",
    ),
    "HISTORICAL_ARCHIVE": (
        "wayback",
        "archive.org",
        "common crawl",
        "commoncrawl",
        "historical",
        "archive",
    ),
}


def normalise_service_name(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    cleaned = re.sub(r"\s+", " ", value.strip())
    return cleaned or "unknown"


def _haystack(name: str, url: str = "") -> str:
    return f"{name} {url}".casefold()


def classify_service(
    name: object,
    *,
    url: object = "",
    category_hint: object = "",
    is_nsfw: bool = False,
) -> str:
    service = normalise_service_name(name)
    url_text = str(url or "")
    hint = str(category_hint or "").strip().casefold()

    if is_nsfw:
        return "ADULT"

    haystack = _haystack(service, url_text)

    # Explicit provider/service names win over generic source-category hints.
    # This is important for Google/YouTube and dating apps that may arrive from
    # an upstream source with a broad category such as "social".
    for category in (
        "GOOGLE",
        "DATING",
        "MESSAGING",
        "DEVELOPER",
        "GAMING",
        "MUSIC",
        "VIDEO",
        "SHOPPING",
        "FINANCE",
        "FORUMS",
        "ADULT",
        "SOCIAL",
    ):
        if any(keyword in haystack for keyword in _KEYWORDS[category]):
            return category

    if hint in _HINT_MAP:
        return _HINT_MAP[hint]
    return "OTHER"


def classify_sensitive_bucket(
    name: object,
    *,
    url: object = "",
    origin: object = "",
) -> str:
    """Classify an already-sensitive signal without asserting identity or activity.

    This helper is deliberately narrower than ``classify_service``. It does not
    promote a normal dating/social service into ADULT. The caller must first
    establish that the record belongs to the ADULT category from source metadata
    or an explicit adult-service match.
    """

    service = normalise_service_name(name)
    haystack = f"{service} {str(url or '')} {str(origin or '')}".casefold()
    for bucket in NSFW_BUCKETS:
        if bucket == "OTHER_ADULT":
            continue
        if any(keyword in haystack for keyword in _NSFW_BUCKET_KEYWORDS[bucket]):
            return bucket
    return "OTHER_ADULT"


def signal_presence_status(value: object) -> str:
    if not isinstance(value, Mapping):
        return "OBSERVED"

    positive_keys = (
        "exists",
        "registered",
        "found",
        "account_exists",
        "present",
        "taken",
        "claimed",
    )
    negative_keys = (
        "available",
        "missing",
        "not_found",
        "unclaimed",
    )

    for key in positive_keys:
        if value.get(key) is True:
            return "FOUND"
    for key in negative_keys:
        if value.get(key) is True:
            return "NOT_FOUND"

    status = str(value.get("status", "")).strip().casefold()
    if status in {"found", "claimed", "exists", "registered", "taken", "unavailable"}:
        return "FOUND"
    if status in {"not_found", "missing", "unclaimed", "available"}:
        return "NOT_FOUND"
    if status in {"blocked", "captcha", "rate_limited", "timeout", "error", "unreliable"}:
        return status.upper()

    return "OBSERVED"


def categorise_accounts(accounts: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {category: [] for category in SOCIAL_CATEGORIES}
    for account in accounts:
        name = (
            account.get("service")
            or account.get("platform")
            or account.get("site")
            or account.get("source")
            or account.get("name")
            or "unknown"
        )
        url = (
            account.get("profile_url")
            or account.get("url")
            or account.get("web_url")
            or account.get("uri_pretty")
            or ""
        )
        category = classify_service(
            name,
            url=url,
            category_hint=account.get("category", ""),
            is_nsfw=bool(account.get("is_nsfw", False)),
        )
        grouped[category].append(dict(account))
    return grouped


def category_counts(accounts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter()
    for category, items in categorise_accounts(accounts).items():
        counts[category] = len(items)
    return {category: int(counts[category]) for category in SOCIAL_CATEGORIES}
