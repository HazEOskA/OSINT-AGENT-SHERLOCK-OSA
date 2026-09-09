from __future__ import annotations

import importlib.metadata
import os
from dataclasses import dataclass, field
from enum import StrEnum

from sherlock_osa.research import IdentifierKind


class SourceCost(StrEnum):
    FREE = "FREE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SourceTrust(StrEnum):
    DIRECT = "DIRECT"
    AUTHORITATIVE = "AUTHORITATIVE"
    AGGREGATOR = "AGGREGATOR"
    ARCHIVE = "ARCHIVE"


@dataclass(frozen=True, slots=True)
class SourceDescriptor:
    name: str
    family: str
    supported_kinds: frozenset[IdentifierKind]
    required_capability: str
    max_identifier_depth: int
    priority: int = 50
    cost: SourceCost = SourceCost.FREE
    trust_class: SourceTrust = SourceTrust.DIRECT
    requires_key: bool = False
    credential_env: str | None = None
    optional_credential_env: str | None = None
    rate_limit: str = "PROVIDER_DEFINED"
    timeout_seconds: float = 30.0
    pivot_types: frozenset[IdentifierKind] = field(default_factory=frozenset)
    historical: bool = False
    identity_capable: bool = False
    package: str | None = None
    expected_version: str | None = None
    network_effect: bool = True

    @property
    def credential_configured(self) -> bool:
        if not self.requires_key:
            return True
        if not self.credential_env:
            return False
        return bool(os.getenv(self.credential_env, "").strip())

    @property
    def optional_credential_configured(self) -> bool:
        if not self.optional_credential_env:
            return False
        return bool(os.getenv(self.optional_credential_env, "").strip())

    def dependency_health(self) -> tuple[bool, str | None, bool]:
        if self.package is None:
            return True, "builtin", True
        try:
            version = importlib.metadata.version(self.package)
        except importlib.metadata.PackageNotFoundError:
            return False, None, False
        return True, version, version == self.expected_version

    def health(self) -> dict[str, object]:
        available, version, version_match = self.dependency_health()
        return {
            "name": self.name,
            "family": self.family,
            "supported_kinds": sorted(kind.value for kind in self.supported_kinds),
            "required_capability": self.required_capability,
            "package": self.package,
            "available": available,
            "version": version,
            "expected_version": self.expected_version,
            "version_match": version_match,
            "network_effect": self.network_effect,
            "max_identifier_depth": self.max_identifier_depth,
            "priority": self.priority,
            "cost": self.cost.value,
            "trust_class": self.trust_class.value,
            "requires_key": self.requires_key,
            "credential_env": self.credential_env,
            "credential_configured": self.credential_configured,
            "optional_credential_env": self.optional_credential_env,
            "optional_credential_configured": self.optional_credential_configured,
            "rate_limit": self.rate_limit,
            "timeout_seconds": self.timeout_seconds,
            "pivot_types": sorted(kind.value for kind in self.pivot_types),
            "historical": self.historical,
            "identity_capable": self.identity_capable,
            "ready": available and version_match and self.credential_configured,
        }


HOLEHE = SourceDescriptor(
    name="holehe.email",
    family="IDENTITY",
    package="holehe",
    expected_version="1.61",
    supported_kinds=frozenset({IdentifierKind.EMAIL}),
    required_capability="osint.email.lookup",
    max_identifier_depth=2,
    priority=22,
    cost=SourceCost.MEDIUM,
    trust_class=SourceTrust.AGGREGATOR,
    timeout_seconds=55.0,
    pivot_types=frozenset({IdentifierKind.DOMAIN}),
    identity_capable=True,
)

MAIGRET = SourceDescriptor(
    name="maigret.username",
    family="IDENTITY",
    package="maigret",
    expected_version="0.6.4",
    supported_kinds=frozenset({IdentifierKind.USERNAME}),
    required_capability="osint.username.lookup",
    max_identifier_depth=2,
    priority=28,
    cost=SourceCost.HIGH,
    trust_class=SourceTrust.AGGREGATOR,
    timeout_seconds=55.0,
    pivot_types=frozenset({IdentifierKind.URL, IdentifierKind.EMAIL, IdentifierKind.USERNAME}),
    identity_capable=True,
)

GRAVATAR_EMAIL = SourceDescriptor(
    name="gravatar.email",
    family="IDENTITY",
    supported_kinds=frozenset({IdentifierKind.EMAIL}),
    required_capability="osint.email.lookup",
    max_identifier_depth=3,
    priority=8,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.DIRECT,
    optional_credential_env="GRAVATAR_API_KEY",
    rate_limit="PUBLIC_LIMITED_OR_KEYED",
    timeout_seconds=15.0,
    pivot_types=frozenset({IdentifierKind.URL, IdentifierKind.USERNAME}),
    identity_capable=True,
)

GITHUB_USERNAME = SourceDescriptor(
    name="github.username",
    family="CODE_IDENTITY",
    supported_kinds=frozenset({IdentifierKind.USERNAME}),
    required_capability="osint.username.lookup",
    max_identifier_depth=3,
    priority=8,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.DIRECT,
    optional_credential_env="GITHUB_TOKEN",
    rate_limit="60_PER_HOUR_UNAUTHENTICATED",
    timeout_seconds=15.0,
    pivot_types=frozenset({IdentifierKind.URL, IdentifierKind.EMAIL, IdentifierKind.USERNAME}),
    identity_capable=True,
)

GITLAB_USERNAME = SourceDescriptor(
    name="gitlab.username",
    family="CODE_IDENTITY",
    supported_kinds=frozenset({IdentifierKind.USERNAME}),
    required_capability="osint.username.lookup",
    max_identifier_depth=3,
    priority=10,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.DIRECT,
    optional_credential_env="GITLAB_TOKEN",
    rate_limit="PROVIDER_DEFINED",
    timeout_seconds=15.0,
    pivot_types=frozenset({IdentifierKind.URL, IdentifierKind.EMAIL, IdentifierKind.USERNAME}),
    identity_capable=True,
)

HIBP_ACCOUNT = SourceDescriptor(
    name="hibp.account",
    family="EXPOSURE",
    supported_kinds=frozenset({IdentifierKind.EMAIL, IdentifierKind.PHONE}),
    required_capability="osint.exposure.lookup",
    max_identifier_depth=1,
    priority=5,
    cost=SourceCost.LOW,
    trust_class=SourceTrust.AUTHORITATIVE,
    requires_key=True,
    credential_env="HIBP_API_KEY",
    rate_limit="SUBSCRIPTION_DEFINED",
    timeout_seconds=15.0,
    identity_capable=False,
)

RDAP_DOMAIN = SourceDescriptor(
    name="rdap.domain",
    family="REGISTRATION",
    supported_kinds=frozenset({IdentifierKind.DOMAIN}),
    required_capability="osint.domain.passive",
    max_identifier_depth=3,
    priority=8,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.AUTHORITATIVE,
    rate_limit="REGISTRY_DEFINED",
    timeout_seconds=20.0,
)

CRTSH_DOMAIN = SourceDescriptor(
    name="crtsh.domain",
    family="CERTIFICATE",
    supported_kinds=frozenset({IdentifierKind.DOMAIN}),
    required_capability="osint.domain.passive",
    max_identifier_depth=2,
    priority=12,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.DIRECT,
    timeout_seconds=20.0,
    pivot_types=frozenset({IdentifierKind.DOMAIN}),
)

WAYBACK_URL = SourceDescriptor(
    name="wayback.url",
    family="ARCHIVE",
    supported_kinds=frozenset({IdentifierKind.URL}),
    required_capability="osint.url.trace",
    max_identifier_depth=3,
    priority=32,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.ARCHIVE,
    timeout_seconds=25.0,
    pivot_types=frozenset({IdentifierKind.URL}),
    historical=True,
)

WAYBACK_DOMAIN = SourceDescriptor(
    name="wayback.domain",
    family="ARCHIVE",
    supported_kinds=frozenset({IdentifierKind.DOMAIN}),
    required_capability="osint.domain.passive",
    max_identifier_depth=2,
    priority=34,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.ARCHIVE,
    timeout_seconds=25.0,
    pivot_types=frozenset({IdentifierKind.URL}),
    historical=True,
)

COMMONCRAWL_URL = SourceDescriptor(
    name="commoncrawl.url",
    family="ARCHIVE",
    supported_kinds=frozenset({IdentifierKind.URL}),
    required_capability="osint.url.trace",
    max_identifier_depth=3,
    priority=38,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.ARCHIVE,
    timeout_seconds=25.0,
    pivot_types=frozenset({IdentifierKind.URL}),
    historical=True,
)

COMMONCRAWL_DOMAIN = SourceDescriptor(
    name="commoncrawl.domain",
    family="ARCHIVE",
    supported_kinds=frozenset({IdentifierKind.DOMAIN}),
    required_capability="osint.domain.passive",
    max_identifier_depth=2,
    priority=40,
    cost=SourceCost.FREE,
    trust_class=SourceTrust.ARCHIVE,
    timeout_seconds=25.0,
    pivot_types=frozenset({IdentifierKind.URL}),
    historical=True,
)


SOURCE_DESCRIPTORS = (
    HIBP_ACCOUNT,
    GRAVATAR_EMAIL,
    GITHUB_USERNAME,
    GITLAB_USERNAME,
    RDAP_DOMAIN,
    CRTSH_DOMAIN,
    HOLEHE,
    MAIGRET,
    WAYBACK_URL,
    WAYBACK_DOMAIN,
    COMMONCRAWL_URL,
    COMMONCRAWL_DOMAIN,
)


def registry_health() -> dict[str, object]:
    sources = [descriptor.health() for descriptor in SOURCE_DESCRIPTORS]
    return {
        "registry_version": "v2",
        "source_count": len(sources),
        "sources": sources,
        "all_dependencies_available": all(bool(source["available"]) for source in sources),
        "all_versions_pinned": all(bool(source["version_match"]) for source in sources),
        "ready_sources": sum(1 for source in sources if bool(source["ready"])),
        "credential_gated_sources": sum(1 for source in sources if bool(source["requires_key"])),
    }
