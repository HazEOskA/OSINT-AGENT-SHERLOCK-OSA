from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from sherlock_osa.research import IdentifierKind, ModuleContext, ModuleResult, ResearchIdentifier


class PhoneMetadataModule:
    """Offline libphonenumber enrichment for international phone identifiers.

    This module does not identify the owner and does not perform network calls. It
    reports only metadata encoded by numbering plans / libphonenumber datasets.
    """

    name = "phone.metadata"
    family = "PHONE_METADATA"
    required_capability = "osint.phone.metadata"
    supported_kinds = frozenset({IdentifierKind.PHONE})

    def __init__(self) -> None:
        self.results: list[dict[str, Any]] = []

    async def lookup(
        self,
        identifier: ResearchIdentifier,
        context: ModuleContext,
    ) -> ModuleResult:
        if identifier.kind is not IdentifierKind.PHONE:
            raise ValueError("phone metadata requires PHONE")
        try:
            parsed = phonenumbers.parse(identifier.value, None)
        except phonenumbers.NumberParseException as exc:
            fields = {
                "provider": "libphonenumber",
                "valid": False,
                "possible": False,
                "reason": str(exc),
                "owner_identified": False,
                "precise_location_available": False,
                "network_lookup_performed": False,
            }
            self.results.append(fields)
            return ModuleResult(fields=fields, confidence=0.0)

        possible = phonenumbers.is_possible_number(parsed)
        valid = phonenumbers.is_valid_number(parsed)
        region = phonenumbers.region_code_for_number(parsed) or ""
        number_type = phonenumbers.number_type(parsed)
        type_name = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
            phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
            phonenumbers.PhoneNumberType.TOLL_FREE: "TOLL_FREE",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
            phonenumbers.PhoneNumberType.SHARED_COST: "SHARED_COST",
            phonenumbers.PhoneNumberType.VOIP: "VOIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
            phonenumbers.PhoneNumberType.PAGER: "PAGER",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "VOICEMAIL",
            phonenumbers.PhoneNumberType.UNKNOWN: "UNKNOWN",
        }.get(number_type, "UNKNOWN")

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        international = phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL,
        )
        national = phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.NATIONAL,
        )
        provider_name = carrier.name_for_number(parsed, "en") or ""
        location = geocoder.description_for_number(parsed, "en") or ""
        zones = tuple(timezone.time_zones_for_number(parsed))[:8]

        fields: dict[str, Any] = {
            "provider": "libphonenumber",
            "possible": possible,
            "valid": valid,
            "e164": e164,
            "international_format": international,
            "national_format": national,
            "country_code": parsed.country_code,
            "region": region,
            "number_type": type_name,
            "carrier": provider_name,
            "general_location": location,
            "timezones": list(zones),
            "owner_identified": False,
            "precise_location_available": False,
            "network_lookup_performed": False,
        }
        self.results.append(fields)
        return ModuleResult(
            fields=fields,
            confidence=0.98 if valid else 0.55 if possible else 0.15,
        )
