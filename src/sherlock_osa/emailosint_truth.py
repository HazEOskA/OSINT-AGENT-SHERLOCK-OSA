from __future__ import annotations

import re
from typing import Any, Mapping

from sherlock_osa.emailosint import EmailOsintClient
from sherlock_osa.errors import SherlockError
from sherlock_osa.truth_engine import TruthVerdict


class TruthEmailOsintClient(EmailOsintClient):
    """EmailOSINT client that preserves provider data but fixes truth semantics."""

    def lookup(self, raw: object) -> dict[str, Any]:
        try:
            bundle = super().lookup(raw)
        except SherlockError as exc:
            if exc.code == "EMAILOSINT_HTTP_ERROR":
                match = re.search(r"HTTP\s+(\d{3})", exc.message)
                code = int(match.group(1)) if match else 0
                if code == 401:
                    raise SherlockError(
                        "EMAILOSINT_AUTH_FAILED",
                        "EmailOSINT odrzucił klucz API (HTTP 401).",
                        status=502,
                    ) from exc
                if code == 403:
                    raise SherlockError(
                        "EMAILOSINT_FORBIDDEN",
                        "EmailOSINT odmówił dostępu (HTTP 403).",
                        status=502,
                    ) from exc
                if code == 429:
                    raise SherlockError(
                        "EMAILOSINT_RATE_LIMITED",
                        "EmailOSINT osiągnął limit zapytań (HTTP 429).",
                        status=503,
                    ) from exc
                if 500 <= code <= 599:
                    raise SherlockError(
                        "EMAILOSINT_UPSTREAM_ERROR",
                        f"EmailOSINT ma błąd upstream (HTTP {code}).",
                        status=503,
                    ) from exc
            raise
        return enforce_emailosint_truth(bundle)


def enforce_emailosint_truth(bundle: dict[str, Any]) -> dict[str, Any]:
    identity = bundle.get("identity")
    signals = identity.get("signals", []) if isinstance(identity, Mapping) else []
    found = [
        signal
        for signal in signals
        if isinstance(signal, Mapping)
        and str(signal.get("status", "")).upper() == TruthVerdict.FOUND.value
    ] if isinstance(signals, list) else []
    observed = [
        signal
        for signal in signals
        if isinstance(signal, Mapping)
        and str(signal.get("status", "")).upper() == TruthVerdict.OBSERVED.value
    ] if isinstance(signals, list) else []

    if isinstance(identity, dict):
        identity["linked_accounts"] = found
        counts = identity.get("counts")
        if isinstance(counts, dict):
            counts["linked_accounts"] = len(found)
            counts["observed"] = len(observed)

    exposure = bundle.get("exposure")
    if isinstance(exposure, dict):
        exposure["linked_accounts"] = found
        counts = exposure.get("counts")
        if isinstance(counts, dict):
            counts["linked_accounts"] = len(found)
            counts["observed_identity_signals"] = len(observed)

    parity = bundle.get("parity")
    if isinstance(parity, dict):
        parity["linked_account_count"] = len(found)
        parity["observed_identity_signal_count"] = len(observed)
        parity["truth_engine"] = "V4"

    verification = bundle.get("verification")
    if isinstance(verification, dict):
        verification["truth_engine"] = "V4"
        verification["completed_is_found"] = False
        verification["observed_is_linked_account"] = False

    bundle["truth"] = {
        "engine": "SHERLOCK_TRUTH_ENGINE_V4",
        "found_identity_signals": len(found),
        "observed_identity_signals": len(observed),
        "completed_is_found": False,
        "observed_is_linked_account": False,
    }
    return bundle
