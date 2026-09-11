from __future__ import annotations

from typing import Sequence

from sherlock_osa.investigation import InvestigationResult


def build_human_report(
    *,
    query: str,
    kind: str,
    investigation: InvestigationResult,
) -> dict[str, object]:
    summary = investigation.summary
    findings = investigation.findings

    strong = [
        finding
        for finding in findings
        if finding.status.value in {"CONFIRMED", "PROBABLE"}
    ]
    possible = [
        finding
        for finding in findings
        if finding.status.value == "POSSIBLE"
    ]

    hard_links = sum(
        1
        for finding in findings
        for source in finding.sources
        if source.url
    )

    if strong:
        headline = f"Znalazłem {len(strong)} ustaleń wspartych dowodami dla: {query}"
    elif findings:
        headline = f"Znalazłem ślady dla: {query}, ale nie spełniają progu mocnego potwierdzenia"
    else:
        headline = f"Brak pozytywnie zweryfikowanych śladów dla: {query}"

    sentences = [
        f"Sprawdziłem {summary.sources_checked} przebiegów źródłowych i wykonałem "
        f"{summary.module_invocations} zapytań.",
        f"Po odrzuceniu wyników negatywnych, niejednoznacznych i niewiarygodnych zostało "
        f"{summary.findings} ustaleń, w tym {summary.confirmed_findings} potwierdzonych.",
        f"Dostępnych jest {hard_links} klikalnych linków do dowodów.",
        "Truth Engine V4 nie traktuje HTTP 200 ani samego zakończenia źródła jako dowodu istnienia konta.",
    ]
    if summary.sources_skipped:
        sentences.append(
            f"{summary.sources_skipped} źródeł pominięto, najczęściej przez brak klucza "
            "lub ograniczenie wybranego trybu."
        )
    if summary.source_errors:
        sentences.append(
            f"{summary.source_errors} źródeł nie odpowiedziało poprawnie; pozostałe "
            "wyniki oceniono niezależnie."
        )
    if investigation.conflicts:
        sentences.append(
            f"Wykryłem {len(investigation.conflicts)} sprzeczności i oznaczyłem je "
            "zamiast zgadywać."
        )

    highlights: list[dict[str, object]] = []
    for finding in sorted(
        findings,
        key=lambda item: (
            item.status.value not in {"CONFIRMED", "PROBABLE"},
            -item.confidence,
            -item.source_count,
            item.kind,
            item.value,
        ),
    )[:20]:
        links = [
            {
                "source": source.source,
                "url": source.url,
            }
            for source in finding.sources
            if source.url
        ][:12]
        highlights.append(
            {
                "title": finding.title,
                "kind": finding.kind,
                "value": finding.value,
                "status": finding.status.value,
                "assertion": finding.assertion.value,
                "confidence": finding.confidence,
                "independent_mechanisms": finding.source_count,
                # Compatibility for the current UI/API clients. In V4 this value is
                # the number of independent evidence mechanisms, not scraper names.
                "source_count": finding.source_count,
                "explanation": _explain_finding(
                    finding.status.value,
                    finding.assertion.value,
                    finding.source_count,
                    len(links),
                ),
                "links": links,
            }
        )

    warnings = _warnings(investigation)

    return {
        "headline": headline,
        "summary": " ".join(sentences),
        "query_kind": kind,
        "truth_engine": "SHERLOCK_TRUTH_ENGINE_V4",
        "truth_contract": {
            "completed_is_found": False,
            "http_200_is_found": False,
            "same_username_is_same_person": False,
            "aggregator_duplicates_are_independent": False,
        },
        "strong_findings": len(strong),
        "possible_findings": len(possible),
        "hard_links": hard_links,
        "highlights": highlights,
        "warnings": warnings,
    }


def _explain_finding(
    status: str,
    assertion: str,
    mechanism_count: int,
    hard_links: int,
) -> str:
    if status == "CONFIRMED":
        return (
            f"Potwierdzone przez {mechanism_count} niezależne mechanizmy dowodowe "
            f"i {hard_links} bezpośrednich linków."
        )
    if status == "PROBABLE" and assertion == "FACT":
        return (
            "Bezpośrednie źródło potwierdza ten konkretny profil lub rekord, ale pojedynczy "
            "mechanizm nie wystarcza do ogłoszenia całej tożsamości jako CONFIRMED."
        )
    if status == "PROBABLE":
        return (
            f"Co najmniej {mechanism_count} niezależne mechanizmy wskazują ten sam trop; "
            "to silne powiązanie, ale nadal nie absolutny pewnik."
        )
    if status == "CONFLICTED":
        return "Dowody są sprzeczne, więc Sherlock nie rozstrzyga tego na siłę."
    if status == "POSSIBLE":
        return (
            "To pozytywny trop, ale nie ma jeszcze wystarczającej niezależności dowodów. "
            "Dwa agregatory tego samego serwisu liczą się jako jeden mechanizm."
        )
    return "To słaby lub pojedynczy sygnał. Nie traktuj go jako potwierdzonego powiązania."


def _warnings(investigation: InvestigationResult) -> list[str]:
    warnings: list[str] = []
    for run in investigation.source_runs:
        if run.status == "SKIPPED":
            if run.reason == "MISSING_CREDENTIAL":
                warnings.append(f"{run.source}: pominięte — brak opcjonalnego klucza API.")
            else:
                warnings.append(f"{run.source}: pominięte — {run.reason or 'ograniczenie planu'}.")
        elif run.status == "TIMEOUT":
            warnings.append(f"{run.source}: przekroczony limit czasu; brak wyniku nie oznacza NOT_FOUND.")
        elif run.status == "ERROR":
            warnings.append(f"{run.source}: źródło zwróciło błąd; nie użyto go jako dowodu negatywnego.")
        if run.rate_limited:
            warnings.append(f"{run.source}: część zapytań została ograniczona przez rate limit.")

    if investigation.conflicts:
        warnings.append(
            f"Sprzeczne ustalenia: {len(investigation.conflicts)}. Są pokazane jako konflikty."
        )
    return warnings[:50]
