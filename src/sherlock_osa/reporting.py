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
        headline = f"Znalazłem {len(strong)} mocnych ustaleń dla: {query}"
    elif findings:
        headline = f"Znalazłem ślady dla: {query}, ale wymagają ostrożnej interpretacji"
    else:
        headline = f"Brak potwierdzonych śladów dla: {query}"

    sentences = [
        f"Sprawdziłem {summary.sources_checked} źródeł i wykonałem "
        f"{summary.module_invocations} zapytań źródłowych.",
        f"Zebrałem {summary.findings} ustaleń, w tym "
        f"{summary.confirmed_findings} potwierdzonych.",
        f"Dostępnych jest {hard_links} klikalnych linków do dowodów.",
    ]
    if summary.sources_skipped:
        sentences.append(
            f"{summary.sources_skipped} źródeł pominięto, najczęściej przez brak klucza "
            "lub ograniczenie wybranego trybu."
        )
    if summary.source_errors:
        sentences.append(
            f"{summary.source_errors} źródeł nie odpowiedziało poprawnie; pozostałe "
            "wyniki nie zostały przez to odrzucone."
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
                "confidence": finding.confidence,
                "source_count": finding.source_count,
                "explanation": _explain_finding(finding.status.value, finding.source_count, len(links)),
                "links": links,
            }
        )

    warnings = _warnings(investigation)

    return {
        "headline": headline,
        "summary": " ".join(sentences),
        "query_kind": kind,
        "strong_findings": len(strong),
        "possible_findings": len(possible),
        "hard_links": hard_links,
        "highlights": highlights,
        "warnings": warnings,
    }


def _explain_finding(status: str, source_count: int, hard_links: int) -> str:
    if status == "CONFIRMED":
        return (
            f"To ustalenie ma mocne wsparcie: {source_count} niezależnych źródeł "
            f"i {hard_links} bezpośrednich linków do dowodów."
        )
    if status == "PROBABLE":
        return (
            f"Kilka źródeł wskazuje ten sam trop ({source_count}); traktuję go jako "
            "bardzo prawdopodobny, ale nie jako pewnik."
        )
    if status == "CONFLICTED":
        return "Źródła są ze sobą sprzeczne, więc Sherlock nie rozstrzyga tego na siłę."
    if status == "POSSIBLE":
        return "To sensowny trop, ale liczba niezależnych dowodów jest jeszcze za mała."
    return "To pojedynczy sygnał. Nie traktuj go jako potwierdzonego powiązania."


def _warnings(investigation: InvestigationResult) -> list[str]:
    warnings: list[str] = []
    for run in investigation.source_runs:
        if run.status == "SKIPPED":
            if run.reason == "MISSING_CREDENTIAL":
                warnings.append(f"{run.source}: pominięte — brak opcjonalnego klucza API.")
            else:
                warnings.append(f"{run.source}: pominięte — {run.reason or 'ograniczenie planu'}.")
        elif run.status == "TIMEOUT":
            warnings.append(f"{run.source}: przekroczony limit czasu.")
        elif run.status == "ERROR":
            warnings.append(f"{run.source}: źródło zwróciło błąd.")
        if run.rate_limited:
            warnings.append(f"{run.source}: część zapytań została ograniczona przez rate limit.")

    if investigation.conflicts:
        warnings.append(
            f"Sprzeczne ustalenia: {len(investigation.conflicts)}. Są pokazane jako konflikty."
        )
    return warnings[:50]
