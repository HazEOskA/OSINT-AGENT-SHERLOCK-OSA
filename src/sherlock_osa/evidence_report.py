from __future__ import annotations

import hashlib
import json
from typing import Sequence

from sherlock_osa.findings import Finding
from sherlock_osa.investigation import InvestigationResult


def build_proof_report(
    *,
    query: str,
    kind: str,
    investigation: InvestigationResult,
) -> dict[str, object]:
    claims = [_claim(finding) for finding in _ordered_findings(investigation.findings)]

    coverage = [
        {
            "tool": run.source,
            "source_family": run.source_family,
            "status": run.status,
            "evidence_count": run.evidence_count,
            "duration_ms": run.duration_ms,
            "rate_limited": run.rate_limited,
            "reason": run.reason,
            "error": run.error,
            "execution": "EXECUTED"
            if run.status in {"COMPLETED", "ERROR", "TIMEOUT"}
            else "NOT_EXECUTED",
        }
        for run in investigation.source_runs
    ]

    integrity_payload = {
        "investigation_id": investigation.investigation_id,
        "research_id": investigation.research_id,
        "research_result_sha256": investigation.research_result_sha256,
        "result_sha256": investigation.result_sha256,
        "claim_hashes": [str(item["claim_sha256"]) for item in claims],
    }
    report_sha256 = _sha256(integrity_payload)

    return {
        "version": "proof-report.v1",
        "query": {"kind": kind, "value": query},
        "methodology": {
            "principle": "CLAIM != PROOF",
            "fact_definition": (
                "FACT oznacza bezpośredni sygnał źródłowy o wysokiej pewności. "
                "Nie oznacza automatycznie, że wszystkie profile lub rekordy należą do tej samej osoby."
            ),
            "correlation_definition": (
                "CORRELATED oznacza zgodny trop wsparty przez co najmniej dwie niezależne "
                "rodziny źródeł."
            ),
            "hypothesis_definition": (
                "HYPOTHESIS oznacza trop wymagający dodatkowego potwierdzenia lub sygnał "
                "obarczony konfliktem."
            ),
            "negative_rule": (
                "Brak wyniku w źródle nie jest dowodem nieistnienia. "
                "Wynik username nie jest sam w sobie dowodem tożsamości osoby."
            ),
        },
        "integrity": {
            "investigation_id": investigation.investigation_id,
            "research_id": investigation.research_id,
            "research_result_sha256": investigation.research_result_sha256,
            "investigation_result_sha256": investigation.result_sha256,
            "proof_report_sha256": report_sha256,
        },
        "summary": {
            "claims": len(claims),
            "facts": sum(1 for item in claims if item["assertion"] == "FACT"),
            "correlated": sum(1 for item in claims if item["assertion"] == "CORRELATED"),
            "hypotheses": sum(1 for item in claims if item["assertion"] == "HYPOTHESIS"),
            "claims_with_hard_links": sum(
                1 for item in claims if any(evidence["url"] for evidence in item["evidence"])
            ),
            "tools_considered": len(coverage),
            "tools_executed": sum(1 for item in coverage if item["execution"] == "EXECUTED"),
        },
        "tool_coverage": coverage,
        "claims": claims,
        "atlas_bridge": {
            "route": "/tools",
            "purpose": (
                "World OSINT Atlas rozszerza discovery narzędzi. Tylko adaptery oznaczone "
                "SHERLOCK LIVE są automatycznie wykonywane; pozostałe są katalogiem."
            ),
        },
    }


def _ordered_findings(findings: Sequence[Finding]) -> list[Finding]:
    assertion_rank = {"FACT": 0, "CORRELATED": 1, "HYPOTHESIS": 2}
    status_rank = {
        "CONFIRMED": 0,
        "PROBABLE": 1,
        "POSSIBLE": 2,
        "UNVERIFIED": 3,
        "CONFLICTED": 4,
    }
    return sorted(
        findings,
        key=lambda item: (
            assertion_rank.get(item.assertion.value, 9),
            status_rank.get(item.status.value, 9),
            -item.confidence,
            -item.source_count,
            item.kind,
            item.value,
        ),
    )


def _claim(finding: Finding) -> dict[str, object]:
    evidence = [
        {
            "evidence_id": source.evidence_id,
            "source": source.source,
            "source_family": source.source_family,
            "url": source.url,
            "collected_at": source.collected_at,
            "evidence_sha256": source.evidence_sha256,
            "confidence": source.confidence,
            "what_is_this": _source_description(source.source_family, source.source),
            "supports": _evidence_support(finding),
            "does_not_establish": _evidence_limit(finding),
        }
        for source in finding.sources
    ]

    source_families = sorted({source.source_family for source in finding.sources})
    strength = _strength(finding)
    explanation = _explanation(finding, source_families)

    return {
        "claim_id": finding.finding_id,
        "title": finding.title,
        "kind": finding.kind,
        "value": finding.value,
        "assertion": finding.assertion.value,
        "status": finding.status.value,
        "confidence": finding.confidence,
        "evidence_strength": strength,
        "independent_source_families": source_families,
        "independent_source_count": finding.source_count,
        "evidence_count": len(finding.sources),
        "first_seen_at": finding.first_seen_at,
        "last_seen_at": finding.last_seen_at,
        "claim_sha256": finding.evidence_sha256,
        "explanation": explanation,
        "supports": _claim_support(finding),
        "does_not_establish": _claim_limit(finding),
        "evidence": evidence,
    }


def _strength(finding: Finding) -> str:
    if finding.status.value == "CONFLICTED":
        return "CONFLICTED"
    if finding.assertion.value == "FACT" and finding.source_count >= 2:
        return "DIRECT_CORROBORATED"
    if finding.assertion.value == "FACT":
        return "DIRECT_SINGLE_SOURCE"
    if finding.assertion.value == "CORRELATED" and finding.source_count >= 3:
        return "MULTI_SOURCE_CORRELATION"
    if finding.assertion.value == "CORRELATED":
        return "CORRELATED"
    return "LEAD_ONLY"


def _explanation(finding: Finding, source_families: list[str]) -> str:
    families = ", ".join(source_families) if source_families else "brak niezależnej rodziny źródła"
    if finding.status.value == "CONFLICTED":
        return (
            f"Źródła dla tego tropu są sprzeczne. Sherlock zachowuje konflikt zamiast "
            f"wymuszać rozstrzygnięcie. Rodziny źródeł: {families}."
        )
    if finding.assertion.value == "FACT":
        return (
            f"Bezpośredni sygnał źródłowy. Niezależne rodziny źródeł: {families}. "
            f"Pewność korelacji: {finding.confidence:.2f}."
        )
    if finding.assertion.value == "CORRELATED":
        return (
            f"Ten sam trop pojawił się w wielu niezależnych rodzinach źródeł: {families}. "
            "Jest to korelacja, nie automatyczny dowód wspólnej tożsamości."
        )
    return (
        f"To lead wymagający dalszego potwierdzenia. Dostępne rodziny źródeł: {families}. "
        f"Pewność: {finding.confidence:.2f}."
    )


def _claim_support(finding: Finding) -> str:
    kind = finding.kind.upper()
    if kind == "USERNAME":
        return "Wspiera istnienie lub występowanie wskazanego username w zebranych źródłach."
    if kind == "EMAIL":
        return "Wspiera występowanie adresu e-mail w zebranych publicznych/providerowych danych."
    if kind == "PHONE":
        return "Wspiera występowanie lub poprawny format numeru w źródłach objętych badaniem."
    if kind == "DOMAIN":
        return "Wspiera powiązanie domeny z rekordem lub obserwacją zwróconą przez źródło."
    if kind == "URL":
        return "Wspiera istnienie lub zaobserwowanie konkretnego adresu URL."
    if kind == "ACCOUNT":
        return "Wspiera istnienie rekordu konta opisanego przez dane źródłowe."
    return f"Wspiera występowanie wartości typu {kind} w zebranym materiale dowodowym."


def _claim_limit(finding: Finding) -> str:
    kind = finding.kind.upper()
    if kind in {"USERNAME", "ACCOUNT", "URL"}:
        return (
            "Nie dowodzi samodzielnie, że konto lub URL należy do konkretnej osoby. "
            "Do identyfikacji potrzebna jest niezależna korelacja."
        )
    if kind == "EMAIL":
        return (
            "Nie dowodzi, że adres jest obecnie kontrolowany przez badaną osobę ani że każdy "
            "rekord z tym adresem dotyczy tej samej tożsamości."
        )
    if kind == "PHONE":
        return (
            "Nie dowodzi właściciela numeru ani jego bieżącej, precyzyjnej lokalizacji."
        )
    if kind == "DOMAIN":
        return (
            "Nie dowodzi bieżącego właściciela osoby fizycznej ani kontroli nad całą infrastrukturą domeny."
        )
    return "Nie dowodzi szerszej tożsamości lub intencji poza zakresem bezpośredniego sygnału źródłowego."


def _evidence_support(finding: Finding) -> str:
    return f"Ten rekord źródłowy jest jednym z dowodów wspierających claim {finding.finding_id}."


def _evidence_limit(finding: Finding) -> str:
    return _claim_limit(finding)


def _source_description(family: str, source: str) -> str:
    descriptions = {
        "github": "Publiczny rekord/API GitHub związany z profilem lub artefaktem kodowym.",
        "gitlab": "Publiczny rekord/API GitLab związany z profilem lub artefaktem kodowym.",
        "gravatar": "Publiczny sygnał Gravatar powiązany z hashem/adresem e-mail.",
        "holehe": "Sygnał enumeracyjny z Holehe dotyczący rejestracji/usługi dla adresu e-mail.",
        "maigret": "Sygnał enumeracyjny username z Maigret.",
        "socialmesh": "Znormalizowany wynik Sherlock Social Mesh z przypiętych datasetów username.",
        "hibp": "Providerowy sygnał Have I Been Pwned dotyczący ekspozycji konta.",
        "rdap": "Autorytatywny/publiczny rekord RDAP dotyczący domeny lub rejestracji.",
        "crtsh": "Publiczny rekord Certificate Transparency z crt.sh.",
        "wayback": "Historyczny rekord URL/domeny z Internet Archive Wayback.",
        "commoncrawl": "Historyczny/publiczny rekord indeksu Common Crawl.",
        "emailosint": "Providerowy rekord EmailOSINT znormalizowany przez Sherlocka.",
        "phone": "Lokalna analiza metadanych numeru telefonu bez identyfikacji właściciela.",
        "seed-expansion": "Lokalny deterministyczny pivot wynikający z wejściowego identyfikatora.",
    }
    return descriptions.get(
        family,
        f"Znormalizowany rekord źródłowy z modułu {source}.",
    )


def _sha256(payload: object) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
