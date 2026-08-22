# Threat model v0.2

## Chronione aktywa

- badany identyfikator i wyniki OSINT;
- klucz operatora, Engine API key i token research workera;
- poprawność planu skills i provenance findings;
- niezmienność receiptu i evidence;
- wymuszenie trasy Tor dla bezpośredniego `.onion`;
- brak credentiali/raw breach rows w odpowiedzi.

## Zakładani przeciwnicy

1. klient API próbujący użyć usługi do stalkingu lub masowego harvestingu;
2. prompt-injected albo błędny agent;
3. złośliwa strona `.onion` i parser-hostile HTML;
4. provider zwracający niepoprawny lub ogromny payload;
5. operator próbujący wstrzyknąć URL/flagę shella przez query;
6. worker próbujący ominąć Tor;
7. proces modyfikujący lokalny ledger;
8. złośliwa zależność albo projekt benchmarkowy.

## Kontrole v0.2

| Zagrożenie | Kontrola | Status |
|---|---|---|
| brak podstawy prawnej | wymagane `purpose` + `consent` | `POLICY_GATE`, nie weryfikuje prawdziwości |
| arbitralny egress publiczny | host allowlist w kliencie | `MITIGATED_APPLICATION` |
| arbitralny egress workera | Ahmia + v3 `.onion` allowlist, fixed argv | `MITIGATED_APPLICATION` |
| ominięcie Tor przez worker | osobna wewnętrzna sieć `tor-lane` | `MITIGATED_COMPOSE` |
| shell injection | brak shella, stałe argv curl | `MITIGATED` |
| oversized/slow source | timeouts, limits bytes/results | `MITIGATED` |
| false positive osoby | jawny candidate + correlation required | `MITIGATED_REPORTING` |
| index = content | dwa odrębne verification states | `MITIGATED_REPORTING` |
| credential exposure | metadata allowlist, raw rows discarded | `MITIGATED_ADAPTER` |
| query leakage to Engine | tylko SHA-256 identyfikatora | `MITIGATED` |
| execution without evidence | Engine `COMPLETED` gate | `MITIGATED_POLICY` |
| ledger edit | hash-chain verification | `DETECTABLE`, nie WORM |
| supply chain | stdlib runtime; brak vendoringu 20 repo | `REDUCED` |

## Remaining risks

- publiczny endpoint nie ma jeszcze rate limitu ani CAPTCHA; preview nie powinien
  być traktowany jak bezobsługowa usługa produkcyjna;
- operator może skłamać w polu celu/zgody;
- provider widzi query i może je logować zgodnie ze swoim regulaminem;
- Tor nie gwarantuje anonimowości przeciw każdemu przeciwnikowi;
- Docker network isolation nie zastępuje microVM ani host firewall;
- HTML parser nie renderuje JS i może ominąć treść aplikacji dynamicznej;
- indeks Ahmia ma niepełne i opóźnione pokrycie;
- administrator hosta może podmienić ledger i przeliczyć cały łańcuch;
- jeden Bearer token nie zapewnia RBAC ani rozliczalności wielu operatorów;
- realny Engine i pełna topologia Tor muszą przejść test na docelowym hoście.
