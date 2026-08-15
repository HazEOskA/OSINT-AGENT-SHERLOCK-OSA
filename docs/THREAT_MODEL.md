# Threat model v0.1

## Chronione aktywa

- klucz operatora i secret podpisujący misje;
- API key OSA Engine;
- niezmienność scope'u i evidence;
- brak nieautoryzowanego efektu sieciowego;
- prywatność targetów i wyników.

## Zakładani przeciwnicy

1. przejęty lub prompt-injected agent;
2. operator UI z błędnym targetem;
3. klient API próbujący rozszerzyć scope po podpisaniu;
4. worker próbujący wykonać inną capability;
5. proces modyfikujący ledger na dysku;
6. złośliwy dependency lub projekt referencyjny.

## Kontrole v0.1

| Zagrożenie | Kontrola | Pozostały status |
|---|---|---|
| Scope tampering | HMAC-SHA256 + constant-time verify | `MITIGATED_LOCAL` |
| Target escape | exact typed target + exact ports | `MITIGATED_POLICY` |
| Prompt injection | model nie podejmuje decyzji policy | `MITIGATED_POLICY` |
| Public target w labie | tylko `lab://` | `MITIGATED_POLICY` |
| External without ownership | hard deny | `MITIGATED_FAIL_CLOSED` |
| Ledger edit | hash-chain verification | `DETECTABLE`, nie WORM |
| Secret leakage | recursive redaction + env-only config | `PARTIAL` |
| Host escape | brak hostile-code execution v0.1 | `NOT_EXPOSED` |
| Supply chain | zero runtime dependencies | `REDUCED` |

## Remaining risks

- Administrator hosta może podmienić ledger i przeliczyć cały łańcuch. Kotwica
  zewnętrzna/WORM nie jest zaimplementowana.
- HMAC jest jednym współdzielonym sekretem; KMS i rotacja kluczy są planowane.
- SQLite i JSONL są przeznaczone dla jednego procesu.
- API nie ma RBAC; istnieje jeden operator token.
- OSA Engine behavioral integration z tym hostem wymaga osobnego testu na realnej
  instancji; w CI używany jest test double.
