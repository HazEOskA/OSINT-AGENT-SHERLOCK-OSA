---
name: osint.username-discovery
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS
---

# Username discovery

Sprawdzaj publiczne profile przez stałe adaptery. Wygenerowany URL jest kandydatem; dopiero odpowiedź źródła z właściwą sygnaturą może stać się findingiem.

Dozwolone adaptery: `github.public-profile`, `local.profile-map`, `leakcheck.v2`
oraz prywatne workery `Sherlock`, `Maigret` i `WhatsMyName`.
