---
name: osint.domain-intelligence
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS
---

# Domain intelligence

Zbieraj wyłącznie pasywne dane DNS i RDAP. Nie wykonuj skanowania portów. Dane kontaktowe z RDAP pomijaj, a rozbudowane asset discovery deleguj do prywatnego workera.

Dozwolone adaptery: `local.dns`, `rdap.bootstrap`, prywatne `Amass`,
`SpiderFoot` i `Recon-ng`.
