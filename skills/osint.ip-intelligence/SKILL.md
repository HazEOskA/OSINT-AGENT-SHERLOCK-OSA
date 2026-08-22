---
name: osint.ip-intelligence
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS
---

# IP intelligence

Wykonaj reverse DNS oraz RDAP dla dokładnego adresu IP. Nie rozszerzaj zakresu na subnet i nie skanuj usług.

Dozwolone adaptery: `local.reverse-dns`, `rdap.bootstrap`.
