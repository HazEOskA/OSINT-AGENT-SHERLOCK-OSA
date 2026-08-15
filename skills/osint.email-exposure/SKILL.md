---
name: osint.email-exposure
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS
---

# E-mail exposure

Sprawdź indeksy breach dla znormalizowanego e-maila i oddziel brak dopasowania od braku dostępności źródła. Account-enumeration wykonuj tylko przez allowlistowany prywatny worker.

Dozwolone adaptery: `xposedornot.community`, `leakcheck.v2`, `worker.holehe`. Raportuj źródło, klasę danych i confidence; nie raportuj credentiali.
