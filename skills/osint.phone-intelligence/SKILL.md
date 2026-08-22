---
name: osint.phone-intelligence
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS
---

# Phone intelligence

Normalizuj numer do E.164, ustal kod kraju bez zgadywania właściciela, a następnie uruchom skonfigurowany provider ekspozycji. Z wyniku providerów zachowaj wyłącznie liczbę dopasowań, nazwy źródeł i typy ujawnionych pól.

Dozwolone adaptery: `local.phone-metadata`, `leakcheck.v2`, prywatny `PhoneInfoga`/`Ignorant` worker. Nigdy nie zwracaj haseł ani pełnych rekordów wycieku.
