---
name: osint.query-classification
version: 1.0.0
effect: LOCAL_ONLY
---

# Query classification

Rozpoznaj `EMAIL`, `PHONE`, `PERSON`, `USERNAME`, `DOMAIN` albo `IP`, znormalizuj wartość i przerwij misję przy niejednoznacznym wejściu. Nie wykonuj sieci ani nie zgaduj typu.

Postcondition: wynik ma typ, wartość kanoniczną, maskę i SHA-256; ledger nie zawiera surowego identyfikatora.
