---
name: osint.darkweb-index-search
version: 1.0.0
effect: PASSIVE_FIXED_EGRESS_OR_ISOLATED_TOR
---

# Dark-web index search

Przeszukaj clearnetowy indeks Ahmia i oznacz wyniki jako `INDEX_MATCH_NOT_CONTENT_VERIFIED`. Nie twierdź, że odwiedzono stronę `.onion`.

Bezpośredni crawl ukrytych usług wymaga `COMPLETED` receiptu misji OSA,
prywatnego workera z wymuszoną trasą Tor i osobnego evidence. Publiczny Vercel
nie jest workerem Tor. Worker nie przyjmuje arbitralnego URL-a i nie zwraca
surowej treści stron.
