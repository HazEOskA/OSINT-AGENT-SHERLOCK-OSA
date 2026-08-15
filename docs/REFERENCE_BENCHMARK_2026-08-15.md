# OSINT reference benchmark — 2026-08-15

To jest kuratorowany benchmark dopasowania do Sherlock OSA, nie obiektywny
ranking GitHuba. Istnienie repo, aktywność, liczba gwiazdek i deklarowana
licencja zostały sprawdzone przez GitHub API 2026-08-15. Gwiazdki są snapshotem.

| # | Repo | Główna domena | ★ | Licencja | Wzorzec użyty w OSA |
|---:|---|---|---:|---|---|
| 1 | [OpenOSINT/OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) | agent | 1,410 | MIT | agentowy dobór narzędzi do typów identyfikatorów |
| 2 | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | framework | 21,073 | MIT | moduły, korelacja, Tor i graf encji |
| 3 | [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) | username | 89,586 | MIT | enumeracja publicznych kont |
| 4 | [soxoj/maigret](https://github.com/soxoj/maigret) | username | 36,788 | MIT | profil, rekurencyjne pivoty i dossier |
| 5 | [sundowndev/phoneinfoga](https://github.com/sundowndev/phoneinfoga) | telefon | 17,504 | GPL-3.0 | normalizacja i pasywne plany wyszukiwania |
| 6 | [megadose/holehe](https://github.com/megadose/holehe) | e-mail | 13,073 | GPL-3.0 | sygnały rejestracji kont dla e-maila |
| 7 | [mxrch/GHunt](https://github.com/mxrch/GHunt) | e-mail | 19,368 | AGPL-3.0 | moduły publicznego footprintu Google |
| 8 | [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) | framework | 5,851 | GPL-3.0 | workspaces, klucze i powtarzalne moduły |
| 9 | [owasp-amass/amass](https://github.com/owasp-amass/amass) | domeny | 14,983 | Apache-2.0 | pasywne mapowanie powierzchni zasobów |
| 10 | [WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | username data | 2,762 | CC-BY-SA-4.0 | utrzymywany katalog detekcji profili |
| 11 | [XposedOrNot/XposedOrNot-API](https://github.com/XposedOrNot/XposedOrNot-API) | wycieki | 90 | MIT | otwarte API metadanych ekspozycji |
| 12 | [khast3x/h8mail](https://github.com/khast3x/h8mail) | wycieki | 5,250 | BSD-3-Clause | wiele źródeł breach lookup dla e-maila |
| 13 | [alpkeskin/mosint](https://github.com/alpkeskin/mosint) | e-mail | 5,990 | MIT | modularne zapytania e-mail OSINT |
| 14 | [qeeqbox/social-analyzer](https://github.com/qeeqbox/social-analyzer) | SOCMINT | 23,759 | AGPL-3.0 | szeroki katalog profili i API/CLI/UI |
| 15 | [megadose/ignorant](https://github.com/megadose/ignorant) | telefon | 2,010 | GPL-3.0 | sygnały rejestracji kont dla telefonu |
| 16 | [ahmia/ahmia-crawler](https://github.com/ahmia/ahmia-crawler) | Dark Web | 228 | BSD-3-Clause | crawler i pipeline indeksu Tor |
| 17 | [apurvsinghgautam/robin](https://github.com/apurvsinghgautam/robin) | Dark Web agent | 6,315 | MIT | filtrowanie wyników i raport śledztwa |
| 18 | [biolds/sosse](https://github.com/biolds/sosse) | crawler | 409 | AGPL-3.0 | self-hosted crawl, archiwum i harmonogram |
| 19 | [Te-k/harpoon](https://github.com/Te-k/harpoon) | threat intel | 1,288 | GPL-3.0 | rejestr źródeł i zunifikowany CLI |
| 20 | [Datalux/Osintgram](https://github.com/Datalux/Osintgram) | SOCMINT | 14,000 | GPL-3.0 | interaktywny workflow badania username |

## Jak wynik benchmarku wpłynął na v0.2

| Problem | Przyjęty wzorzec | Implementacja |
|---|---|---|
| różne typy identyfikatorów | agentowy router OpenOSINT | deterministyczny registry 10 typed skills |
| setki potencjalnych źródeł | moduły SpiderFoot/Recon-ng | adaptery ze wspólnym `AdapterResult` i niezależnym statusem |
| false positives osoby | dossier Maigret | kandydat ma `CANDIDATE_REQUIRES_CORRELATION` |
| wycieki | XposedOrNot/h8mail | zwracamy źródła/metadane, nigdy hasła ani raw rows |
| telefon | PhoneInfoga | E.164, kraj, precyzyjne pivoty; owner/carrier nie są zgadywane |
| Dark Web | Ahmia/Robin | index match oddzielony od weryfikacji treści przez Tor |
| odtwarzalność | Recon-ng/SpiderFoot | plan, trace i per-request evidence hash-chain |

## Zasada licencyjna

Repo z MIT/Apache/BSD mogą zostać biblioteką dopiero po osobnym przeglądzie
zależności. GPL/AGPL i zewnętrzne datasety pozostają osobnymi procesami/API lub
inspiracją interfejsu. W v0.2 żaden z 20 projektów nie jest vendorowany.

Repo bez jednoznacznego pliku licencji nie zostały wpisane do głównej
dwudziestki, nawet jeśli technicznie były interesujące.
