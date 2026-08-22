# Security policy

## Supported versions

`0.2.x` receives security fixes. This remains an alpha OSINT release; it is not
a claim of perfect anonymity, exhaustive coverage or production-grade isolation.

## Reporting

Nie otwieraj publicznego issue zawierającego podatność, token, badany
identyfikator, wynik wycieku ani payload evidence. Użyj GitHub Private
Vulnerability Reporting. Podaj commit, reprodukcję, wpływ i minimalną poprawkę,
jeżeli jest znana.

## Non-negotiable boundaries

- prywatne adaptery nie startują bez `COMPLETED` receipt OSA Engine;
- Engine dostaje hash identyfikatora, nigdy surowy e-mail/telefon;
- publiczny preview nie wykonuje bezpośrednich połączeń `.onion`;
- worker Tor nie przyjmuje arbitralnego URL-a i nie ma bezpośredniego egressu;
- breach adaptery nie zwracają haseł ani surowych rekordów;
- `AUTHORIZED_EXTERNAL` pozostaje zablokowany bez dowodu własności;
- sekrety pochodzą z env i nie mogą trafić do evidence;
- container nie jest przedstawiany jako nieprzekraczalna granica bezpieczeństwa.

## Operator responsibilities

Używaj wyłącznie do self-audytu, badań za zgodą, obrony organizacji lub
udokumentowanego interesu publicznego. Sprawdź regulamin każdego providera,
ustaw limity zapytań, krótki retention i osobny token workera. Nie publikuj
wyników zawierających dane osobowe.

Publiczny Vercel działa stateless i tworzy ledger tylko w pamięci requestu. To
minimalizuje retencję, ale nie usuwa faktu, że wybrany provider otrzymuje
identyfikator potrzebny do lookupu.
