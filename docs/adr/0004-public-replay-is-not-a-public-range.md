# ADR-0004: Public replay is not a public Attack Range

Status: accepted

Date: 2026-08-15

## Decision

Vercel hostuje wyłącznie stateless replay oznaczonego wektora receiptu OSA.
Prawdziwy Engine, durable evidence, Tor, podatne targety i worker z efektami
pozostają poza publicznym deploymentem.

## Consequences

- demo działa bez sekretów i zewnętrznej bazy;
- signer, broker, simulation worker i hash-chain są wykonywane naprawdę;
- wynik nie może być przedstawiany jako live Engine mission;
- evidence publicznego demo ma trwałość `PER_REQUEST`, nie `DURABLE`.
