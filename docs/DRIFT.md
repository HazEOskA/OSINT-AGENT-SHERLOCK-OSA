# Drift ledger

## DRIFT-001 — OSA Engine capability backing

- Evidence SHA: `f365360383511fea13cd3f7af36ecbbc720ce38d`
- Engine truth: `agents.sandbox-execution` is a native fail-closed analysis, but
  `shell.run` and the sandbox execution effect are not backed.
- Sherlock response: v0.1 exposes only a simulation adapter and labels all real
  execution adapters `UNBACKED`.
- Closure: implement a separate adapter, add an Engine capability-backing entry,
  execute E2E isolation tests, then update this record.

## DRIFT-002 — Engine distribution licence

- GitHub repository metadata currently reports no detected licence for
  `HazEOskA/osa-execution-force-skills`.
- Sherlock integrates over HTTP and does not vendor Engine code.
- Fully frictionless open-source distribution remains `BLOCKED` until the Engine
  repository has an explicit licence selected by its owner.

## DRIFT-003 — Runtime attestation

- Sherlock wymaga, aby receipt Engine zwrócił w `context.commit_sha` dokładnie
  skonfigurowany pin i wiąże ten receipt hashem w scope.
- To dowodzi spójności receiptu z kontekstem misji, ale nie jest kryptograficzną
  atestacją obrazu procesu Engine.
- Pełna runtime identity pozostaje `CONFIG_BOUND_NOT_ATTESTED` do czasu podpisu
  release/image lub zewnętrznego verifiera deploymentu.
