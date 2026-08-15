# Security policy

## Supported versions

`0.1.x` receives security fixes. This is an alpha control-plane release; it is
not a claim of production-grade isolation.

## Reporting

Do not open a public issue containing an exploitable vulnerability, token,
target data or evidence payload. Use GitHub's private vulnerability reporting
for this repository. Include the affected commit, reproduction, impact and a
minimal proposed fix when possible.

## Non-negotiable boundaries

- No execution without a signed, unexpired mission and an engine receipt.
- `AUTHORIZED_EXTERNAL` stays blocked until an independent ownership verifier
  is implemented and tested.
- v0.1 performs deterministic simulations only; it does not run scanners,
  exploits, shell commands or arbitrary payloads.
- A container is not claimed as the final hostile-code security boundary.
- Secrets must come from environment variables and must never enter evidence.
