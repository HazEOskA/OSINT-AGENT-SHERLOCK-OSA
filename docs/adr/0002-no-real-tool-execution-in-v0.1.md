# ADR-0002: No real tool execution in v0.1

Status: accepted

The first release proves scope, evidence and replay with a deterministic
simulation adapter. It cannot invoke shell, scanners, exploits or arbitrary
network requests.

This avoids turning an unverified container into a claimed security boundary.
An adapter becomes backed only after effect evidence, independent postcondition
verification, isolation tests and rollback/kill-switch validation.
