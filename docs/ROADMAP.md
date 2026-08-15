# Roadmap

## v0.1 — control-plane proof

- signed mission, deterministic broker, simulation, evidence, replay, UI;
- OSA Engine HTTP adapter;
- zero real security-tool execution.

## v0.2 — isolated lab worker

- osobny worker host;
- typed adapter registry and idempotency;
- only `lab://` asset resolution inside an isolated range network;
- Juice Shop adapter followed by Zeek telemetry;
- kill switch and resource quotas;
- destructive tests only on disposable fixtures.

## v0.3 — research plane

- passive-only OSINT adapters;
- Tor gateway enforced by network namespace, not prompt;
- source provenance and rate limits;
- PII minimisation and retention controls.

## v0.4 — microVM boundary

- Firecracker lifecycle controller;
- gVisor defence-in-depth where compatible;
- signed immutable worker images;
- escape drills and independent validation.

## v0.5 — authorised external

- DNS/HTTP ownership challenge verifier;
- exact FQDN/IP/port allowlist with short expiry;
- separate approval binding and emergency stop;
- policy/legal review before enablement.
