# ADR-0001: OSA Engine is the only agent router

Status: accepted

Sherlock OSA sends mission intent to OSA Execution Force Engine and stores the
Engine receipt hash in the signed scope. It does not implement a second natural
language router. The local Capability Broker is a deterministic enforcement
boundary, not an intent router.

Consequence: if Engine is unavailable or does not complete the mission, the
broker denies execution.
