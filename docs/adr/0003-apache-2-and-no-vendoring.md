# ADR-0003: Apache-2.0 and no third-party vendoring in v0.1

Status: accepted

Sherlock OSA is Apache-2.0. The benchmark contains MIT, Apache, BSD, GPL, AGPL,
mixed and source-available projects. To prevent accidental licence contamination,
v0.1 copies no third-party source and integrates only the separately owned OSA
Engine over HTTP.
