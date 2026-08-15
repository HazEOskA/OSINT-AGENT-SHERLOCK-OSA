# Reference benchmark — 2026-08-15

To jest kuratorowany benchmark dopasowania architektonicznego, nie obiektywny
ranking całego GitHuba. Metadane, aktywność i licencje sprawdzono bezpośrednio w
repozytoriach 2026-08-15. Liczba gwiazdek jest snapshotem, nie miarą jakości.

| # | Repo | Plane / wzorzec | ★ snapshot | Licencja | Decyzja v0.1 |
|---:|---|---|---:|---|---|
| 1 | [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) | multi-agent pentest, monitoring, persistence | 21,833 | MIT | wzorzec supervision; bez kopiowania |
| 2 | [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) | staged pipeline, resume, walkthrough | 14,866 | MIT | wzorzec session state |
| 3 | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | AI red-team scenarios, scoring, memory | 4,304 | MIT | wzorzec scenario/eval |
| 4 | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | MCP tool gateway | 11,016 | MIT | katalog adapterów; nie uruchamiamy v0.1 |
| 5 | [OWASP/Nettacker](https://github.com/OWASP/Nettacker) | modular scanner, drift, API/UI | 5,507 | Apache-2.0 | wzorzec modułów i raportów |
| 6 | [apache/caldera](https://github.com/apache/caldera) | adversary emulation, plugin model | 7,190 | Apache-2.0 | wzorzec range operation |
| 7 | [owasp-amass/amass](https://github.com/owasp-amass/amass) | attack-surface mapping | 14,983 | Apache-2.0 | przyszły passive adapter |
| 8 | [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) | username OSINT | 89,549 | MIT | przyszły passive adapter |
| 9 | [soxoj/maigret](https://github.com/soxoj/maigret) | dossier, graph, report formats | 36,777 | MIT | wzorzec entity evidence |
| 10 | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | 200+ OSINT modules, correlations | 21,053 | MIT | wzorzec plugin graph |
| 11 | [intelowlproject/IntelOwl](https://github.com/intelowlproject/IntelOwl) | analyzers/connectors, async jobs | 4,667 | AGPL-3.0 | API inspiration only |
| 12 | [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) | CTI graph and connectors | 9,810 | Community Apache-2.0; mixed repo | concept/API only; per-file review |
| 13 | [MISP/MISP](https://github.com/MISP/MISP) | CTI exchange, workflow, RBAC, audit | 6,473 | AGPL-3.0 | external API only |
| 14 | [wazuh/wazuh](https://github.com/wazuh/wazuh) | XDR/SIEM endpoint telemetry | 16,529 | GPL-2.0 + exception text | future external adapter |
| 15 | [zeek/zeek](https://github.com/zeek/zeek) | network telemetry and PCAP analysis | 7,875 | BSD-style | future blue-plane adapter |
| 16 | [Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD) | disposable AD lab as code | 8,194 | GPL-3.0 | future range target, isolated |
| 17 | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | vulnerable web training target | 13,668 | MIT | first planned lab target |
| 18 | [rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) | vulnerable VM factory | 5,667 | BSD-3-Clause + third parties | future range target |
| 19 | [firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker) | microVM lifecycle/isolation | 36,076 | Apache-2.0 | planned security boundary |
| 20 | [google/gvisor](https://github.com/google/gvisor) | userspace application kernel | 19,088 | Apache-2.0 | planned defence-in-depth |

## Synthesis

| Problem | Pattern adopted | Source references |
|---|---|---|
| Agent can be wrong | deterministic out-of-model broker | OSA Engine, PyRIT |
| Large tool catalogue | typed adapter manifest with explicit backing | HexStrike, Nettacker, IntelOwl |
| Long-running missions | persisted state and replay | PentAGI, PentestGPT, Caldera |
| Correlation | entity/evidence graph later, not raw LLM memory | Maigret, SpiderFoot, OpenCTI, MISP |
| Range safety | non-addressable `lab://` targets + disposable IaC | GOAD, Juice Shop, Metasploitable3 |
| Defender learning | capture telemetry for the same mission | Wazuh, Zeek |
| Hostile worker | microVM boundary plus optional userspace kernel | Firecracker, gVisor |

## Licence rule

No source from these repositories is included in v0.1. MIT/Apache/BSD projects
may become optional adapters after a dependency review. GPL/AGPL components must
remain separate processes unless a deliberate licence decision says otherwise.
Mixed/source-available repositories require per-file or API-boundary review.

## Considered but rejected as the open-source code base

- `aliasrobotics/cai`: repository licence combines MIT-derived components with
  proprietary research-only additions and prohibits commercial/production use
  without another licence.
- `Security-Onion-Solutions/securityonion`: ELv2 is source-available and limits
  hosted/managed service use; useful architecture reference, not an open-source
  dependency claim.
- `TheHive-Project/TheHive`: the inspected repository is archived and describes
  the current distribution as commercial.
