# Threat-Informed SOC Lab

A professional, reproducible detection-engineering lab that connects harmless attack simulation, normalized telemetry, detections, MITRE ATT&CK, triage, incident response, validation, coverage, and gap analysis.

> **Safety:** “attacks” in this repository are inert, local Python event generators. They do not execute commands, authenticate, scan ports, create persistence, collect credentials, exploit vulnerabilities, or contact any external target.

## Overview

The MVP is intentionally small enough to understand and test end-to-end. It provides a typed JSONL telemetry contract and four validated detection paths. Future collectors (Zeek, Suricata, Sysmon, Wazuh, or a SIEM) can feed the same normalized model.

## Objectives

- Demonstrate threat-informed defense and detection engineering practice.
- Map telemetry and rules to MITRE ATT&CK.
- Validate coverage from actual detection output, not documentation claims.
- Practice analyst triage and lab-scoped incident response.

## Architecture

```text
Simulator → Telemetry → Parser → Detection Engine → Alert → MITRE ATT&CK
                                                        ↓
Coverage ← Retest ← Detection Gap ← Incident Response ← Triage
```

See [architecture/architecture.md](architecture/architecture.md) and the editable [Mermaid lifecycle diagram](architecture/diagrams/detection-lifecycle.mmd).

## Threat Model

The lab models behavior at the telemetry layer only: repeated SSH failures, multi-port connection attempts, an unusual successful login, and Unix shell metadata. Details and boundaries are in [docs/threat-model.md](docs/threat-model.md).

## MITRE ATT&CK Coverage

| Technique | Detection rule | Local validation |
|---|---|---|
| T1110 — Brute Force | `SSH-BRUTE-FORCE-001` | `brute-force` |
| T1046 — Network Service Discovery | `NETWORK-SERVICE-DISCOVERY-001` | `port-scan` |
| T1078 — Valid Accounts | `UNUSUAL-VALID-ACCOUNT-001` | `suspicious-login` |
| T1059.004 — Unix Shell | `UNIX-SHELL-EXECUTION-001` | `suspicious-process` |

`T1046` is correctly named **Network Service Discovery** per MITRE ATT&CK. Its scenario name retains `port-scan` only as a familiar shorthand for synthetic multi-port telemetry; it does not scan anything.

## Detection Engineering

The four [Sigma rules](detection/sigma/) document portable detection intent. The local evaluator implements the same logic with clear thresholds and structured JSON alerts. Read [docs/detection-engineering.md](docs/detection-engineering.md) for the engineering method.

## Attack Simulation

```bash
python -m soc_lab simulate all
python -m soc_lab detect
```

Simulation only writes `data/events.jsonl`. It includes `"source": "lab-simulator"` and `"simulation": true` on every event.

## Detection Validation

```bash
python -m soc_lab validate
```

This runs each scenario separately, verifies its expected rule, and writes measured results to `reports/coverage-report.md` and `mitre/coverage.json`. A technique is PASS only if its expected alert is observed.

## Incident Response

Runbooks in [incidents/](incidents/) cover detection, validation, triage, containment, eradication, recovery, and lessons learned. Actions are lab-scoped and require authorization.

## Detection Gaps

On failure, the coverage JSON records the technique, expected/missing telemetry, missing rule, recommended detection, remediation, and retest status. This turns a failed validation into an actionable engineering backlog.

## Results

Run validation locally to produce the result; no unverified PASS results are committed. The report shows a technique matrix and overall percentage derived from the executed checks.

## Screenshots

CLI output is designed to be screenshot-ready after `python -m soc_lab validate`. Add sanitized screenshots to `reports/examples/`; do not include sensitive logs or identities.

## Installation

Requires Python 3.10+.

```bash
git clone <your-repository-url>
cd threat-informed-soc-lab
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e '.[dev]'
```

## Usage

```bash
python -m soc_lab simulate brute-force
python -m soc_lab detect
python -m soc_lab validate
python -m soc_lab coverage
python -m soc_lab incident T1110
```

`docker compose run --rm soc-lab` is optional. The compose service drops Linux capabilities, uses a non-root user, and mounts only local data/report directories.

## Testing

```bash
pytest
ruff check .
mypy soc_lab parsers detection_engine
python -m soc_lab validate
```

## Roadmap

- [x] Safe local telemetry and end-to-end validation
- [x] ATT&CK mapping, Sigma intent, coverage and gap artifacts
- [x] Lab-scoped incident runbooks and CI
- [ ] Zeek and Suricata field adapters
- [ ] Sysmon/Windows adapter and SIEM dashboards
- [ ] Containerized optional sensors with documented lab topology

## Security

Read [SECURITY.md](SECURITY.md) before use or contribution. Never add real credentials, external targets, sensitive logs, or active offensive behavior.

## License

MIT — see [LICENSE](LICENSE).
