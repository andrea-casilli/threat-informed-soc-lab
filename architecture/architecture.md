# Architecture

The MVP deliberately has no listener, scanner, packet capture, privilege requirement, or remote target. `soc_lab.simulator` creates normalized JSONL events in the local filesystem; the same event contract can later be supplied by Linux, Zeek, Suricata, Windows Sysmon, or a SIEM collector.

| Component | Responsibility | Trust boundary |
|---|---|---|
| Simulator | Writes explicitly simulated local telemetry | Lab process only |
| Parsers | Reads and validates JSONL into typed events | Local files only |
| Detection engine | Applies deterministic rules | No side effects |
| Validation | Confirms expected alert per scenario | No synthetic PASS values |
| Triage / runbooks | Documents analyst response | Documentation only |

Future adapters must normalize their input to the event schema and preserve source provenance.
