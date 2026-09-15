from __future__ import annotations

from detection_engine.scoring import score
from soc_lab.models import Alert


def render_triage(alert: Alert) -> str:
    evidence = "\n".join(
        f"- `{item['event_type']}` from `{item['src_ip']}`" for item in alert.evidence
    )
    return f"""# Triage: {alert.alert_id}

| Field | Value |
|---|---|
| Alert ID | {alert.alert_id} |
| Timestamp | {alert.timestamp} |
| Severity | {alert.severity} ({score(alert)}/100) |
| Source | {alert.source_ip} |
| Target | {alert.target} |
| MITRE Technique | {alert.technique} — {alert.technique_name} |
| Rule | {alert.rule} |

## Evidence
{evidence}

## Analysis
This is controlled `lab-simulator` telemetry. Validate the source, timeline, and rule
threshold before applying an operational response.

## False Positive Assessment
INCONCLUSIVE until the lab scenario and expected telemetry are confirmed.

## Recommended Action
Preserve the local events, review the matching incident runbook, and tune only after retesting.

## Final Disposition
INCONCLUSIVE
"""
