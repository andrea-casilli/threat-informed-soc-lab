from __future__ import annotations

from soc_lab.models import Alert

SEVERITY_SCORES = {"low": 25, "medium": 50, "high": 75, "critical": 100}


def score(alert: Alert) -> int:
    """Return a stable triage priority score; it is not a risk score."""
    return SEVERITY_SCORES[alert.severity]
