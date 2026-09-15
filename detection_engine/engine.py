from __future__ import annotations

import logging

from detection_engine.rules import RULES
from soc_lab.models import Alert, Event

LOGGER = logging.getLogger(__name__)


def detect(events: list[Event]) -> list[Alert]:
    """Evaluate only local event objects against deterministic lab rules."""
    alerts: list[Alert] = []
    for rule in RULES:
        produced = rule.detector(events)
        LOGGER.info("rule=%s alerts=%d", rule.rule_id, len(produced))
        alerts.extend(produced)
    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule))
