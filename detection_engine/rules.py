from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_lab.models import Alert, Event

Detector = Callable[[list[Event]], list[Alert]]


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    technique: str
    technique_name: str
    severity: str
    detector: Detector


def _parse_time(event: Event) -> datetime:
    return datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))


def ssh_brute_force(events: list[Event]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == "authentication_failure" and event.status == "failed":
            grouped[(event.src_ip, event.dst_host)].append(event)
    alerts: list[Alert] = []
    window = timedelta(minutes=5)
    for (source, target), matches in grouped.items():
        ordered = sorted(matches, key=_parse_time)
        for index, event in enumerate(ordered):
            in_window = [
                candidate
                for candidate in ordered[index:]
                if _parse_time(candidate) - _parse_time(event) <= window
            ]
            if len(in_window) >= 5:
                alerts.append(
                    Alert(
                        "medium",
                        "T1110",
                        "Brute Force",
                        "SSH-BRUTE-FORCE-001",
                        event.timestamp,
                        source,
                        target,
                        len(in_window),
                        [item.to_dict() for item in in_window],
                    )
                )
                break
    return alerts


def network_service_discovery(events: list[Event]) -> list[Alert]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type == "network_connection_attempt" and event.dst_port is not None:
            grouped[(event.src_ip, event.dst_host)].append(event)
    alerts: list[Alert] = []
    for (source, target), matches in grouped.items():
        ports = {event.dst_port for event in matches}
        if len(ports) >= 10:
            first = min(matches, key=_parse_time)
            alerts.append(
                Alert(
                    "medium",
                    "T1046",
                    "Network Service Discovery",
                    "NETWORK-SERVICE-DISCOVERY-001",
                    first.timestamp,
                    source,
                    target,
                    len(matches),
                    [item.to_dict() for item in matches],
                )
            )
    return alerts


def valid_accounts(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if (
            event.event_type == "authentication_success"
            and event.fields.get("unusual_login") is True
        ):
            alerts.append(
                Alert(
                    "high",
                    "T1078",
                    "Valid Accounts",
                    "UNUSUAL-VALID-ACCOUNT-001",
                    event.timestamp,
                    event.src_ip,
                    event.dst_host,
                    1,
                    [event.to_dict()],
                )
            )
    return alerts


def unix_shell(events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        if event.event_type == "process_execution" and event.fields.get("shell") in {
            "sh",
            "bash",
            "zsh",
        }:
            alerts.append(
                Alert(
                    "low",
                    "T1059.004",
                    "Unix Shell",
                    "UNIX-SHELL-EXECUTION-001",
                    event.timestamp,
                    event.src_ip,
                    event.dst_host,
                    1,
                    [event.to_dict()],
                )
            )
    return alerts


RULES = [
    DetectionRule("SSH-BRUTE-FORCE-001", "T1110", "Brute Force", "medium", ssh_brute_force),
    DetectionRule(
        "NETWORK-SERVICE-DISCOVERY-001",
        "T1046",
        "Network Service Discovery",
        "medium",
        network_service_discovery,
    ),
    DetectionRule("UNUSUAL-VALID-ACCOUNT-001", "T1078", "Valid Accounts", "high", valid_accounts),
    DetectionRule("UNIX-SHELL-EXECUTION-001", "T1059.004", "Unix Shell", "low", unix_shell),
]
