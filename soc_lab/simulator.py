"""Generate inert synthetic events; this module never opens sockets or executes commands."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from soc_lab.models import Event

ScenarioFactory = Callable[[datetime], list[Event]]
LAB_HOST = "lab-linux"


def _time(base: datetime, offset_seconds: int) -> str:
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def brute_force(base: datetime) -> list[Event]:
    return [
        Event(
            _time(base, i * 20),
            "lab-simulator",
            "authentication_failure",
            "10.10.10.50",
            LAB_HOST,
            username="testuser",
            status="failed",
            fields={"service": "ssh", "scenario": "brute-force"},
        )
        for i in range(8)
    ]


def port_scan(base: datetime) -> list[Event]:
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]
    return [
        Event(
            _time(base, i * 3),
            "lab-simulator",
            "network_connection_attempt",
            "10.10.10.60",
            LAB_HOST,
            dst_port=port,
            fields={"protocol": "tcp", "scenario": "network-service-discovery"},
        )
        for i, port in enumerate(ports)
    ]


def suspicious_login(base: datetime) -> list[Event]:
    return [
        Event(
            _time(base, 0),
            "lab-simulator",
            "authentication_success",
            "10.10.10.70",
            LAB_HOST,
            username="testuser",
            status="success",
            fields={"service": "ssh", "unusual_login": True, "scenario": "valid-accounts"},
        )
    ]


def suspicious_process(base: datetime) -> list[Event]:
    return [
        Event(
            _time(base, 0),
            "lab-simulator",
            "process_execution",
            "127.0.0.1",
            LAB_HOST,
            command="sh -c 'echo LAB_SIMULATION'",
            fields={"shell": "sh", "parent_process": "lab-simulator", "scenario": "unix-shell"},
        )
    ]


SCENARIOS: dict[str, ScenarioFactory] = {
    "brute-force": brute_force,
    "port-scan": port_scan,
    "suspicious-login": suspicious_login,
    "suspicious-process": suspicious_process,
}


def generate(names: list[str] | None = None, base: datetime | None = None) -> list[Event]:
    selected = names or list(SCENARIOS)
    unknown = set(selected).difference(SCENARIOS)
    if unknown:
        raise ValueError(f"Unknown simulation scenario(s): {', '.join(sorted(unknown))}")
    started = base or datetime.now(timezone.utc).replace(microsecond=0)
    return [event for name in selected for event in SCENARIOS[name](started)]
