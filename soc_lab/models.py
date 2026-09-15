from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class Event:
    timestamp: str
    source: str
    event_type: str
    src_ip: str
    dst_host: str
    simulation: bool = True
    username: str | None = None
    status: str | None = None
    dst_port: int | None = None
    command: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(data.pop("fields"))
        return {key: value for key, value in data.items() if value is not None}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        known = {
            "timestamp",
            "source",
            "event_type",
            "src_ip",
            "dst_host",
            "simulation",
            "username",
            "status",
            "dst_port",
            "command",
        }
        return cls(
            timestamp=str(raw["timestamp"]),
            source=str(raw["source"]),
            event_type=str(raw["event_type"]),
            src_ip=str(raw["src_ip"]),
            dst_host=str(raw["dst_host"]),
            simulation=bool(raw.get("simulation", False)),
            username=raw.get("username"),
            status=raw.get("status"),
            dst_port=raw.get("dst_port"),
            command=raw.get("command"),
            fields={k: v for k, v in raw.items() if k not in known},
        )


@dataclass(frozen=True)
class Alert:
    severity: str
    technique: str
    technique_name: str
    rule: str
    timestamp: str
    source_ip: str
    target: str
    event_count: int
    evidence: list[dict[str, Any]]
    alert_id: str = field(default_factory=lambda: f"LAB-{uuid4().hex[:12].upper()}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
