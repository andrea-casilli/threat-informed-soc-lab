from __future__ import annotations

import json
from pathlib import Path

from soc_lab.models import Event


def write_events(path: Path, events: list[Event]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(event.to_dict(), sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def read_events(path: Path) -> list[Event]:
    if not path.exists():
        raise FileNotFoundError(f"Event file does not exist: {path}")
    events: list[Event] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(Event.from_dict(json.loads(line)))
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"Invalid JSON event at {path}:{number}") from exc
    return events
