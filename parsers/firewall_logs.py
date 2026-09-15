from pathlib import Path

from soc_lab.io import read_events
from soc_lab.models import Event


def parse(path: Path) -> list[Event]:
    return [
        event for event in read_events(path) if event.event_type == "network_connection_attempt"
    ]
