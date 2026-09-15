from datetime import datetime, timezone

from parsers.auth_logs import parse as parse_auth
from parsers.firewall_logs import parse as parse_firewall
from soc_lab.io import write_events
from soc_lab.simulator import generate


def test_auth_parser_returns_only_authentication_events(tmp_path):
    path = tmp_path / "events.jsonl"
    write_events(path, generate(base=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    events = parse_auth(path)
    assert len(events) == 9
    assert all(event.event_type.startswith("authentication_") for event in events)


def test_firewall_parser_returns_network_events(tmp_path):
    path = tmp_path / "events.jsonl"
    write_events(path, generate())
    assert len(parse_firewall(path)) == 12
