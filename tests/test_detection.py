from datetime import datetime, timezone

from detection_engine.engine import detect
from soc_lab.simulator import generate

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _rules(scenario: str) -> set[str]:
    return {alert.rule for alert in detect(generate([scenario], base=BASE))}


def test_bruteforce_detection():
    assert "SSH-BRUTE-FORCE-001" in _rules("brute-force")


def test_port_scan_detection():
    assert "NETWORK-SERVICE-DISCOVERY-001" in _rules("port-scan")


def test_valid_account_detection():
    assert "UNUSUAL-VALID-ACCOUNT-001" in _rules("suspicious-login")


def test_unix_shell_detection():
    assert "UNIX-SHELL-EXECUTION-001" in _rules("suspicious-process")
