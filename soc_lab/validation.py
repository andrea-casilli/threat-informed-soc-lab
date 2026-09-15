from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from detection_engine.engine import detect
from soc_lab.models import Alert
from soc_lab.simulator import generate


@dataclass(frozen=True)
class ValidationResult:
    technique: str
    scenario: str
    expected_rule: str
    result: str
    alert_count: int
    gap: dict[str, str] | None


VALIDATION_PLAN = {
    "T1110": ("brute-force", "SSH-BRUTE-FORCE-001", "SSH authentication failures"),
    "T1046": ("port-scan", "NETWORK-SERVICE-DISCOVERY-001", "network connection attempts"),
    "T1078": ("suspicious-login", "UNUSUAL-VALID-ACCOUNT-001", "successful unusual SSH login"),
    "T1059.004": ("suspicious-process", "UNIX-SHELL-EXECUTION-001", "process execution telemetry"),
}


def run_validation() -> tuple[list[ValidationResult], list[Alert]]:
    results: list[ValidationResult] = []
    all_alerts: list[Alert] = []
    for technique, (scenario, expected_rule, telemetry) in VALIDATION_PLAN.items():
        alerts = detect(generate([scenario]))
        expected = [alert for alert in alerts if alert.rule == expected_rule]
        all_alerts.extend(alerts)
        gap = None
        if not expected:
            gap = {
                "technique": technique,
                "expected_telemetry": telemetry,
                "missing_telemetry": "none observed by validation",
                "missing_rule": expected_rule,
                "recommended_detection": f"Implement and tune {expected_rule}",
                "remediation": "Collect the required local telemetry and add a tested rule.",
                "retest_status": "pending",
            }
        results.append(
            ValidationResult(
                technique,
                scenario,
                expected_rule,
                "PASS" if expected else "FAIL",
                len(expected),
                gap,
            )
        )
    return results, all_alerts


def coverage_payload(results: list[ValidationResult]) -> dict[str, object]:
    passed = sum(result.result == "PASS" for result in results)
    return {
        "overall_coverage_percent": round(passed / len(results) * 100, 2) if results else 0,
        "results": [asdict(result) for result in results],
        "gaps": [result.gap for result in results if result.gap is not None],
    }


def write_coverage(results: list[ValidationResult], reports_dir: Path, mitre_dir: Path) -> Path:
    payload = coverage_payload(results)
    reports_dir.mkdir(parents=True, exist_ok=True)
    mitre_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        "# Detection Validation Report",
        "",
        "| Technique | Validation test | Detection | Result | Coverage | Gap |",
        "|---|---|---|---|---:|---|",
    ]
    for result in results:
        gap = "none" if result.gap is None else result.gap["missing_rule"]
        coverage = "100%" if result.result == "PASS" else "0%"
        row = (
            f"| {result.technique} | {result.scenario} | {result.expected_rule} | "
            f"{result.result} | {coverage} | {gap} |"
        )
        rows.append(row)
    rows.extend(
        [
            "",
            f"**Overall Detection Coverage: {payload['overall_coverage_percent']}%**",
            "",
            "This report is generated from executed local simulations; a PASS requires the "
            "expected rule to emit an alert.",
        ]
    )
    report_path = reports_dir / "coverage-report.md"
    report_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    (mitre_dir / "coverage.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return report_path
