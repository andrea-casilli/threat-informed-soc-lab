import json

from soc_lab.validation import run_validation, write_coverage


def test_detection_validation(tmp_path):
    results, alerts = run_validation()
    assert len(results) == 4
    assert len(alerts) == 4
    assert all(result.result == "PASS" for result in results)
    report = write_coverage(results, tmp_path / "reports", tmp_path / "mitre")
    assert "Overall Detection Coverage: 100.0%" in report.read_text(encoding="utf-8")
    payload = json.loads((tmp_path / "mitre" / "coverage.json").read_text(encoding="utf-8"))
    assert payload["gaps"] == []
