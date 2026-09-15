from pathlib import Path

import yaml


def test_mitre_mapping_is_complete_and_uses_expected_ids():
    mapping = yaml.safe_load(Path("mitre/attack-mapping.yaml").read_text(encoding="utf-8"))
    techniques = mapping["techniques"]
    ids = {item["id"] for item in techniques}
    assert ids == {"T1110", "T1046", "T1078", "T1059.004"}
    assert all(item["telemetry"] and item["detection"] and item["test"] for item in techniques)
