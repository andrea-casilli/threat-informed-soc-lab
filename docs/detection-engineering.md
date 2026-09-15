# Detection Engineering

Each rule starts with a documented telemetry hypothesis, an ATT&CK technique, a threshold or condition, expected false positives, and an executable validation case. Sigma rules under `detection/sigma/` document portable intent; `detection_engine/rules.py` is the MVP evaluator for the normalized local schema.

Rules are intentionally small and transparent. A validation failure creates a structured gap record rather than changing coverage to PASS.
