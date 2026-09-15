from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from detection_engine.engine import detect
from soc_lab.io import read_events, write_events
from soc_lab.simulator import SCENARIOS, generate
from soc_lab.validation import run_validation, write_coverage

# Artifacts belong to the operator's current lab workspace, never site-packages.
WORKSPACE = Path.cwd()
DEFAULT_EVENTS = WORKSPACE / "data" / "events.jsonl"


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe local threat-informed SOC lab")
    parser.add_argument("--log-level", default="WARNING")
    subparsers = parser.add_subparsers(dest="command", required=True)
    simulate = subparsers.add_parser("simulate", help="write inert synthetic events")
    simulate.add_argument("scenario", choices=[*SCENARIOS, "all"])
    simulate.add_argument("--output", type=Path, default=DEFAULT_EVENTS)
    detect_command = subparsers.add_parser("detect", help="evaluate local events")
    detect_command.add_argument("--input", type=Path, default=DEFAULT_EVENTS)
    subparsers.add_parser(
        "validate", help="execute each simulation and verify its expected detection"
    )
    subparsers.add_parser("coverage", help="run validation and write coverage artifacts")
    incident = subparsers.add_parser("incident", help="print a static lab incident runbook")
    incident.add_argument("technique", choices=["T1110", "T1046", "T1078", "T1059.004"])
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING))

    if args.command == "simulate":
        names = None if args.scenario == "all" else [args.scenario]
        events = generate(names)
        write_events(args.output, events)
        print(f"Wrote {len(events)} simulated events to {args.output}")
    elif args.command == "detect":
        alerts = detect(read_events(args.input))
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2))
        print(f"{len(alerts)} alert(s) generated")
    elif args.command in {"validate", "coverage"}:
        results, _ = run_validation()
        report = write_coverage(results, WORKSPACE / "reports", WORKSPACE / "mitre")
        for result in results:
            print(f"{result.technique:<9} {result.result}  {result.expected_rule}")
        print(f"Coverage report: {report}")
    elif args.command == "incident":
        matches = list((WORKSPACE / "incidents").glob(f"{args.technique}-*.md"))
        if not matches:
            raise FileNotFoundError(f"No incident runbook for {args.technique}")
        print(matches[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
