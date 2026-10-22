"""Command-line interface; avoid echoing plan values in parse errors."""

import argparse
import json
import sys
from pathlib import Path

from .scanner import assess


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review an Azure Terraform JSON plan.")
    parser.add_argument("plan", type=Path, help="Path to terraform show -json output")
    parser.add_argument("--json", action="store_true", help="Print a JSON report")
    args = parser.parse_args(argv)
    try:
        contents = args.plan.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        print("Azure Guardrail: Cannot read plan as UTF-8. Check its path, permissions, and encoding.", file=sys.stderr)
        return 2
    try:
        plan = json.loads(contents)
    except (ValueError, RecursionError):
        print("Azure Guardrail: Plan must contain valid JSON.", file=sys.stderr)
        return 2
    try:
        report = assess(plan)
    except ValueError as error:
        print(f"Azure Guardrail: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for finding in report["findings"]:
            print(f"[{finding['severity'].upper()} / {finding['status']}] {finding['id']} "
                  f"{json.dumps(finding['resource'])}\n"
                  f"  {finding['title']}\n  Why: {finding['why']}\n"
                  f"  Suggestion: {finding['suggestion']}\n")
        s = report["summary"]
        print(f"Assessed {s['assessed_resources']} resources; skipped {s['skipped_resources']}; "
              f"{s['risk_findings']} risks; {s['review_findings']} need review.")
        print("Results cover only supported checks and resources present in this plan.")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
