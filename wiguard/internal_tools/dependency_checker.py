"""WiGuard internal dependency checker.

Usage:
  python -m wiguard.internal_tools.dependency_checker
"""
from __future__ import annotations

import json
from pathlib import Path
from wiguard.services.professional_pipeline import health_report


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    report = health_report(root)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    missing = [d["name"] for d in report.get("required_dependencies", []) if not d.get("installed")]
    if missing:
        print("\nMissing required packages:", ", ".join(missing))
        print("Install with:", report.get("install_command"))
        return 1
    print("\nWiGuard required dependency stack is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
