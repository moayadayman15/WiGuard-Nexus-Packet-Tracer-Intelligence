"""Preflight checker for demo/release readiness.

Usage:
  python -m wiguard.internal_tools.preflight_check
"""
from __future__ import annotations

import json
from pathlib import Path
from wiguard.services.professional_pipeline import health_report


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    report = health_report(root)
    blockers = []
    for dep in report.get("required_dependencies", []):
        if not dep.get("installed"):
            blockers.append(f"missing dependency: {dep['name']}")
    for row in report.get("directories", []):
        if row["path"] in {"data", "wiguard"} and not row.get("exists"):
            blockers.append(f"missing required directory: {row['path']}")
    print(json.dumps({"ok": not blockers, "blockers": blockers, "health": report}, indent=2, ensure_ascii=False))
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
