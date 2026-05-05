"""Remove generated Python/build artifacts without deleting source data.

Usage:
  python -m wiguard.internal_tools.project_cleaner
"""
from __future__ import annotations

import shutil
from pathlib import Path

JUNK_DIRS = {"__pycache__", ".pytest_cache", "build", "dist", ".mypy_cache", ".ruff_cache"}
JUNK_SUFFIXES = {".pyc", ".pyo"}


def clean(root: Path) -> list[str]:
    removed: list[str] = []
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir() and path.name in JUNK_DIRS:
            shutil.rmtree(path, ignore_errors=True)
            removed.append(str(path.relative_to(root)))
        elif path.is_file() and path.suffix in JUNK_SUFFIXES:
            path.unlink(missing_ok=True)
            removed.append(str(path.relative_to(root)))
    return removed


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    removed = clean(root)
    print(f"Removed {len(removed)} generated artifact(s).")
    for item in removed[:80]:
        print("-", item)
    if len(removed) > 80:
        print(f"... and {len(removed) - 80} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
