from pathlib import Path

FALLBACK_VERSION = "5.16.1-professional-hardening"


def get_version() -> str:
    """Read the release version from the root VERSION file.

    A single version source prevents the UI, README, runtime state, and package
    metadata from drifting apart across rapid builds.
    """
    try:
        root = Path(__file__).resolve().parent.parent
        value = (root / "VERSION").read_text(encoding="utf-8").strip()
        return value or FALLBACK_VERSION
    except Exception:
        return FALLBACK_VERSION


def get_product_label() -> str:
    return f"WiGuard Nexus v{get_version()}"
