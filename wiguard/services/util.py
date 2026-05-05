from datetime import datetime, timezone
import hashlib
import json
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def mask_to_prefix(mask):
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen)
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        logger.debug("Could not convert mask to prefix: %s", exc)
        return None


def network_cidr(ip, mask):
    try:
        return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        logger.debug("Could not derive network CIDR: %s", exc)
        return None


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        logger.debug("Could not convert value to int: %s", exc)
        return default


def short_text(value, limit=300):
    """Return a safe single-line preview for logs/UI snippets."""
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def log_safely(logger_obj, level, message, *args):
    """Log without letting logging misconfiguration break request handling."""
    try:
        getattr(logger_obj, level)(message, *args)
    except Exception:
        # Last-resort safety: callers use this inside exception paths.
        return None


def clamp_percent(value, *, already_percent=False):
    """Normalize a 0..1 or 0..100 score into an integer percent."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if not already_percent and number <= 1:
        number *= 100
    return max(0, min(100, int(round(number))))

def friendly_error(exc, fallback="The request could not be completed. Please check the input and try again."):
    """Return a short user-safe error message without paths, secrets, or tracebacks.

    Detailed exceptions still belong in server logs. Flash messages and JSON
    responses should stay friendly, especially for uploads and admin actions.
    """
    text = short_text(exc, 220)
    if not text:
        return fallback
    lowered = text.lower()
    sensitive_markers = (
        "traceback", "secret", "token", "password", "api_key", "apikey",
        "database_url", "wiguard_secret_key", "no such file or directory",
    )
    looks_like_path = ("/" in text or "\\" in text) and (".py" in lowered or ":\\" in text or text.startswith("/"))
    if looks_like_path or any(marker in lowered for marker in sensitive_markers):
        return fallback
    return text
