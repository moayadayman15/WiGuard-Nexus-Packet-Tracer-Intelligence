from datetime import datetime
import hashlib
import json
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


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
