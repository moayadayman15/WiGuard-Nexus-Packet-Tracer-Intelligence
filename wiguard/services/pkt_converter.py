"""External Packet Tracer converter integration.

WiGuard cannot depend on one specific third-party `.pkt/.pka -> XML` tool, so
this module supports a small set of safe adapter patterns:

- WIGUARD_PKT_CONVERTER_PATH or legacy PTEXPLORER_PATH / PKT2XML_PATH
- optional WIGUARD_PKT_CONVERTER_ARGS template using {input}, {output}, {output_dir}
- stdout XML/JSON output
- XML files written to the requested output path or output directory

The importer records every attempt so the UI can show whether data came from a
real converter, a companion export, or internal best-effort recovery.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree as ET

MAX_CONVERTER_OUTPUT_BYTES = 6 * 1024 * 1024
DEFAULT_TIMEOUT = 60

CONVERTER_ENV_NAMES = (
    "WIGUARD_PKT_CONVERTER_PATH",
    "PACKET_TRACER_CONVERTER_PATH",
    "PTEXPLORER_PATH",
    "PKT2XML_PATH",
    "CPT_XML_CONVERTER_PATH",
)


def _safe_read_text(path: Path, max_bytes: int = MAX_CONVERTER_OUTPUT_BYTES) -> str:
    raw = path.read_bytes()[:max_bytes]
    return raw.decode("utf-8", errors="replace")


def _looks_like_xml(text: str) -> bool:
    sample = (text or "").lstrip("\ufeff\x00\r\n\t ")[:2000]
    if not sample:
        return False
    if sample.startswith("<?xml") or sample.startswith("<"):
        try:
            ET.fromstring(text.strip())
            return True
        except Exception:
            # Some converters print banners before/after XML. Try to recover a body.
            return bool(re.search(r"<[^!?][A-Za-z0-9_:\-\.]+[\s>/]", sample))
    return False


def _looks_like_json(text: str) -> bool:
    sample = (text or "").strip()
    if not sample or sample[0] not in "[{":
        return False
    try:
        json.loads(sample)
        return True
    except Exception:
        return False


def _extract_xml_fragment(text: str) -> str:
    """Recover an XML document when a CLI prints banners around it."""
    value = (text or "").strip()
    if not value:
        return ""
    if _looks_like_xml(value):
        first = value.find("<")
        return value[first:] if first >= 0 else value
    start = value.find("<?xml")
    if start < 0:
        start = value.find("<")
    if start >= 0:
        candidate = value[start:]
        if _looks_like_xml(candidate):
            return candidate
    return ""


def _payload_from_text(name: str, source: str, text: str, command: List[str] | None = None) -> Dict[str, Any] | None:
    text = text or ""
    if not text.strip():
        return None
    xml_text = _extract_xml_fragment(text)
    if xml_text:
        content = xml_text[:MAX_CONVERTER_OUTPUT_BYTES]
        return {
            "name": name,
            "kind": "xml",
            "source": source,
            "bytes": len(content.encode("utf-8", errors="replace")),
            "sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
            "preview": content[:1200],
            "content": content,
            "command": command or [],
        }
    if _looks_like_json(text):
        content = text[:MAX_CONVERTER_OUTPUT_BYTES]
        return {
            "name": name,
            "kind": "json",
            "source": source,
            "bytes": len(content.encode("utf-8", errors="replace")),
            "sha256": hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
            "preview": content[:1200],
            "content": content,
            "command": command or [],
        }
    return None


def _converter_path() -> Tuple[str | None, str | None]:
    for env_name in CONVERTER_ENV_NAMES:
        value = os.environ.get(env_name)
        if value:
            return value, env_name
    return None, None


def _auto_discover_converter(input_path: Path, output_dir: Path) -> Tuple[str | None, str | None, List[str]]:
    """Find a local PKT→XML converter placed beside the project/upload folder.

    This keeps WiGuard self-contained for demos: if the team drops ptexplorer.py,
    pka2xml.py, pkt2xml.py, or a converter executable in the project root, tools/,
    converters/, or the upload folder, the backend will try it without requiring
    environment variables. No network download is performed.
    """
    names = [
        "ptexplorer.py", "pka2xml.py", "pkt2xml.py", "cpt2xml.py",
        "ptexplorer", "pka2xml", "pkt2xml", "cpt2xml",
        "ptexplorer.exe", "pka2xml.exe", "pkt2xml.exe",
    ]
    roots: List[Path] = []
    for base in [Path.cwd(), output_dir, input_path.parent]:
        try:
            base = Path(base).resolve()
        except Exception:
            continue
        for candidate_root in [base, base / "tools", base / "tools" / "packet_tracer", base / "converters", base / "vendor", base.parent]:
            if candidate_root not in roots:
                roots.append(candidate_root)
    checked: List[str] = []
    for root in roots:
        for name in names:
            candidate = root / name
            checked.append(str(candidate))
            try:
                if candidate.exists() and candidate.is_file():
                    return str(candidate), "auto_discovered", checked[:30]
            except Exception:
                continue
    return None, None, checked[:30]


def _is_safe_converter(path_value: str) -> Tuple[bool, str]:
    try:
        path = Path(path_value).expanduser()
        if not path.exists():
            return False, "converter path does not exist"
        if path.is_dir():
            return False, "converter path is a directory"
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def _command_prefix(tool: str) -> List[str]:
    path = Path(tool).expanduser()
    # On Windows/Linux a .py converter may not be executable. Run it through the
    # current interpreter so ptexplorer.py/pka2xml.py work reliably.
    if path.suffix.lower() == ".py":
        py_args = shlex.split(os.environ.get("WIGUARD_PKT_CONVERTER_PYTHON_ARGS", "-S"))
        return [sys.executable] + py_args + [str(path)]
    return [str(path)]


def _build_commands(tool: str, input_path: Path, output_xml: Path, output_dir: Path) -> List[List[str]]:
    template = os.environ.get("WIGUARD_PKT_CONVERTER_ARGS") or os.environ.get("PKT_CONVERTER_ARGS")
    prefix = _command_prefix(tool)
    if template:
        rendered = template.format(input=str(input_path), output=str(output_xml), output_dir=str(output_dir))
        return [prefix + shlex.split(rendered)]
    # Cover common converter CLIs. ptexplorer/pka2xml use the important
    # decode-style form: `tool -d input.pkt output.xml`. Older code missed this,
    # so correctly installed converters often produced no XML.
    shapes = [
        [str(input_path), str(output_xml)],
        ["-d", str(input_path), str(output_xml)],
        ["--decode", str(input_path), str(output_xml)],
        ["--input", str(input_path), "--output", str(output_xml)],
        ["-i", str(input_path), "-o", str(output_xml)],
        ["convert", str(input_path), str(output_xml)],
        ["export", str(input_path), str(output_xml)],
        [str(input_path)],  # tools that emit XML/JSON to stdout
    ]
    commands: List[List[str]] = []
    seen = set()
    for shape in shapes:
        command = prefix + shape
        marker = tuple(command)
        if marker not in seen:
            commands.append(command)
            seen.add(marker)
    return commands


def _discover_outputs(output_dir: Path, since: float, stem: str) -> List[Path]:
    candidates: List[Path] = []
    for pattern in ("*.xml", "*.json"):
        for path in output_dir.glob(pattern):
            try:
                if path.stat().st_mtime >= since - 1 and path.stat().st_size > 0:
                    candidates.append(path)
            except Exception:
                continue
    # Prefer files that look related to this upload or explicit converter outputs.
    def score(path: Path) -> Tuple[int, int]:
        name = path.name.lower()
        related = 2 if stem.lower() in name else 1 if "convert" in name or "packet" in name or "pkt" in name else 0
        try:
            size = path.stat().st_size
        except Exception:
            size = 0
        return related, size
    return sorted(set(candidates), key=score, reverse=True)[:8]


def run_external_pkt_converters(input_path: Path, output_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run configured converter adapters and return attempts + decoded outputs.

    No converter is bundled or downloaded. Admins wire an existing local converter
    through environment variables, keeping this feature safe and auditable.
    """
    attempts: List[Dict[str, Any]] = []
    payloads: List[Dict[str, Any]] = []
    converter, env_name = _converter_path()
    discovery_checked: List[str] = []
    if not converter:
        converter, env_name, discovery_checked = _auto_discover_converter(Path(input_path), Path(output_dir))
    if not converter:
        attempts.append({
            "tool": "external_converter",
            "status": "not_configured",
            "env_checked": list(CONVERTER_ENV_NAMES),
            "auto_discovery_checked": discovery_checked,
            "detail": "Set WIGUARD_PKT_CONVERTER_PATH/PTEXPLORER_PATH or place ptexplorer.py/pka2xml.py in the project root, tools/, converters/, or upload directory to enable real .pkt/.pka → XML conversion.",
        })
        return attempts, payloads

    ok, reason = _is_safe_converter(converter)
    if not ok:
        attempts.append({
            "tool": "external_converter",
            "status": "configuration_error",
            "path": converter,
            "env": env_name,
            "detail": reason,
        })
        return attempts, payloads

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_xml = output_dir / f"{Path(input_path).stem}_external_converter.xml"
    commands = _build_commands(str(Path(converter).expanduser()), Path(input_path), output_xml, output_dir)
    timeout = int(os.environ.get("WIGUARD_PKT_CONVERTER_TIMEOUT", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
    seen_hashes = set()
    start_time = time.time()

    for index, command in enumerate(commands, start=1):
        attempt = {
            "tool": "external_converter",
            "env": env_name,
            "path": converter,
            "adapter": "custom_args" if os.environ.get("WIGUARD_PKT_CONVERTER_ARGS") or os.environ.get("PKT_CONVERTER_ARGS") else f"adapter_{index}",
            "command_shape": [Path(command[0]).name] + ["<input/output>" if str(input_path) in arg or str(output_xml) in arg or str(output_dir) in arg else arg for arg in command[1:]],
        }
        try:
            before = time.time()
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, cwd=str(output_dir))
            attempt.update({
                "returncode": result.returncode,
                "status": "success" if result.returncode == 0 else "failed",
                "duration_ms": int((time.time() - before) * 1000),
                "stdout_preview": (result.stdout or "")[:600],
                "stderr_preview": (result.stderr or "")[:600],
            })
            # stdout payload path.
            payload = _payload_from_text("converter_stdout", "external_converter_stdout", result.stdout or "", command)
            if payload and payload["sha256"] not in seen_hashes:
                payloads.append(payload)
                seen_hashes.add(payload["sha256"])
                attempt["stdout_payload"] = payload["kind"]
            # output files written by converter.
            paths = []
            if output_xml.exists():
                paths.append(output_xml)
            paths.extend(_discover_outputs(output_dir, start_time, Path(input_path).stem))
            for path in paths:
                try:
                    text = _safe_read_text(path)
                except Exception as exc:
                    attempt.setdefault("output_errors", []).append({"path": str(path), "error": str(exc)[:300]})
                    continue
                payload = _payload_from_text(path.name, "external_converter_file", text, command)
                if payload and payload["sha256"] not in seen_hashes:
                    payload["path"] = str(path)
                    payloads.append(payload)
                    seen_hashes.add(payload["sha256"])
            if payloads:
                attempt["status"] = "success"
                attempt["outputs"] = len(payloads)
                attempts.append(attempt)
                break
            attempts.append(attempt)
        except subprocess.TimeoutExpired as exc:
            attempt.update({"status": "timeout", "timeout_seconds": timeout, "stderr_preview": str(exc)[:600]})
            attempts.append(attempt)
        except Exception as exc:
            attempt.update({"status": "failed", "error": str(exc)[:600]})
            attempts.append(attempt)

    if not payloads and attempts:
        attempts.append({
            "tool": "external_converter",
            "status": "no_xml_or_json_output",
            "detail": "Converter ran/configured but no parseable XML/JSON was found in stdout or output files.",
        })
    return attempts, payloads
