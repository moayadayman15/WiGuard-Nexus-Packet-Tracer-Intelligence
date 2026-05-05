"""Professional data-import, normalization, risk, health, and reporting layer.

This module is intentionally additive. It does not replace the historical
WiGuard extractors; it gives the UI and reports a stable normalized contract that
can be built from existing extracted objects, raw JSON/XML/CSV/text payloads, or
future parsers.
"""
from __future__ import annotations

import csv
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
import platform
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:  # safer XML parsing is required for untrusted imports
    from defusedxml import ElementTree as SafeET
except Exception:  # pragma: no cover - fallback for minimal installs
    SafeET = None  # type: ignore

try:
    from jinja2 import Environment
except Exception:  # pragma: no cover - HTML report has stdlib fallback
    Environment = None  # type: ignore


SEVERITY_WEIGHTS = {"Critical": 100, "High": 82, "Medium": 58, "Low": 30, "Info": 12}
SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key|enable secret|community)\b\s*[:= ]+\s*([^\s,;\"']{4,})"
)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b")
VLAN_RE = re.compile(r"(?i)\bvlan\s+(\d{1,4})\b")
INTERFACE_RE = re.compile(r"(?i)^\s*interface\s+([A-Za-z][\w./:-]+)", re.MULTILINE)
HOSTNAME_RE = re.compile(r"(?i)^\s*hostname\s+([A-Za-z0-9_.-]{1,80})", re.MULTILINE)
SSID_RE = re.compile(r"(?i)\bssid\s+([\w .:@-]{2,64})")
MGMT_PORTS = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt"}


@dataclass
class NormalizedEvidence:
    source_file: str = ""
    source_type: str = "parsed"
    source_line: Optional[int] = None
    source_path: str = ""
    source_text: str = ""
    confidence: float = 0.70


@dataclass
class NormalizedEntity:
    id: str
    type: str
    name: str
    source_file: str = ""
    confidence: float = 0.70
    evidence: NormalizedEvidence = field(default_factory=NormalizedEvidence)
    raw_reference: str = ""
    normalized_fields: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass
class NormalizedFinding:
    id: str
    title: str
    severity: str
    confidence: float
    affected_asset: str
    evidence: str
    why_it_matters: str
    recommendation: str
    source_reference: str = ""
    category: str = "Configuration"


@dataclass
class AnalysisResult:
    summary: Dict[str, Any]
    extracted_assets: Dict[str, List[Dict[str, Any]]]
    topology: Dict[str, Any]
    findings: List[Dict[str, Any]]
    risk_score: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    recommended_actions: List[str]
    export_ready: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)


class ImportValidationError(ValueError):
    """Friendly validation error raised before unsafe/unsupported parsing."""


class ParserError(ValueError):
    """Friendly parser error that should be shown without tracebacks in the UI."""


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(p) for p in parts if p is not None)
    digest = hashlib.sha1(material.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _safe_str(value: Any, max_len: int = 240) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:max_len]


def redact_secret(value: Any) -> str:
    text = _safe_str(value, 400)
    if not text:
        return ""
    return SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(row: Mapping[str, Any], keys: Sequence[str], default: Any = "") -> Any:
    for key in keys:
        if key in row and row.get(key) not in (None, ""):
            return row.get(key)
    return default


class DataImportValidator:
    """Pre-parse validation used by internal tools and future UI validation."""

    DEFAULT_EXTENSIONS = {
        ".json", ".xml", ".csv", ".txt", ".log", ".cfg", ".conf", ".config", ".ios", ".nxos", ".zip", ".pkt", ".pka"
    }

    def __init__(self, max_bytes: int = 20 * 1024 * 1024, allowed_extensions: Optional[Iterable[str]] = None):
        self.max_bytes = int(max_bytes)
        self.allowed_extensions = {e.lower() for e in (allowed_extensions or self.DEFAULT_EXTENSIONS)}

    def validate_path(self, path: Path) -> Dict[str, Any]:
        path = Path(path)
        if not path.exists():
            raise ImportValidationError(f"Missing file: {path.name or 'selected file'}")
        if not path.is_file():
            raise ImportValidationError(f"Selected path is not a file: {path.name or 'selected path'}")
        size = path.stat().st_size
        if size <= 0:
            raise ImportValidationError("File is empty. Export or select evidence with content.")
        if size > self.max_bytes:
            raise ImportValidationError(f"File is too large ({size} bytes). Limit is {self.max_bytes} bytes.")
        ext = path.suffix.lower()
        if ext not in self.allowed_extensions:
            raise ImportValidationError(f"Unsupported file extension '{ext or 'none'}'.")
        return {
            "ok": True,
            "filename": path.name,
            "extension": ext,
            "bytes": size,
            "format_hint": self.detect_format(path),
            "warnings": ["Native .pkt/.pka parsing is best-effort; prefer exported TXT/XML/JSON evidence."] if ext in {".pkt", ".pka"} else [],
        }

    def detect_format(self, path: Path) -> str:
        ext = path.suffix.lower()
        if ext == ".json":
            return "json"
        if ext == ".xml":
            return "xml"
        if ext == ".csv":
            return "csv"
        if ext in {".pkt", ".pka"}:
            return "packet_tracer_native"
        if ext == ".zip":
            return "zip_bundle"
        sample = path.read_bytes()[:2048]
        text = sample.decode("utf-8", errors="ignore").lstrip()
        if text.startswith("{") or text.startswith("["):
            return "json"
        if text.startswith("<"):
            return "xml"
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if "," in first_line:
            return "csv"
        return "text_config"


class BaseParser:
    name = "base"
    extensions: Tuple[str, ...] = ()

    def can_parse(self, file_path: Path) -> bool:
        return Path(file_path).suffix.lower() in self.extensions

    def parse(self, file_path: Path) -> Dict[str, Any]:
        raise NotImplementedError

    def validate(self, raw_data: Any) -> List[str]:
        return []

    def extract_entities(self, raw_data: Any, source_file: str) -> List[NormalizedEntity]:
        return []

    def normalize(self, entities: List[NormalizedEntity]) -> List[Dict[str, Any]]:
        return [asdict(e) for e in entities]


class JsonParser(BaseParser):
    name = "json"
    extensions = (".json",)

    def parse(self, file_path: Path) -> Dict[str, Any]:
        try:
            payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            payload = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid JSON near line {exc.lineno}: {exc.msg}") from exc
        entities = SchemaNormalizer().entities_from_payload(payload, Path(file_path).name, "json")
        return {"parser": self.name, "raw_type": type(payload).__name__, "entities": self.normalize(entities), "raw": payload}


class XmlParser(BaseParser):
    name = "xml"
    extensions = (".xml",)

    def parse(self, file_path: Path) -> Dict[str, Any]:
        if SafeET is None:
            raise ParserError("defusedxml is required for safe XML parsing.")
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        try:
            root = SafeET.fromstring(text)
        except Exception as exc:
            raise ParserError(f"Invalid or unsafe XML: {exc}") from exc
        payload = _xml_to_dict(root)
        entities = SchemaNormalizer().entities_from_payload(payload, Path(file_path).name, "xml")
        return {"parser": self.name, "raw_type": "xml", "root": root.tag, "entities": self.normalize(entities), "raw": payload}


class CsvParser(BaseParser):
    name = "csv"
    extensions = (".csv",)

    def parse(self, file_path: Path) -> Dict[str, Any]:
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        try:
            rows = list(csv.DictReader(text.splitlines()))
        except csv.Error as exc:
            raise ParserError(f"Invalid CSV: {exc}") from exc
        entities = SchemaNormalizer().entities_from_rows(rows, Path(file_path).name)
        return {"parser": self.name, "raw_type": "csv", "rows": len(rows), "entities": self.normalize(entities), "raw": rows}


class TextConfigParser(BaseParser):
    name = "text_config"
    extensions = (".txt", ".log", ".cfg", ".conf", ".config", ".ios", ".nxos")

    def can_parse(self, file_path: Path) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self.extensions or not ext

    def parse(self, file_path: Path) -> Dict[str, Any]:
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        entities = SchemaNormalizer().entities_from_text(text, Path(file_path).name)
        return {"parser": self.name, "raw_type": "text", "entities": self.normalize(entities), "raw": {"preview": redact_secret(text[:4000])}}


class ZipBundleParser(BaseParser):
    name = "zip_bundle"
    extensions = (".zip",)
    allowed_member_extensions = {".json", ".xml", ".csv", ".txt", ".log", ".cfg", ".conf", ".config", ".ios", ".nxos", ".pkt", ".pka"}
    max_members = 100
    max_member_bytes = 2 * 1024 * 1024
    max_total_bytes = 8 * 1024 * 1024

    def parse(self, file_path: Path) -> Dict[str, Any]:
        file_path = Path(file_path)
        if not zipfile.is_zipfile(file_path):
            raise ParserError("Invalid ZIP bundle. Upload a valid .zip containing exported TXT/XML/JSON/CSV evidence.")

        entities: List[NormalizedEntity] = []
        warnings: List[str] = []
        manifest: List[Dict[str, Any]] = []
        total = 0
        normalizer = SchemaNormalizer()

        with zipfile.ZipFile(file_path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            if len(infos) > self.max_members:
                warnings.append(f"ZIP contains {len(infos)} files; only the first {self.max_members} safe members were reviewed.")
            for info in infos[: self.max_members]:
                member = info.filename.replace("\\", "/")
                member_path = Path(member)
                if member.startswith("/") or ".." in member_path.parts:
                    warnings.append(f"Skipped unsafe ZIP member path: {member}")
                    continue
                ext = member_path.suffix.lower()
                if ext not in self.allowed_member_extensions:
                    warnings.append(f"Skipped unsupported ZIP member: {member}")
                    continue
                if info.file_size > self.max_member_bytes:
                    warnings.append(f"Skipped oversized ZIP member: {member}")
                    continue
                if total + info.file_size > self.max_total_bytes:
                    warnings.append("Stopped reading ZIP after safe total-size limit was reached.")
                    break
                total += info.file_size
                raw = archive.read(info)
                source = f"{file_path.name}:{member}"
                manifest.append({"name": member, "bytes": info.file_size, "extension": ext})
                try:
                    text = raw.decode("utf-8-sig", errors="replace")
                    if ext == ".json":
                        payload = json.loads(text)
                        entities.extend(normalizer.entities_from_payload(payload, source, "zip_json"))
                    elif ext == ".xml":
                        if SafeET is None:
                            warnings.append(f"Skipped XML member because defusedxml is not installed: {member}")
                            continue
                        root = SafeET.fromstring(text)
                        entities.extend(normalizer.entities_from_payload(_xml_to_dict(root), source, "zip_xml"))
                    elif ext == ".csv":
                        entities.extend(normalizer.entities_from_rows(list(csv.DictReader(text.splitlines())), source))
                    elif ext in {".pkt", ".pka"}:
                        warning = "Native Packet Tracer member was recorded for hash/manifest only; export config/XML/JSON for high-fidelity parsing."
                        entities.append(NormalizedEntity(
                            id=_stable_id("source", source, info.file_size),
                            type="source_file",
                            name=member,
                            source_file=source,
                            confidence=0.35,
                            evidence=NormalizedEvidence(source_file=source, source_type="zip_native_manifest", confidence=0.35, source_text=warning),
                            normalized_fields={"extension": ext, "bytes": info.file_size, "sha256": hashlib.sha256(raw).hexdigest()},
                            warnings=[warning],
                        ))
                    else:
                        entities.extend(normalizer.entities_from_text(text, source))
                except (json.JSONDecodeError, csv.Error) as exc:
                    warnings.append(f"Could not parse ZIP member {member}: {exc}")
                except Exception as exc:
                    warnings.append(f"Skipped unsafe or invalid ZIP member {member}: {exc}")

        if not manifest:
            warnings.append("No supported evidence files were found inside the ZIP bundle.")
        return {
            "parser": self.name,
            "raw_type": "zip",
            "entities": [asdict(e) for e in _dedupe_entities(entities)],
            "warnings": warnings,
            "raw": {"members": manifest, "total_reviewed_bytes": total},
        }


class PacketTracerNativeParser(BaseParser):
    name = "packet_tracer_native_hook"
    extensions = (".pkt", ".pka")

    def parse(self, file_path: Path) -> Dict[str, Any]:
        info = DataImportValidator().validate_path(Path(file_path))
        warning = "Native Packet Tracer binary is accepted for hashing/bridging only. Export configs/XML/JSON for high-fidelity parsing."
        entity = NormalizedEntity(
            id=_stable_id("source", file_path.name, info.get("bytes")),
            type="source_file",
            name=file_path.name,
            source_file=file_path.name,
            confidence=0.35,
            evidence=NormalizedEvidence(source_file=file_path.name, source_type="native_manifest", confidence=0.35, source_text=warning),
            normalized_fields={"extension": file_path.suffix.lower(), "bytes": info.get("bytes"), "format_hint": info.get("format_hint")},
            warnings=[warning],
        )
        return {"parser": self.name, "raw_type": "binary", "entities": [asdict(entity)], "warnings": [warning], "raw": {"sha256": _file_sha256(Path(file_path))}}


class ParserRegistry:
    """Small registry so parsers can be added without editing routes."""

    def __init__(self, parsers: Optional[Sequence[BaseParser]] = None):
        self.parsers: List[BaseParser] = list(parsers or [JsonParser(), XmlParser(), CsvParser(), TextConfigParser(), ZipBundleParser(), PacketTracerNativeParser()])

    def register(self, parser: BaseParser) -> None:
        self.parsers.append(parser)

    def select(self, file_path: Path) -> BaseParser:
        for parser in self.parsers:
            if parser.can_parse(file_path):
                return parser
        raise ImportValidationError(f"No parser registered for {Path(file_path).suffix.lower() or 'extensionless file'}.")

    def parse(self, file_path: Path) -> Dict[str, Any]:
        DataImportValidator().validate_path(Path(file_path))
        parser = self.select(Path(file_path))
        result = parser.parse(Path(file_path))
        result.setdefault("parser", parser.name)
        return result

    def status(self) -> List[Dict[str, Any]]:
        return [{"name": p.name, "extensions": list(p.extensions), "status": "ready"} for p in self.parsers]


class SchemaNormalizer:
    """Creates one stable schema for UI tables, reports, and risk analysis."""

    def entities_from_payload(self, payload: Any, source_file: str, source_type: str) -> List[NormalizedEntity]:
        rows: List[NormalizedEntity] = []
        walker_items = list(_walk(payload))
        for path, value in walker_items:
            if isinstance(value, Mapping):
                maybe = self._entity_from_mapping(dict(value), source_file, source_type, path)
                if maybe:
                    rows.append(maybe)
        if not rows:
            rows.extend(self.entities_from_text(json.dumps(payload, ensure_ascii=False)[:100000], source_file))
        return _dedupe_entities(rows)

    def entities_from_rows(self, rows: List[Mapping[str, Any]], source_file: str) -> List[NormalizedEntity]:
        entities: List[NormalizedEntity] = []
        for idx, row in enumerate(rows, start=2):
            mapped = self._entity_from_mapping(dict(row), source_file, "csv", f"row[{idx}]")
            if mapped:
                mapped.evidence.source_line = idx
                entities.append(mapped)
            else:
                text = " ".join(str(v) for v in row.values())
                entities.extend(self.entities_from_text(text, source_file))
        return _dedupe_entities(entities)

    def entities_from_text(self, text: str, source_file: str) -> List[NormalizedEntity]:
        entities: List[NormalizedEntity] = []
        host_match = HOSTNAME_RE.search(text)
        hostname = host_match.group(1) if host_match else ""
        if hostname:
            entities.append(NormalizedEntity(
                id=_stable_id("dev", source_file, hostname), type="device", name=hostname, source_file=source_file, confidence=0.82,
                evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, host_match.start()), source_text=host_match.group(0), confidence=0.82),
                normalized_fields={"hostname": hostname, "device_type": _guess_device_type(text)},
            ))
        for match in INTERFACE_RE.finditer(text):
            name = match.group(1)
            block = _interface_block(text, match.start())
            ips = IP_RE.findall(block)
            entities.append(NormalizedEntity(
                id=_stable_id("if", source_file, hostname, name), type="interface", name=name, source_file=source_file, confidence=0.80,
                evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, match.start()), source_text=match.group(0), confidence=0.80),
                normalized_fields={"device": hostname, "interface": name, "ip_addresses": ips, "mode": _interface_mode(block), "shutdown": "shutdown" in block.lower()},
                warnings=["No hostname found for interface owner"] if not hostname else [],
            ))
        for vlan in VLAN_RE.finditer(text):
            vlan_id = int(vlan.group(1))
            if 1 <= vlan_id <= 4094:
                entities.append(NormalizedEntity(
                    id=_stable_id("vlan", source_file, vlan_id), type="vlan", name=f"VLAN {vlan_id}", source_file=source_file, confidence=0.76,
                    evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, vlan.start()), source_text=vlan.group(0), confidence=0.76),
                    normalized_fields={"vlan_id": vlan_id, "device": hostname},
                ))
        for ip_match in IP_RE.finditer(text):
            ip_value = ip_match.group(0)
            if _is_probable_ip(ip_value):
                entities.append(NormalizedEntity(
                    id=_stable_id("ip", source_file, ip_value, _line_number(text, ip_match.start())), type="ip_address", name=ip_value, source_file=source_file, confidence=0.65,
                    evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, ip_match.start()), source_text=_source_line(text, ip_match.start()), confidence=0.65),
                    normalized_fields={"ip": ip_value, "device": hostname},
                ))
        for mac_match in MAC_RE.finditer(text):
            mac = mac_match.group(0)
            entities.append(NormalizedEntity(
                id=_stable_id("mac", source_file, mac), type="mac_address", name=mac, source_file=source_file, confidence=0.70,
                evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, mac_match.start()), source_text=_source_line(text, mac_match.start()), confidence=0.70),
                normalized_fields={"mac": mac},
            ))
        for ssid_match in SSID_RE.finditer(text):
            ssid = ssid_match.group(1).strip()
            entities.append(NormalizedEntity(
                id=_stable_id("ssid", source_file, ssid), type="wireless_network", name=ssid, source_file=source_file, confidence=0.70,
                evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, ssid_match.start()), source_text=ssid_match.group(0), confidence=0.70),
                normalized_fields={"ssid": ssid, "security_mode": _wireless_security_mode(text)},
            ))
        for secret_match in SECRET_RE.finditer(text):
            line = _source_line(text, secret_match.start())
            entities.append(NormalizedEntity(
                id=_stable_id("secret", source_file, _line_number(text, secret_match.start()), secret_match.group(1)), type="credential", name=secret_match.group(1), source_file=source_file, confidence=0.86,
                evidence=NormalizedEvidence(source_file=source_file, source_type="text_config", source_line=_line_number(text, secret_match.start()), source_text=redact_secret(line), confidence=0.86),
                normalized_fields={"secret_type": secret_match.group(1), "redacted": True},
                warnings=["Sensitive value redacted in UI and reports"],
            ))
        return _dedupe_entities(entities)

    def _entity_from_mapping(self, row: Dict[str, Any], source_file: str, source_type: str, path: str) -> Optional[NormalizedEntity]:
        lower = {str(k).lower(): v for k, v in row.items()}
        name = _first(lower, ["name", "hostname", "device", "device_name", "id", "interface", "ssid", "vlan", "ip"])
        if not name:
            text = json.dumps(row, ensure_ascii=False)[:800]
            if not (IP_RE.search(text) or VLAN_RE.search(text) or MAC_RE.search(text)):
                return None
        entity_type = self._infer_type(lower)
        fields = {str(k): redact_secret(v) if "password" in str(k).lower() or "secret" in str(k).lower() or "token" in str(k).lower() else v for k, v in row.items() if _jsonable(v)}
        confidence = float(_first(lower, ["confidence", "score"], 0.74) or 0.74)
        if confidence > 1:
            confidence = confidence / 100.0
        name_text = _safe_str(name or entity_type)
        return NormalizedEntity(
            id=_stable_id(entity_type[:4], source_file, path, name_text),
            type=entity_type,
            name=name_text,
            source_file=source_file,
            confidence=max(0.05, min(0.99, confidence)),
            evidence=NormalizedEvidence(source_file=source_file, source_type=source_type, source_path=path, source_text=redact_secret(json.dumps(row, ensure_ascii=False)[:500]), confidence=confidence),
            raw_reference=path,
            normalized_fields=fields,
            warnings=[],
        )

    def _infer_type(self, lower: Mapping[str, Any]) -> str:
        keys = set(lower.keys())
        blob = " ".join(str(v).lower() for v in lower.values() if isinstance(v, (str, int, float)))[:800]
        if {"ssid", "security"} & keys or "ssid" in blob:
            return "wireless_network"
        if "vlan" in keys or "vlan_id" in keys or re.search(r"\bvlan\s*\d+", blob):
            return "vlan"
        if "interface" in keys or "ifname" in keys or "port" in keys:
            return "interface"
        if "route" in keys or "next_hop" in keys or "gateway" in keys:
            return "route"
        if "mac" in keys or MAC_RE.search(blob):
            return "mac_address"
        if "ip" in keys or "ip_address" in keys or IP_RE.search(blob):
            return "ip_address"
        if {"password", "secret", "token", "api_key"} & keys or SECRET_RE.search(blob):
            return "credential"
        if "firewall" in blob or "acl" in blob or "access-list" in blob:
            return "firewall_rule"
        if "hostname" in keys or "device" in keys or "device_type" in keys or "router" in blob or "switch" in blob:
            return "device"
        return "evidence"

    def from_existing_objects(self, objects: Mapping[str, Any], source_file: str = "active_import", source_mode: str = "existing") -> Dict[str, List[Dict[str, Any]]]:
        entities: List[NormalizedEntity] = []
        mapping = {
            "devices": "device",
            "interfaces": "interface",
            "ip_inventory": "ip_address",
            "vlans": "vlan",
            "vlan_database": "vlan",
            "routes": "route",
            "routing": "route",
            "wireless_networks": "wireless_network",
            "ssids": "wireless_network",
            "acl_rules": "firewall_rule",
            "security_rules": "firewall_rule",
            "credentials": "credential",
            "secrets": "credential",
            "links": "topology_link",
            "cdp_links": "topology_link",
            "topology_links": "topology_link",
        }
        for key, target_type in mapping.items():
            for idx, item in enumerate(_as_list(objects.get(key)), start=1):
                if not isinstance(item, Mapping):
                    continue
                name = _safe_str(_first(item, ["name", "hostname", "device", "interface", "local_interface", "remote_device", "ssid", "id", "vlan_id", "network", "destination"], f"{key}-{idx}"))
                evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
                confidence = _first(item, ["confidence"], _first(evidence, ["confidence"], 0.72))
                try:
                    confidence = float(confidence)
                    if confidence > 1:
                        confidence = confidence / 100.0
                except Exception:
                    confidence = 0.72
                entities.append(NormalizedEntity(
                    id=_stable_id(target_type[:4], source_file, key, idx, name),
                    type=target_type,
                    name=name,
                    source_file=source_file,
                    confidence=max(0.05, min(0.99, confidence)),
                    evidence=NormalizedEvidence(
                        source_file=source_file,
                        source_type=source_mode,
                        source_line=evidence.get("source_line") if isinstance(evidence, Mapping) else None,
                        source_path=f"objects.{key}[{idx-1}]",
                        source_text=redact_secret(evidence.get("source_text") or json.dumps(item, ensure_ascii=False)[:500]),
                        confidence=max(0.05, min(0.99, confidence)),
                    ),
                    raw_reference=f"objects.{key}[{idx-1}]",
                    normalized_fields={str(k): redact_secret(v) if "secret" in str(k).lower() or "password" in str(k).lower() or "token" in str(k).lower() else v for k, v in item.items() if _jsonable(v)},
                    warnings=[] if confidence >= 0.55 else ["Low-confidence recovered/inferred evidence"],
                ))
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for entity in _dedupe_entities(entities):
            grouped.setdefault(entity.type, []).append(asdict(entity))
        return grouped


class ProfessionalRiskEngine:
    """Evidence-based risk engine with conservative severity rules."""

    def analyze(self, grouped: Mapping[str, List[Dict[str, Any]]], objects: Optional[Mapping[str, Any]] = None) -> List[NormalizedFinding]:
        findings: List[NormalizedFinding] = []
        objects = objects or {}
        wireless_rows = list(grouped.get("wireless_network", [])) + _as_list(objects.get("ssids")) + _as_list(objects.get("wireless_networks"))
        for row in wireless_rows:
            fields = _entity_fields(row)
            mode = _safe_str(_first(fields, ["security_mode", "security", "auth", "encryption"], "")).lower()
            ssid = _safe_str(_first(fields, ["ssid", "name"], row.get("name") if isinstance(row, Mapping) else "wireless network"))
            if mode in {"open", "none", "wep"} or "wep" in mode or "open" in mode:
                sev = "High" if "open" in mode or mode == "none" else "Medium"
                findings.append(self._finding("wireless-weak", f"Weak wireless security on {ssid}", sev, 0.86, ssid, f"Security mode: {mode or 'not specified'}", "Attackers may join or decrypt traffic when wireless encryption is missing or weak.", "Use WPA2/WPA3 Enterprise or strong WPA2/WPA3 PSK; remove WEP/open production SSIDs.", "Wireless"))
        credential_rows = list(grouped.get("credential", [])) + _as_list(objects.get("credentials")) + _as_list(objects.get("secrets"))
        for row in credential_rows[:20]:
            name = _safe_str(row.get("name") if isinstance(row, Mapping) else "credential")
            findings.append(self._finding("cleartext-secret", f"Sensitive credential indicator detected: {name}", "High", 0.88, name, _entity_evidence_text(row), "Cleartext secrets in configs or logs can enable unauthorized access if the file is shared or committed.", "Rotate exposed secrets, replace plaintext with hashed/secret-store values, and redact reports by default.", "Secrets"))
        ip_rows = list(grouped.get("ip_address", []))
        ip_map: Dict[str, List[str]] = {}
        for row in ip_rows:
            fields = _entity_fields(row)
            ip = _safe_str(_first(fields, ["ip", "ip_address", "address"], row.get("name")))
            if _is_probable_ip(ip):
                ip_map.setdefault(ip, []).append(_safe_str(_first(fields, ["device", "interface", "name"], row.get("name"))))
        for ip, owners in ip_map.items():
            unique_owners = sorted({o for o in owners if o})
            if len(unique_owners) > 1:
                findings.append(self._finding("duplicate-ip", f"Duplicate IP address candidate: {ip}", "Medium", 0.76, ip, ", ".join(unique_owners[:6]), "Duplicate IP addresses can cause intermittent outage, hijacked traffic, or unstable routing.", "Verify interface inventories and DHCP reservations; remove the conflicting assignment.", "Addressing"))
        vlan_count = len(grouped.get("vlan", []))
        devices = grouped.get("device", [])
        interfaces = grouped.get("interface", [])
        if len(devices) >= 3 and vlan_count <= 1:
            findings.append(self._finding("flat-network", "Possible flat network / weak segmentation", "Medium", 0.62, "network", f"{len(devices)} device(s), {vlan_count} VLAN(s)", "A flat topology increases blast radius when one endpoint or VLAN is compromised.", "Create separate VLANs/security zones for users, servers, guests, management, and IoT; enforce ACLs/firewall policy.", "Segmentation"))
        firewall_rules = grouped.get("firewall_rule", []) or _as_list(objects.get("acl_rules"))
        if len(devices) >= 2 and not firewall_rules:
            findings.append(self._finding("missing-firewall-evidence", "No firewall/ACL evidence found", "Low", 0.55, "network", "No ACL/security-rule rows extracted", "Without ACL/firewall evidence, the report cannot prove segmentation or deny rules.", "Import show access-lists, firewall policies, or running-config security sections.", "Evidence Coverage"))
        for row in interfaces:
            fields = _entity_fields(row)
            name = _safe_str(row.get("name"))
            mode = _safe_str(_first(fields, ["mode", "switchport_mode"], "")).lower()
            shutdown = bool(_first(fields, ["shutdown", "disabled"], False))
            if mode == "access" and not shutdown and not _first(fields, ["vlan", "access_vlan", "vlan_id"], None):
                findings.append(self._finding("interface-missing-vlan", f"Access interface lacks VLAN evidence: {name}", "Low", 0.58, name, json.dumps(fields)[:220], "Access ports without clear VLAN evidence make segmentation validation weaker.", "Confirm access VLAN and port-security status for this interface.", "Interface Hygiene"))
        service_rows = _as_list(objects.get("services")) + _as_list(objects.get("open_services"))
        for service in service_rows:
            if not isinstance(service, Mapping):
                continue
            port = _first(service, ["port", "local_port"], None)
            try:
                port_i = int(port)
            except Exception:
                continue
            if port_i in MGMT_PORTS:
                findings.append(self._finding("mgmt-service", f"Management service exposed: {MGMT_PORTS[port_i]}:{port_i}", "Medium" if port_i != 23 else "High", 0.72, _safe_str(_first(service, ["host", "ip", "device"], "service")), redact_secret(json.dumps(service)[:300]), "Exposed management services increase attack surface, especially from user or guest networks.", "Restrict management services to admin VLAN/VPN, prefer SSH/HTTPS, and disable Telnet/VNC where possible.", "Exposure"))
        return _dedupe_findings(findings)

    def _finding(self, stem: str, title: str, severity: str, confidence: float, asset: str, evidence: str, why: str, rec: str, category: str) -> NormalizedFinding:
        return NormalizedFinding(
            id=_stable_id("finding", stem, title, asset, evidence),
            title=title,
            severity=severity if severity in SEVERITY_WEIGHTS else "Info",
            confidence=max(0.05, min(0.99, confidence)),
            affected_asset=asset or "network",
            evidence=redact_secret(evidence),
            why_it_matters=why,
            recommendation=rec,
            source_reference=asset or "network evidence",
            category=category,
        )

    def score(self, findings: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"score": 0, "label": "No confirmed risk", "max_severity": "Info", "finding_count": 0}
        weighted = sum(SEVERITY_WEIGHTS.get(str(f.get("severity")), 12) * float(f.get("confidence", 0.5) or 0.5) for f in findings)
        score = min(100, round(weighted / max(1, len(findings)) + min(18, len(findings) * 2)))
        max_sev = max((str(f.get("severity", "Info")) for f in findings), key=lambda s: SEVERITY_WEIGHTS.get(s, 0))
        label = "Critical exposure" if score >= 90 else "High risk" if score >= 72 else "Moderate risk" if score >= 45 else "Low risk"
        return {"score": score, "label": label, "max_severity": max_sev, "finding_count": len(findings)}


class ProfessionalReportBuilder:
    def build_json(self, result: AnalysisResult) -> bytes:
        return json.dumps(asdict(result), indent=2, ensure_ascii=False).encode("utf-8")

    def build_html(self, result: AnalysisResult) -> bytes:
        data = asdict(result)
        if Environment:
            template = Environment(autoescape=True).from_string(_HTML_TEMPLATE)
            return template.render(data=data).encode("utf-8")
        body = "<h1>WiGuard Nexus Analysis Report</h1>" + f"<pre>{html.escape(json.dumps(data, indent=2, ensure_ascii=False))}</pre>"
        return ("<!doctype html><meta charset='utf-8'>" + body).encode("utf-8")


class SystemHealthChecker:
    REQUIRED = ["flask", "werkzeug", "defusedxml", "jinja2"]
    OPTIONAL = ["networkx", "textfsm", "ntc_templates", "scapy", "reportlab", "pandas", "rapidfuzz"]

    def __init__(self, root: Optional[Path] = None):
        self.root = Path(root or Path.cwd())

    def check(self) -> Dict[str, Any]:
        required = [self._dep(name, required=True) for name in self.REQUIRED]
        optional = [self._dep(name, required=False) for name in self.OPTIONAL]
        dirs = []
        for rel in ["data", "data/uploads", "data/reports", "data/artifacts", "wiguard", "tests"]:
            path = self.root / rel
            dirs.append({"path": rel, "exists": path.exists(), "writable": os.access(path, os.W_OK) if path.exists() else False})
        parsers = ParserRegistry().status()
        ok = all(d["installed"] for d in required) and all(d["exists"] for d in dirs if d["path"] in {"data", "wiguard"})
        return {
            "ok": bool(ok),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "root": str(self.root),
            "required_dependencies": required,
            "optional_dependencies": optional,
            "directories": dirs,
            "parsers": parsers,
            "install_command": "python -m pip install -r requirements.txt",
            "optional_command": "python -m pip install -r requirements-full.txt",
            "test_command": "python -m pytest -q",
            "startup_command": "python main.py",
        }

    def _dep(self, name: str, required: bool) -> Dict[str, Any]:
        installed = importlib.util.find_spec(name) is not None
        return {"name": name, "installed": installed, "required": required, "status": "ready" if installed else ("missing" if required else "optional")}


def build_professional_analysis(objects: Mapping[str, Any], metadata: Optional[Mapping[str, Any]] = None) -> AnalysisResult:
    metadata = dict(metadata or {})
    source_file = _safe_str(metadata.get("filename") or metadata.get("source_file") or "active_import")
    source_mode = _safe_str(metadata.get("source_mode") or "existing")
    grouped = SchemaNormalizer().from_existing_objects(objects or {}, source_file=source_file, source_mode=source_mode)
    findings = [asdict(f) for f in ProfessionalRiskEngine().analyze(grouped, objects)]
    risk = ProfessionalRiskEngine().score(findings)
    topology = _build_topology_summary(grouped, objects or {})
    evidence_rows = _evidence_rows(grouped)
    summary = {
        "source_file": source_file,
        "source_mode": source_mode,
        "entity_count": sum(len(v) for v in grouped.values()),
        "device_count": len(grouped.get("device", [])),
        "interface_count": len(grouped.get("interface", [])),
        "vlan_count": len(grouped.get("vlan", [])),
        "route_count": len(grouped.get("route", [])),
        "finding_count": len(findings),
        "confidence_avg": _avg([float(r.get("confidence", 0.0) or 0.0) for rows in grouped.values() for r in rows]),
    }
    actions = _recommended_actions(findings, grouped)
    warnings = _analysis_warnings(grouped, objects or {})
    return AnalysisResult(
        summary=summary,
        extracted_assets=grouped,
        topology=topology,
        findings=findings,
        risk_score=risk,
        evidence=evidence_rows[:250],
        recommended_actions=actions,
        export_ready={"redacted": True, "schema_version": "professional-v1", "supports_json": True, "supports_html": True},
        warnings=warnings,
    )


def attach_professional_layer(objects: Dict[str, Any], metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Attach normalized UI/report rows to an existing WiGuard object dict."""
    if not isinstance(objects, dict):
        objects = {}
    result = build_professional_analysis(objects, metadata)
    data = asdict(result)
    assets = data.get("extracted_assets", {})
    objects["normalized_devices"] = assets.get("device", [])
    objects["normalized_interfaces"] = assets.get("interface", [])
    objects["normalized_ip_addresses"] = assets.get("ip_address", [])
    objects["normalized_vlans"] = assets.get("vlan", [])
    objects["normalized_routes"] = assets.get("route", [])
    objects["normalized_wireless"] = assets.get("wireless_network", [])
    objects["normalized_security_rules"] = assets.get("firewall_rule", [])
    objects["normalized_topology_links"] = assets.get("topology_link", [])
    objects["professional_findings"] = data.get("findings", [])
    objects["professional_analysis_result"] = [
        {
            "summary": data.get("summary", {}),
            "risk_score": data.get("risk_score", {}),
            "topology": data.get("topology", {}),
            "recommended_actions": data.get("recommended_actions", []),
            "warnings": data.get("warnings", []),
            "export_ready": data.get("export_ready", {}),
        }
    ]
    objects["professional_evidence_view"] = data.get("evidence", [])
    return objects


def health_report(root: Optional[Path] = None) -> Dict[str, Any]:
    return SystemHealthChecker(root).check()


def parse_file(file_path: Path) -> Dict[str, Any]:
    return ParserRegistry().parse(Path(file_path))


def _xml_to_dict(element: Any) -> Dict[str, Any]:
    node: Dict[str, Any] = {"tag": element.tag}
    if element.attrib:
        node["attributes"] = dict(element.attrib)
    text = (element.text or "").strip()
    if text:
        node["text"] = text[:1000]
    children = [_xml_to_dict(child) for child in list(element)]
    if children:
        node["children"] = children
    return node


def _walk(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, Mapping):
        for key, val in value.items():
            yield from _walk(val, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, val in enumerate(value):
            yield from _walk(val, f"{path}[{idx}]")


def _jsonable(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool, type(None), list, dict))


def _dedupe_entities(rows: Iterable[NormalizedEntity]) -> List[NormalizedEntity]:
    seen = set()
    out: List[NormalizedEntity] = []
    for row in rows:
        key = (row.type, row.name, row.source_file, row.raw_reference or row.evidence.source_path or row.evidence.source_line)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _dedupe_findings(rows: Iterable[NormalizedFinding]) -> List[NormalizedFinding]:
    seen = set()
    out: List[NormalizedFinding] = []
    for row in rows:
        key = (row.title, row.affected_asset, row.severity)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return sorted(out, key=lambda r: (order.get(r.severity, 9), -r.confidence, r.title))


def _line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, max(0, pos)) + 1


def _source_line(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, max(0, pos)) + 1
    end = text.find("\n", max(0, pos))
    if end == -1:
        end = len(text)
    return redact_secret(text[start:end].strip())[:500]


def _interface_block(text: str, start: int) -> str:
    end_match = re.search(r"\n\s*!|\n\s*interface\s+", text[start + 1:], flags=re.I)
    end = start + 1 + end_match.start() if end_match else min(len(text), start + 4000)
    return text[start:end]


def _interface_mode(block: str) -> str:
    lower = block.lower()
    if "switchport mode trunk" in lower:
        return "trunk"
    if "switchport mode access" in lower:
        return "access"
    if "ip address" in lower:
        return "routed"
    return "unknown"


def _wireless_security_mode(text: str) -> str:
    lower = text.lower()
    if "wpa3" in lower:
        return "wpa3"
    if "wpa2" in lower:
        return "wpa2"
    if "wep" in lower:
        return "wep"
    if "open" in lower or "authentication open" in lower:
        return "open"
    return "unknown"


def _guess_device_type(text: str) -> str:
    lower = text.lower()
    if "ip routing" in lower or "router ospf" in lower or "router eigrp" in lower:
        return "router_or_l3_switch"
    if "switchport" in lower or "spanning-tree" in lower:
        return "switch"
    if "wlan" in lower or "ssid" in lower:
        return "wireless"
    return "network_device"


def _is_probable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_multicast or addr.is_unspecified)
    except Exception:
        return False


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _entity_fields(row: Any) -> Dict[str, Any]:
    if not isinstance(row, Mapping):
        return {}
    fields = row.get("normalized_fields")
    if isinstance(fields, Mapping):
        return dict(fields)
    return dict(row)


def _entity_evidence_text(row: Any) -> str:
    if not isinstance(row, Mapping):
        return ""
    evidence = row.get("evidence")
    if isinstance(evidence, Mapping):
        return _safe_str(evidence.get("source_text"), 500)
    return _safe_str(row.get("evidence") or row, 500)


def _build_topology_summary(grouped: Mapping[str, List[Dict[str, Any]]], objects: Mapping[str, Any]) -> Dict[str, Any]:
    devices = grouped.get("device", [])
    links = grouped.get("topology_link", []) + _as_list(objects.get("cdp_links")) + _as_list(objects.get("links"))
    nodes = [{"id": d.get("id"), "label": d.get("name"), "type": _first(_entity_fields(d), ["device_type", "type"], "device")} for d in devices]
    edges = []
    for idx, link in enumerate(links, start=1):
        if not isinstance(link, Mapping):
            continue
        fields = _entity_fields(link)
        src = _safe_str(_first(fields, ["from", "source", "local_device", "device", "name"], link.get("name")))
        dst = _safe_str(_first(fields, ["to", "target", "remote_device", "neighbor"], ""))
        if src or dst:
            edges.append({"id": _stable_id("edge", idx, src, dst), "from": src, "to": dst, "confidence": link.get("confidence", 0.65)})
    return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges), "status": "ready" if nodes else "waiting_for_import"}


def _evidence_rows(grouped: Mapping[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for category, items in grouped.items():
        for item in items:
            evidence = item.get("evidence") if isinstance(item, Mapping) else {}
            evidence = evidence if isinstance(evidence, Mapping) else {}
            rows.append({
                "category": category,
                "name": item.get("name"),
                "source_file": evidence.get("source_file") or item.get("source_file"),
                "source_type": evidence.get("source_type"),
                "source_line": evidence.get("source_line"),
                "source_path": evidence.get("source_path"),
                "source_text": evidence.get("source_text"),
                "confidence": item.get("confidence"),
            })
    return rows


def _recommended_actions(findings: Sequence[Mapping[str, Any]], grouped: Mapping[str, List[Dict[str, Any]]]) -> List[str]:
    actions = []
    for finding in findings[:8]:
        rec = _safe_str(finding.get("recommendation"), 300)
        if rec and rec not in actions:
            actions.append(rec)
    if not grouped.get("firewall_rule"):
        actions.append("Import ACL/firewall policy evidence so WiGuard can validate segmentation instead of guessing.")
    if not grouped.get("topology_link"):
        actions.append("Import CDP/LLDP or topology export to improve attack-path confidence.")
    return actions[:10]


def _analysis_warnings(grouped: Mapping[str, List[Dict[str, Any]]], objects: Mapping[str, Any]) -> List[str]:
    warnings = []
    if not grouped.get("device"):
        warnings.append("No normalized device identity was extracted. Upload running-config/show version/XML/JSON with hostnames.")
    if not grouped.get("interface"):
        warnings.append("No normalized interface inventory was extracted. Upload interface configuration or show ip interface brief output.")
    if objects.get("native_source_manifest") and not grouped.get("device"):
        warnings.append("Native Packet Tracer evidence exists, but full topology may require exported config/XML/JSON companion evidence.")
    return warnings


def _avg(values: Sequence[float]) -> float:
    values = [v for v in values if isinstance(v, (int, float))]
    return round(sum(values) / len(values), 3) if values else 0.0


_HTML_TEMPLATE = """
<!doctype html>
<meta charset="utf-8">
<title>WiGuard Nexus Professional Analysis Report</title>
<style>
body{font-family:Arial, sans-serif; margin:32px; color:#142033} h1,h2{margin-bottom:6px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{border:1px solid #d8e0ea;border-radius:14px;padding:14px;background:#f8fbff}table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #d8e0ea;padding:8px;text-align:left;vertical-align:top}.sev-High,.sev-Critical{font-weight:bold}.muted{color:#6b7280}code{white-space:pre-wrap}
</style>
<h1>WiGuard Nexus Professional Analysis Report</h1>
<p class="muted">Redacted export · Schema {{ data.export_ready.schema_version }}</p>
<div class="cards">
  <div class="card"><b>Risk</b><br>{{ data.risk_score.score }}/100 · {{ data.risk_score.label }}</div>
  <div class="card"><b>Devices</b><br>{{ data.summary.device_count }}</div>
  <div class="card"><b>Interfaces</b><br>{{ data.summary.interface_count }}</div>
  <div class="card"><b>Findings</b><br>{{ data.summary.finding_count }}</div>
</div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>Affected asset</th><th>Evidence</th><th>Recommendation</th></tr>{% for f in data.findings %}<tr class="sev-{{ f.severity }}"><td>{{ f.severity }}</td><td>{{ f.title }}</td><td>{{ f.affected_asset }}</td><td><code>{{ f.evidence }}</code></td><td>{{ f.recommendation }}</td></tr>{% else %}<tr><td colspan="5">No confirmed findings.</td></tr>{% endfor %}</table>
<h2>Recommended Actions</h2>
<ol>{% for a in data.recommended_actions %}<li>{{ a }}</li>{% endfor %}</ol>
<h2>Evidence Preview</h2>
<table><tr><th>Category</th><th>Name</th><th>Source</th><th>Confidence</th><th>Text</th></tr>{% for e in data.evidence[:100] %}<tr><td>{{ e.category }}</td><td>{{ e.name }}</td><td>{{ e.source_file }} {{ e.source_line or '' }}</td><td>{{ e.confidence }}</td><td><code>{{ e.source_text }}</code></td></tr>{% endfor %}</table>
"""
