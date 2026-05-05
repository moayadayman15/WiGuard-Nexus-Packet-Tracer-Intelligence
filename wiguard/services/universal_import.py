"""Universal payload visibility layer for JSON/XML/Packet Tracer bridge imports.

This module does not pretend to reverse-engineer proprietary Packet Tracer data.
It guarantees that every uploaded structured payload (JSON, XML-derived JSON, or
internal PKT bridge JSON) is converted into reviewer-visible indexes:

* deterministic XML bridge preview
* normalized JSON preview
* recursive source tree
* key/value evidence index
* network candidate facts
* table summaries for arrays

The goal is simple: no successful import should look empty just because the
source schema is unfamiliar.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from xml.etree import ElementTree as ET

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
MAC_RE = re.compile(r"\b[0-9a-f]{2}(?:(?:[:.-])[0-9a-f]{2}){5}\b", re.I)
IFACE_RE = re.compile(r"\b(?:GigabitEthernet|FastEthernet|Ethernet|Serial|Tunnel|Loopback|Vlan|Port-channel|Fa|Gi|Eth|Se|Lo|Po|Vl)\s*\d+(?:[/.:]\d+){0,3}\b", re.I)
VLAN_KEY_RE = re.compile(r"(?:^|[^a-z])vlan(?:id)?(?:$|[^a-z])|\bvid\b", re.I)
CONFIG_LINE_RE = re.compile(r"^\s*(?:hostname|interface|ip address|switchport|vlan\s+\d+|ip route|router\s+\w+|access-list|ip access-list|line vty|enable secret|username|service password|spanning-tree|ip dhcp|snmp-server|crypto key)\b", re.I)
DEVICE_KEY_RE = re.compile(r"(?:hostname|device(?:name|id)?|node(?:name|id)?|router|switch|label|displayname|sysname)$", re.I)
LINK_KEY_RE = re.compile(r"(?:link|edge|connection|cable|neighbor|source|target|from|to|endpoint|port)", re.I)

MAX_TREE_ROWS = 900
MAX_KV_ROWS = 2500
MAX_FACT_ROWS = 1500
MAX_TABLE_ROWS = 120
MAX_XML_NODES = 2500
MAX_PREVIEW = 500


def _safe_text(value: Any, limit: int = MAX_PREVIEW) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    else:
        text = str(value)
    text = "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)
    return text[:limit]


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _path_key(path: str) -> str:
    # Last JSON-ish token from $.a.b[0].c
    tokens = re.split(r"[.\[\]/]+", str(path or ""))
    for token in reversed(tokens):
        token = token.strip("] ")
        if token and not token.isdigit() and token != "$":
            return token
    return "$"


def _tokenize_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(text or "").lower())


def _classify_fact(path: str, key: str, value: Any) -> Tuple[str | None, float]:
    key_blob = f"{path} {key}".lower()
    text = _safe_text(value, 900).strip()
    if not text:
        return None, 0.0
    if IP_RE.fullmatch(text) or (IP_RE.search(text) and any(k in key_blob for k in ["ip", "address", "gateway", "dns", "server", "next", "target"])):
        return "ip_address", 0.90
    if MAC_RE.search(text):
        return "mac_address", 0.88
    if IFACE_RE.search(text) or any(k in key_blob for k in ["interface", "ifname", "portname", "localport", "remoteport"]):
        if len(text) <= 120:
            return "interface", 0.78
    if VLAN_KEY_RE.search(key_blob):
        m = re.search(r"\b\d{1,4}\b", text)
        if m and 1 <= int(m.group(0)) <= 4094:
            return "vlan", 0.82
    if CONFIG_LINE_RE.search(text) or any(k in key_blob for k in ["runningconfig", "startupconfig", "config", "cli", "command", "showoutput"]):
        if len(text) > 8:
            return "config_or_cli", 0.76
    if DEVICE_KEY_RE.search(_tokenize_key(key)) or any(k in key_blob for k in ["devices", "nodes", "topology"]):
        if len(text) <= 140 and not IP_RE.fullmatch(text) and not MAC_RE.fullmatch(text):
            # Avoid classifying generic booleans/status values as devices.
            if text.lower() not in {"true", "false", "up", "down", "on", "off", "yes", "no"}:
                return "device_candidate", 0.72
    if LINK_KEY_RE.search(key_blob) and len(text) <= 160:
        return "link_reference", 0.62
    if re.match(r"^[a-z0-9_.-]+\.(local|lan|corp|internal|com|net|org)$", text, re.I):
        return "hostname_or_domain", 0.70
    return None, 0.0


def _iter_payload(value: Any, path: str = "$", depth: int = 0) -> Iterable[Tuple[str, Any, int]]:
    yield path, value, depth
    if depth > 40:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            safe_key = str(key).replace(".", "_")[:120]
            yield from _iter_payload(child, f"{path}.{safe_key}", depth + 1)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            yield from _iter_payload(child, f"{path}[{idx}]", depth + 1)


def _tree_row(path: str, value: Any, depth: int) -> Dict[str, Any]:
    if isinstance(value, dict):
        children = len(value)
        preview = ", ".join(list(map(str, value.keys()))[:12])
    elif isinstance(value, list):
        children = len(value)
        preview = f"{len(value)} item(s)"
    else:
        children = 0
        preview = _safe_text(value, 260)
    return {
        "path": path,
        "key": _path_key(path),
        "depth": depth,
        "type": _value_type(value),
        "children": children,
        "preview": preview,
        "evidence": {"source_path": path, "source_text": preview, "confidence": 0.70},
    }


def _table_summaries(payload: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path, value, depth in _iter_payload(payload):
        if len(rows) >= MAX_TABLE_ROWS:
            break
        if not isinstance(value, list) or not value:
            continue
        dict_items = [item for item in value[:50] if isinstance(item, dict)]
        if not dict_items:
            continue
        columns: Dict[str, int] = {}
        for item in dict_items:
            for key in item.keys():
                columns[str(key)] = columns.get(str(key), 0) + 1
        rows.append({
            "path": path,
            "rows": len(value),
            "sampled_rows": len(dict_items),
            "columns": [{"name": k, "presence": v} for k, v in sorted(columns.items(), key=lambda x: (-x[1], x[0]))[:30]],
            "sample": dict_items[:3],
            "evidence": {"source_path": path, "source_text": f"Array with {len(value)} row(s)", "confidence": 0.74},
        })
    return rows


def _safe_tag(name: Any) -> str:
    tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "item")).strip("._-")
    if not tag or not re.match(r"^[A-Za-z_]", tag):
        tag = "n_" + tag
    return tag[:80]


def _xml_add(parent: ET.Element, key: str, value: Any, counter: Dict[str, int]) -> None:
    if counter["nodes"] >= MAX_XML_NODES:
        return
    tag = _safe_tag(key)
    counter["nodes"] += 1
    elem = ET.SubElement(parent, tag, {"type": _value_type(value)})
    if isinstance(value, dict):
        for k, child in value.items():
            _xml_add(elem, k, child, counter)
    elif isinstance(value, list):
        elem.set("items", str(len(value)))
        for idx, child in enumerate(value[:350]):
            item = ET.SubElement(elem, "item", {"index": str(idx), "type": _value_type(child)})
            counter["nodes"] += 1
            if isinstance(child, dict):
                for k, v in child.items():
                    _xml_add(item, k, v, counter)
            elif isinstance(child, list):
                _xml_add(item, "nestedList", child, counter)
            else:
                item.text = _safe_text(child, 2000)
    else:
        elem.text = _safe_text(value, 5000)


def build_payload_xml(payload: Any, filename: str, source_mode: str) -> str:
    root = ET.Element("wiguardPayloadBridge", {
        "filename": Path(filename or "uploaded").name,
        "sourceMode": str(source_mode or "structured"),
        "fidelity": "lossless_structure_preview_capped_for_ui",
    })
    counter = {"nodes": 0}
    _xml_add(root, "payload", payload, counter)
    root.set("nodeCount", str(counter["nodes"]))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8", errors="replace")


def build_universal_objects(payload: Any, filename: str, source_mode: str) -> Dict[str, Any]:
    tree: List[Dict[str, Any]] = []
    kv: List[Dict[str, Any]] = []
    facts: List[Dict[str, Any]] = []
    total_nodes = 0
    total_leaves = 0
    type_counts: Dict[str, int] = {}
    fact_counts: Dict[str, int] = {}

    for path, value, depth in _iter_payload(payload):
        total_nodes += 1
        vt = _value_type(value)
        type_counts[vt] = type_counts.get(vt, 0) + 1
        if len(tree) < MAX_TREE_ROWS:
            tree.append(_tree_row(path, value, depth))
        if not isinstance(value, (dict, list)):
            total_leaves += 1
            key = _path_key(path)
            fact_type, confidence = _classify_fact(path, key, value)
            preview = _safe_text(value, 900)
            if len(kv) < MAX_KV_ROWS:
                kv.append({
                    "path": path,
                    "key": key,
                    "value_type": vt,
                    "value": preview,
                    "fact_type": fact_type or "generic_value",
                    "confidence": confidence or 0.45,
                    "evidence": {"source_path": path, "source_text": preview, "confidence": confidence or 0.45},
                })
            if fact_type and len(facts) < MAX_FACT_ROWS:
                row = {
                    "fact_type": fact_type,
                    "key": key,
                    "value": preview,
                    "path": path,
                    "confidence": confidence,
                    "evidence": {"source_path": path, "source_text": preview, "confidence": confidence},
                }
                facts.append(row)
                fact_counts[fact_type] = fact_counts.get(fact_type, 0) + 1
                # Extract multiple IP/MAC/interface occurrences from long strings.
                if fact_type == "config_or_cli":
                    for ip in sorted(set(IP_RE.findall(preview)))[:30]:
                        if len(facts) >= MAX_FACT_ROWS:
                            break
                        facts.append({"fact_type": "ip_address", "key": key, "value": ip, "path": path, "confidence": 0.80, "evidence": {"source_path": path, "source_text": preview[:900], "confidence": 0.80}})
                    for mac in sorted(set(MAC_RE.findall(preview)))[:30]:
                        if len(facts) >= MAX_FACT_ROWS:
                            break
                        facts.append({"fact_type": "mac_address", "key": key, "value": mac.lower(), "path": path, "confidence": 0.78, "evidence": {"source_path": path, "source_text": preview[:900], "confidence": 0.78}})
                    for iface in sorted(set(IFACE_RE.findall(preview)))[:30]:
                        if len(facts) >= MAX_FACT_ROWS:
                            break
                        facts.append({"fact_type": "interface", "key": key, "value": iface, "path": path, "confidence": 0.72, "evidence": {"source_path": path, "source_text": preview[:900], "confidence": 0.72}})

    table_rows = _table_summaries(payload)
    xml_text = build_payload_xml(payload, filename, source_mode)
    normalized = {
        "filename": Path(filename or "uploaded").name,
        "source_mode": source_mode,
        "summary": {
            "total_nodes": total_nodes,
            "leaf_values": total_leaves,
            "tree_rows_preserved": len(tree),
            "key_value_rows_preserved": len(kv),
            "network_facts": len(facts),
            "tables": len(table_rows),
            "type_counts": type_counts,
            "fact_counts": fact_counts,
        },
        "tree_preview": tree[:200],
        "key_value_preview": kv[:300],
        "network_facts_preview": facts[:300],
        "payload_tables_preview": table_rows[:60],
    }
    normalized_text = json.dumps(normalized, ensure_ascii=False, indent=2, default=str)
    manifest = [{
        "filename": Path(filename or "uploaded").name,
        "source_mode": source_mode,
        "status": "deep_payload_indexed",
        "total_nodes": total_nodes,
        "leaf_values": total_leaves,
        "tree_rows": len(tree),
        "key_value_rows": len(kv),
        "network_facts": len(facts),
        "tables": len(table_rows),
        "xml_bridge_bytes": len(xml_text.encode("utf-8", errors="replace")),
        "normalized_json_bytes": len(normalized_text.encode("utf-8", errors="replace")),
        "note": "Every readable JSON/XML/bridge value was walked recursively and preserved in the UI indexes with capped previews.",
        "evidence": {"source_path": "$", "source_text": "universal payload walk", "confidence": 0.80},
    }]
    return {
        "source_conversion_manifest": manifest,
        "source_payload_tree": tree,
        "source_key_value_index": kv,
        "universal_network_facts": facts,
        "payload_tables": table_rows,
        "universal_xml_preview": [{"name": f"{Path(filename or 'uploaded').stem}_universal_bridge.xml", "content": xml_text[:50000]}],
        "universal_json_preview": [{"name": f"{Path(filename or 'uploaded').stem}_universal.normalized.json", "content": normalized_text[:50000]}],
    }


def merge_universal_objects(objects: Dict[str, Any], payload: Any, filename: str, source_mode: str) -> Dict[str, Any]:
    """Append universal indexes to an existing extracted object dictionary."""
    if not isinstance(objects, dict):
        objects = {}
    universal = build_universal_objects(payload, filename, source_mode)
    for key, rows in universal.items():
        if not isinstance(rows, list):
            continue
        existing = objects.setdefault(key, [])
        if not isinstance(existing, list):
            objects[key] = []
            existing = objects[key]
        # Deduplicate by JSON representation while preserving order.
        seen = set()
        for item in existing:
            try:
                seen.add(json.dumps(item, sort_keys=True, ensure_ascii=False, default=str))
            except Exception:
                seen.add(str(item))
        for item in rows:
            try:
                marker = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
            except Exception:
                marker = str(item)
            if marker not in seen:
                existing.append(item)
                seen.add(marker)
    return objects
