"""Deep, schema-tolerant JSON/XML import normalizer for Packet Tracer evidence.

Packet Tracer native .pkt/.pka files are proprietary, while exported or converted
lab data often appears as JSON/XML with inconsistent keys.  This normalizer is
intentionally defensive: it walks every record, understands common topology
schemas, extracts embedded Cisco configs/show outputs, keeps source-path
evidence, and adds validation findings instead of silently returning zero data.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET

from .packet_tracer import normalize_interface_name
from .util import network_cidr, safe_int

CANONICAL_LIST_KEYS = [
    "devices", "vlans", "interfaces", "dhcp_scopes", "dhcp_excluded",
    "acl_rules", "nat_rules", "cdp_links", "lldp_links", "services",
    "ip_inventory", "interface_status", "trunk_operational", "route_table",
    "ospf_neighbors", "port_security", "spanning_tree", "etherchannels",
    "mac_table", "arp_table", "device_facts", "device_inventory",
    "security_hardening", "wireless_hints", "vlan_brief", "acl_hit_counts",
    "interface_counters", "stp_root", "protocol_summary", "command_blocks",
    "deep_evidence_index", "raw_evidence", "dhcp_gateway_matches",
    "subnet_inventory", "policy_controls", "risk_atoms", "coverage_domains",
    # v5.8.4 structured intelligence layers
    "schema_map", "import_warnings", "structured_relationships",
    "validation_findings", "endpoint_inventory",
    # v5.8.5 lab-result / Packet Tracer activity-matrix intelligence
    "access_tests", "client_access_matrix", "service_inventory",
    "roaming_events", "lab_result_summary",
    # v5.8.6-v5.8.9 native .pkt/.pka binary + XML/JSON bridge layers
    "native_pkt_profile", "binary_signatures", "recovered_string_preview",
    "native_conversion_guidance", "native_visible_hints",
    "internal_xml_bridge", "converted_xml_preview", "normalized_json_preview",
    "auto_conversion_pipeline", "decoded_payloads", "extraction_fidelity",
    "printable_segments_preview", "reconstructed_config_preview",
    # v5.9.8 deep fidelity layers: preserve every useful IOS/PT detail instead of
    # only counting the high-level topology objects.
    "all_config_commands", "interface_features", "management_services",
    "gateway_redundancy", "routing_protocol_details", "extraction_completeness",
    # v5.12 universal payload visibility: every JSON/XML/bridge upload gets
    # a recursive tree, key/value index, XML bridge, normalized JSON preview,
    # and fact candidates so unknown schemas never render as empty.
    "source_conversion_manifest", "source_payload_tree", "source_key_value_index",
    "universal_network_facts", "payload_tables", "universal_xml_preview",
    "universal_json_preview",
    # v5.12.4: real external Packet Tracer converter outputs and adapter attempts.
    "external_converter_outputs",
]


def blank_objects() -> Dict[str, Any]:
    objects = {key: [] for key in CANONICAL_LIST_KEYS}
    objects["routing"] = {"static_routes": [], "protocols": []}
    objects["vlan_crosscheck"] = {}
    objects["evidence_profile"] = {}
    return objects


def _json_text(value: Any, limit: int = 900) -> str:
    if isinstance(value, str):
        return value[:limit]
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:limit]
    except Exception:
        return str(value)[:limit]


def structured_evidence(path: str, value: Any = None, confidence: float = 0.78) -> Dict[str, Any]:
    return {
        "source_line": None,
        "source_path": path or "$",
        "source_text": _json_text(value, 900),
        "confidence": confidence,
    }


def merge_unique(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(base, dict):
        base = blank_objects()
    if not isinstance(extra, dict):
        return base
    for key, value in extra.items():
        if key == "routing" and isinstance(value, dict):
            base.setdefault("routing", {"static_routes": [], "protocols": []})
            for rkey in ["static_routes", "protocols"]:
                base["routing"].setdefault(rkey, [])
                for row in value.get(rkey, []) or []:
                    if isinstance(row, dict) and row not in base["routing"][rkey]:
                        base["routing"][rkey].append(row)
            continue
        if isinstance(value, list):
            base.setdefault(key, [])
            seen = {json.dumps(item, sort_keys=True, default=str) for item in base.get(key, []) or []}
            for row in value:
                marker = json.dumps(row, sort_keys=True, default=str)
                if marker not in seen:
                    base[key].append(row)
                    seen.add(marker)
        elif value not in (None, {}, []):
            base[key] = value
    return base


def _key_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def first_value(record: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    if not isinstance(record, dict):
        return default
    lower_map = {_key_token(k): k for k in record.keys()}
    for key in keys:
        actual = lower_map.get(_key_token(key))
        if actual is not None and record.get(actual) not in (None, "", [], {}):
            return record.get(actual)
    return default


def looks_like_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    return all(0 <= int(p) <= 255 for p in parts)


def _mac_like(value: Any) -> bool:
    return isinstance(value, str) and bool(re.match(r"^[0-9a-f]{2}([:.-]?[0-9a-f]{2}){5}$", value.strip(), flags=re.I))


def path_hint(path: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(path or ""))
    return value.lower().replace("/", ".")


def _hint_terms(*values: Any) -> set:
    text = " ".join(str(v or "") for v in values)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if t}


def _has_any_term(terms: set, names: Iterable[str]) -> bool:
    wanted = {_key_token(name) for name in names}
    normalized = {_key_token(term) for term in terms}
    return bool(normalized & wanted)


def _safe_path_key(path: str, parent_tokens: Iterable[str]) -> Optional[str]:
    """Infer a record name from object-map JSON paths.

    Many topology exports use dictionaries instead of arrays, for example
    {"devices": {"R1": {...}}} or {"interfaces": {"Gig0/0": {...}}}.
    The previous normalizer only trusted in-record name/id fields, so these
    valid exports lost device/interface identities. This helper recovers the
    key only when it sits under an explicit parent context, avoiding random
    wrapper keys becoming fake objects.
    """
    if not path:
        return None
    segments = [seg for seg in str(path).replace("$.", "").split(".") if seg and seg != "$"]
    if not segments:
        return None
    leaf = segments[-1]
    # Array rows such as nodes[0] are not stable names. Object-map leaves are.
    if re.search(r"\[\d+\]$", leaf):
        return None
    leaf = leaf.strip().strip('"\'')
    if not leaf or len(leaf) > 140:
        return None
    token = _key_token(leaf)
    generic = {
        "network", "topology", "devices", "device", "nodes", "node", "interfaces", "interface",
        "ports", "port", "links", "link", "connections", "vlans", "vlan", "config", "data",
        "attributes", "properties", "metadata", "settings", "children", "items", "records", "objects",
    }
    if token in generic or looks_like_ip(leaf):
        return None
    parents = {_key_token(x) for x in parent_tokens}
    for parent in segments[:-1]:
        base = re.sub(r"\[\d+\]$", "", parent)
        if _key_token(base) in parents:
            return leaf
    return None


def has_canonical_objects(payload: Any) -> bool:
    src = payload.get("objects") if isinstance(payload, dict) and isinstance(payload.get("objects"), dict) else payload
    if not isinstance(src, dict):
        return False
    for key in CANONICAL_LIST_KEYS:
        rows = src.get(key)
        if isinstance(rows, list) and any(_looks_canonical_row(key, row) for row in rows):
            return True
    return False


def _looks_canonical_row(key: str, row: Any) -> bool:
    """Avoid copying raw converter wrapper rows as already-normalized objects."""
    if not isinstance(row, dict):
        return False
    canonical_markers = {
        "devices": ["hostname", "id", "type", "role"],
        "interfaces": ["name", "interface", "normalized_name", "ip_address", "mode", "access_vlan"],
        "vlans": ["id", "vlan", "vlanId", "name"],
        "cdp_links": ["device", "neighbor", "local_interface", "remote_interface"],
        "lldp_links": ["device", "neighbor", "local_interface", "remote_interface"],
        "dhcp_scopes": ["name", "network", "cidr", "default_gateway"],
        "acl_rules": ["acl_name", "action", "protocol", "source", "destination"],
        "endpoint_inventory": ["device", "ip_address", "mac"],
    }
    markers = canonical_markers.get(key)
    if not markers:
        return True
    if any(row.get(marker) not in (None, "", [], {}) for marker in markers):
        return True
    # If the useful data is buried under wrappers, let StructuredEvidenceNormalizer
    # interpret it instead of displaying wrapper JSON as if it were an extracted object.
    if any(isinstance(row.get(wrapper), dict) for wrapper in ["attributes", "properties", "config", "data", "metadata"]):
        return False
    return False


def canonical_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    objects = blank_objects()
    if not isinstance(payload, dict):
        return objects
    src = payload.get("objects") if isinstance(payload.get("objects"), dict) else payload.get("extracted") if isinstance(payload.get("extracted"), dict) else payload
    if not isinstance(src, dict):
        return objects
    for key in CANONICAL_LIST_KEYS:
        if isinstance(src.get(key), list):
            objects[key] = [row for row in src.get(key) if _looks_canonical_row(key, row)]
    if isinstance(src.get("routing"), dict):
        objects["routing"] = src.get("routing")
    for key in ["vlan_crosscheck", "evidence_profile", "packet_tracer_profile", "structured_summary"]:
        if src.get(key) not in (None, {}, []):
            objects[key] = src.get(key)
    return objects


class StructuredEvidenceNormalizer:
    DEVICE_TYPE_HINTS = (
        "router", "switch", "ap", "access point", "wireless", "wlc", "server",
        "pc", "laptop", "firewall", "asa", "cloud", "internet", "printer",
    )
    CONFIG_HINTS = (
        "hostname ", "interface ", "switchport", "ip address", "ip route", "router ospf",
        "access-list", "ip access-list", "vlan ", "ip dhcp pool", "show ", "spanning-tree",
        "port-security", "cdp neighbors", "lldp neighbors", "running-config", "startup-config",
        "line vty", "enable secret", "snmp-server", "ip nat", "encapsulation dot1q",
    )
    CONFIG_KEY_HINTS = (
        "config", "running", "startup", "cli", "command", "output", "show", "terminal",
        "console", "deviceconfig", "iosconfig", "startupconfig", "runningconfig",
    )
    DEVICE_KEYS = [
        "hostname", "host_name", "displayName", "display_name", "label", "name", "id",
        "deviceName", "device_name", "nodeName", "node_name", "sysName", "systemName",
        "deviceLabel", "device_label", "displayLabel", "display_label", "caption",
    ]
    TYPE_KEYS = ["type", "deviceType", "device_type", "model", "category", "class", "className", "platform", "kind", "family"]
    IFACE_KEYS = ["interface", "interfaceName", "ifName", "if_name", "portName", "port_name", "port", "name", "id", "label",
        "portId", "port_id", "interfaceId", "interface_id", "adapterName", "adapter_name", "nicName", "nic_name"]
    DEVICE_REF_KEYS = ["device", "deviceName", "hostname", "parent", "node", "nodeName", "nodeId", "deviceId", "objectId", "uuid", "guid", "owner", "host",
        "sourceDevice", "targetDevice", "destinationDevice", "srcDevice", "dstDevice", "sourceNode", "targetNode",
        "sourceId", "targetId", "srcId", "dstId", "fromId", "toId", "localId", "remoteId"]

    def __init__(self):
        self.objects = blank_objects()
        self.text_chunks: List[str] = []
        self.summary = {
            "status": "empty",
            "records_walked": 0,
            "embedded_text_chunks": 0,
            "schema_hints": [],
            "sample_paths": [],
            "detected_sections": {},
            "normalizer": "structured_json_xml_v3_lab_matrix",
            "quality_notes": [],
        }
        self._seen_paths = set()
        self._id_to_name: Dict[str, str] = {}
        self._list_contexts: Dict[str, int] = {}

    def normalize_json(self, payload: Any) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        self.summary["format"] = "json"
        self._walk(payload, "$", parent={}, ancestors=[])
        return self._finish()

    def normalize_xml(self, text: str) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        self.summary["format"] = "xml"
        try:
            root = ET.fromstring(text)
            self.summary["root_tag"] = self._strip_ns(root.tag)
            self._walk_xml(root, f"/{self.summary['root_tag']}", parent={}, ancestors=[])
        except Exception as exc:
            self.summary["status"] = "xml_parse_failed"
            self.summary["error"] = str(exc)
            self.objects["import_warnings"].append({"severity": "High", "title": "XML parse failed", "detail": str(exc)})
        return self._finish()

    def _finish(self) -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
        self._enrich_from_relationships()
        self._derive_lab_result_summary()
        self._derive_validation_findings()
        self._build_schema_map()
        self.summary["embedded_text_chunks"] = len(self.text_chunks)
        tracked = [
            "devices", "interfaces", "vlans", "cdp_links", "dhcp_scopes", "acl_rules",
            "route_table", "wireless_hints", "endpoint_inventory", "access_tests",
            "client_access_matrix", "service_inventory", "roaming_events",
            "lab_result_summary", "validation_findings",
        ]
        for key in tracked:
            self.summary["detected_sections"][key] = len(self.objects.get(key, []) or [])
        if any(self.summary["detected_sections"].values()) or self.text_chunks:
            self.summary["status"] = "understood"
        elif self.summary.get("status") == "empty":
            self.summary["status"] = "no_network_objects_detected"
            self.objects["import_warnings"].append({
                "severity": "Medium",
                "title": "No network objects detected",
                "detail": "The file parsed successfully, but no devices, links, interfaces, VLANs, routes, ACLs, or config chunks matched known schemas.",
            })
        if self._list_contexts:
            self.summary["list_contexts"] = dict(sorted(self._list_contexts.items(), key=lambda x: (-x[1], x[0]))[:30])
        self.objects["structured_summary"] = self.summary
        if self.text_chunks:
            self.objects["command_blocks"].append({
                "command": "embedded structured text/config chunks",
                "start_line": None,
                "lines": sum(len(c.splitlines()) for c in self.text_chunks),
                "evidence": structured_evidence("embedded_text_chunks", f"{len(self.text_chunks)} chunks", 0.82),
            })
        return self.objects, "\n\n".join(self.text_chunks), self.summary

    def _remember_path(self, path: str) -> None:
        if len(self.summary["sample_paths"]) < 80 and path not in self._seen_paths:
            self.summary["sample_paths"].append(path)
            self._seen_paths.add(path)

    def _add_schema_hint(self, hint: str) -> None:
        if hint and hint not in self.summary["schema_hints"] and len(self.summary["schema_hints"]) < 80:
            self.summary["schema_hints"].append(hint)

    def _strip_ns(self, tag: Any) -> str:
        return str(tag or "").split("}")[-1]

    def _flatten_nested_payload(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Expose common Packet Tracer converter wrappers as top-level keys.

        Several PT exporters/converters wrap the useful fields inside
        attributes/properties/config/data dictionaries. The old normalizer walked
        those dictionaries later, but the parent context was sometimes lost, so
        device → interface, node → port, and link endpoint records looked empty.
        This flattening pass keeps the raw record intact while copying only
        scalar/list fields from known wrapper keys into the current record.
        """
        if not isinstance(record, dict):
            return record
        expanded = dict(record)
        wrapper_keys = [
            "attributes", "attribute", "attrs", "properties", "props", "property",
            "config", "configuration", "settings", "metadata", "meta", "data",
            "details", "parameters", "params", "addressing", "ipConfig", "ip_config",
            "networkConfig", "network_config", "portConfig", "port_config",
            # Real Packet Tracer converter JSON often stores useful values one
            # layer deeper than the object row, e.g. {"ipv4": {"address":
            # "10.0.0.1", "mask": "255.255.255.0"}} or
            # {"switchport": {"mode": "access", "vlan": 10}}.
            # Promoting only scalar/list leaves preserves the raw structure while
            # allowing the canonical extractor to populate interfaces/VLANs/IPs.
            "ipv4", "ipv6", "ip", "ipAddressing", "ip_addressing",
            "switchport", "switchPort", "layer2", "layer3", "ethernet",
            "portSettings", "port_settings", "interfaceConfig", "interface_config",
            "vlanMembership", "vlan_membership", "membership", "address",
        ]
        for wrapper in wrapper_keys:
            nested = record.get(wrapper)
            if isinstance(nested, dict):
                for key, value in nested.items():
                    if key not in expanded and not isinstance(value, dict):
                        expanded[key] = value
                    alias = f"{wrapper}_{key}"
                    if alias not in expanded and not isinstance(value, dict):
                        expanded[alias] = value
        # Some converters encode {"key": "hostname", "value": "R1"} records.
        key_name = first_value(record, ["key", "name", "field", "attributeName"])
        key_value = first_value(record, ["value", "val", "text", "attributeValue"])
        if key_name not in (None, "", [], {}) and key_value not in (None, "", [], {}):
            normalized_key = str(key_name)
            expanded.setdefault(normalized_key, key_value)
        return expanded


    def _flatten_xml_record(self, elem: ET.Element) -> Dict[str, Any]:
        record = {self._strip_ns(k): v for k, v in elem.attrib.items()}
        tag = self._strip_ns(elem.tag)
        record["tag"] = tag
        text = (elem.text or "").strip()
        if text:
            record["text"] = text
        # Include immediate child leaf values. Many PT-converter XML files use
        # <device><name>R1</name><type>Router</type></device> instead of attrs.
        for child in list(elem):
            child_tag = self._strip_ns(child.tag)
            child_text = (child.text or "").strip()
            if child_text and child_tag not in record:
                record[child_tag] = child_text
            if child.attrib:
                for key, value in child.attrib.items():
                    ckey = f"{child_tag}_{self._strip_ns(key)}"
                    if ckey not in record:
                        record[ckey] = value
        return record

    def _walk_xml(self, elem: ET.Element, path: str, parent: Dict[str, Any], ancestors: List[Dict[str, Any]]) -> None:
        self.summary["records_walked"] += 1
        self._remember_path(path)
        record = self._flatten_xml_record(elem)
        expanded_record = self._flatten_nested_payload(record)
        self._consume_record(expanded_record, path, parent, ancestors)
        next_parent = self._derive_next_parent(expanded_record, parent, path)
        for idx, child in enumerate(list(elem)):
            tag = self._strip_ns(child.tag)
            self._walk_xml(child, f"{path}/{tag}[{idx}]", next_parent, ancestors + [record])

    def _walk(self, value: Any, path: str, parent: Dict[str, Any], ancestors: List[Dict[str, Any]]) -> None:
        self.summary["records_walked"] += 1
        self._remember_path(path)
        if isinstance(value, dict):
            expanded_value = self._flatten_nested_payload(value)
            self._consume_record(expanded_value, path, parent, ancestors)
            next_parent = self._derive_next_parent(expanded_value, parent, path)
            for key, child in value.items():
                self._walk(child, f"{path}.{key}", next_parent, ancestors + [expanded_value])
        elif isinstance(value, list):
            key = path.split(".")[-1]
            self._list_contexts[key] = self._list_contexts.get(key, 0) + len(value)
            self._add_schema_hint(key)
            for idx, child in enumerate(value):
                self._walk(child, f"{path}[{idx}]", parent, ancestors)
        elif isinstance(value, str):
            self._consume_text(value, path)

    def _derive_next_parent(self, record: Dict[str, Any], parent: Dict[str, Any], path: str) -> Dict[str, Any]:
        if not isinstance(record, dict):
            return parent
        merged = dict(parent or {})
        name = first_value(record, self.DEVICE_KEYS) or _safe_path_key(path, ["devices", "device", "nodes", "node", "routers", "switches", "hosts", "endpoints", "ap", "access_points"])
        dtype = first_value(record, self.TYPE_KEYS)
        if self._record_is_device(record, path, name, dtype):
            merged.update({"deviceName": name, "hostname": name, "deviceType": dtype})
        else:
            # Keep lightweight parent identity keys without polluting child records.
            for key in ["deviceName", "hostname", "name", "id", "nodeId", "deviceId"]:
                if record.get(key) not in (None, "", [], {}):
                    merged.setdefault(key, record.get(key))
        return merged

    def _consume_text(self, value: str, path: str) -> None:
        text = str(value or "").strip()
        if not text:
            return
        lowered = text.lower()
        key_hint = path_hint(path)
        is_config_key = any(k in key_hint for k in self.CONFIG_KEY_HINTS)
        config_like = is_config_key or any(h in lowered for h in self.CONFIG_HINTS)
        if config_like and len(text) > 15:
            self.text_chunks.append(f"! structured-source: {path}\n{text}")
            self.objects["raw_evidence"].append({"line": None, "path": path, "text": text[:1500]})
            self._add_schema_hint("embedded_config_or_cli_text")
            return
        # Some converters store config as base64 strings. Decode only when it is
        # long enough and the decoded text contains network-config keywords.
        if len(text) > 60 and re.match(r"^[A-Za-z0-9+/=\s]+$", text):
            compact = re.sub(r"\s+", "", text)
            try:
                decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False).decode("utf-8", errors="ignore")
                dlow = decoded.lower()
                if len(decoded) > 30 and any(h in dlow for h in self.CONFIG_HINTS):
                    self.text_chunks.append(f"! structured-source-base64: {path}\n{decoded}")
                    self.objects["raw_evidence"].append({"line": None, "path": path, "text": decoded[:1500]})
                    self._add_schema_hint("base64_config_or_cli_text")
            except Exception:
                return

    def _consume_record(self, record: Dict[str, Any], path: str, parent: Dict[str, Any], ancestors: List[Dict[str, Any]]) -> None:
        if not isinstance(record, dict):
            return
        record = self._flatten_nested_payload(record)
        self._remember_path(path)
        hint = path_hint(path)
        keys = {str(k).lower() for k in record.keys()}
        for key, value in list(record.items()):
            if isinstance(value, str):
                self._consume_text(value, f"{path}.{key}")
        self._maybe_lab_result(record, path, hint, keys)
        self._maybe_device(record, path, hint, keys)
        self._maybe_interface(record, path, hint, keys, parent, ancestors)
        self._maybe_vlan(record, path, hint, keys)
        self._maybe_link(record, path, hint, keys)
        self._maybe_dhcp(record, path, hint, keys)
        self._maybe_acl(record, path, hint, keys)
        self._maybe_route(record, path, hint, keys)
        self._maybe_nat(record, path, hint, keys)
        self._maybe_wireless(record, path, hint, keys)
        self._maybe_inventory_fact(record, path, hint, keys)
        self._maybe_endpoint(record, path, hint, keys)
        self._maybe_mac_arp(record, path, hint, keys)

    def _add_unique(self, key: str, row: Dict[str, Any], identity_keys: List[str]) -> None:
        marker = tuple(str(row.get(k, "")) for k in identity_keys)
        for existing in self.objects.setdefault(key, []):
            if tuple(str(existing.get(k, "")) for k in identity_keys) == marker and any(marker):
                # Enrich rather than duplicate.
                for k, v in row.items():
                    current = existing.get(k)
                    if current in (None, "", [], {}) and v not in (None, "", [], {}):
                        existing[k] = v
                    elif k == "name" and v not in (None, "", [], {}):
                        current_text = str(current or "")
                        new_text = str(v or "")
                        # Replace generated/placeholder VLAN names with a later
                        # concrete VLAN label from a real vlan record.
                        if current_text.startswith("VLAN_") and not new_text.startswith("VLAN_"):
                            existing[k] = v
                return
        self.objects[key].append(row)

    def _record_is_device(self, record: Dict[str, Any], path: str, name: Any, dtype: Any) -> bool:
        tag_token = _key_token(record.get("tag"))
        if tag_token in {"devices", "nodes", "interfaces", "ports", "vlans", "links", "connections", "cables", "topology"}:
            return False
        hint = path_hint(path)
        keys = {str(k).lower() for k in record.keys()}
        terms = _hint_terms(hint, *keys, name, dtype)
        non_device_child = _has_any_term(terms, ["interface", "interfaces", "port", "ports", "vlan", "vlans", "link", "links", "dhcp", "acl", "route", "mac", "arp"])
        explicit_device_key = any(_key_token(k) in {"devicetype", "deviceclass", "devicecategory", "hostname", "devicename", "nodeid"} for k in keys)
        path_is_device = _has_any_term(terms, ["device", "devices", "node", "nodes", "router", "switch"]) or "topology.physical" in hint or "network.physical" in hint
        type_terms = _hint_terms(name, dtype)
        type_hint = any(_has_any_term(type_terms, [t]) for t in self.DEVICE_TYPE_HINTS if len(t) > 2) or _has_any_term(type_terms, ["ap", "pc"])
        return bool(name and ((path_is_device and not (non_device_child and not explicit_device_key)) or type_hint or explicit_device_key))

    def _infer_device_type(self, name: Any, dtype: Any) -> str:
        blob = f"{name or ''} {dtype or ''}".lower()
        if "router" in blob or re.match(r"^r\d+\b", str(name or ""), re.I):
            return "router"
        if "switch" in blob or re.match(r"^(sw|s)\d+\b", str(name or ""), re.I):
            return "switch"
        if "access point" in blob or " ap" in f" {blob}" or "wireless" in blob:
            return "access_point"
        if "firewall" in blob or "asa" in blob:
            return "firewall"
        if "server" in blob:
            return "server"
        if "pc" in blob or "laptop" in blob or "desktop" in blob:
            return "endpoint"
        if "cloud" in blob or "internet" in blob:
            return "cloud"
        return "device"

    def _maybe_device(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        name = first_value(record, self.DEVICE_KEYS) or _safe_path_key(path, ["devices", "device", "nodes", "node", "routers", "switches", "hosts", "endpoints", "access_points", "aps"])
        dtype = first_value(record, self.TYPE_KEYS)
        if name and self._record_is_device(record, path, name, dtype) and not looks_like_ip(str(name)) and len(str(name)) <= 140:
            ev = structured_evidence(path, record, 0.86)
            row = {
                "id": str(name),
                "hostname": str(name),
                "type": self._infer_device_type(name, dtype),
                "role": "structured_import",
                "model": str(dtype) if dtype else None,
                "x": first_value(record, ["x", "posX", "positionX", "left"]),
                "y": first_value(record, ["y", "posY", "positionY", "top"]),
                "evidence": ev,
            }
            self._add_unique("devices", row, ["id"])
            for id_key in ["id", "nodeId", "node_id", "deviceId", "device_id", "objectId", "object_id", "uuid", "guid", "sourceId", "targetId"]:
                val = first_value(record, [id_key])
                if val not in (None, "", [], {}):
                    self._id_to_name[str(val)] = str(name)
            self._id_to_name[str(name)] = str(name)

    def _device_name_from_ref(self, value: Any) -> Optional[str]:
        if isinstance(value, dict):
            # Endpoint dictionaries usually look like {nodeId/deviceId, port}.
            # Resolve the stable node id before generic name/id fields so link
            # rows become R1 ↔ SW1 instead of raw n1 ↔ n2 identifiers.
            value = first_value(value, [
                "nodeId", "node_id", "deviceId", "device_id", "objectId", "object_id", "uuid", "guid",
                "sourceId", "targetId", "srcId", "dstId", "fromId", "toId", "localId", "remoteId",
                "node", "device", "sourceNode", "targetNode", "sourceDevice", "targetDevice",
            ] + self.DEVICE_KEYS)
        if value in (None, "", [], {}):
            return None
        return self._id_to_name.get(str(value), str(value))

    def _context_device(self, record: Dict[str, Any], parent: Dict[str, Any], ancestors: List[Dict[str, Any]]) -> Optional[str]:
        direct = first_value(record, self.DEVICE_REF_KEYS)
        if direct:
            return self._device_name_from_ref(direct)
        parent_ref = first_value(parent or {}, self.DEVICE_REF_KEYS + self.DEVICE_KEYS)
        if parent_ref:
            return self._device_name_from_ref(parent_ref)
        for anc in reversed(ancestors or []):
            ref = first_value(anc, self.DEVICE_REF_KEYS + self.DEVICE_KEYS)
            dtype = first_value(anc, self.TYPE_KEYS)
            if ref and self._record_is_device(anc, "$", ref, dtype):
                return self._device_name_from_ref(ref)
        return None

    def _maybe_interface(self, record: Dict[str, Any], path: str, hint: str, keys: set, parent: Dict[str, Any], ancestors: List[Dict[str, Any]]) -> None:
        terms = _hint_terms(hint, *keys, record.get("tag"))
        if _key_token(record.get("tag")) in {"devices", "nodes", "interfaces", "ports", "vlans", "links", "connections", "cables", "topology"}:
            return
        # Do not turn a device/node row into an interface just because it owns an
        # `interfaces` or `ports` child array. The actual child rows are walked
        # separately and will become real interfaces.
        device_name = first_value(record, self.DEVICE_KEYS) or _safe_path_key(path, ["devices", "device", "nodes", "node", "routers", "switches", "hosts", "endpoints", "access_points", "aps"])
        device_type = first_value(record, self.TYPE_KEYS)
        explicit_iface_identity = first_value(record, [
            "interface", "interfaceName", "ifName", "if_name", "portName", "port_name",
            "port", "portId", "port_id", "interfaceId", "interface_id", "slotPort", "modulePort", "adapterName", "adapter_name", "nicName", "nic_name",
        ])
        if explicit_iface_identity in (None, "", [], {}) and self._record_is_device(record, path, device_name, device_type):
            return
        path_iface = _safe_path_key(path, ["interfaces", "interface", "ports", "port", "adapters", "nics", "modules"])
        name = explicit_iface_identity or first_value(record, ["name", "label", "id"]) or path_iface
        interface_context = _has_any_term(terms, ["interface", "interfaces", "port", "ports", "switchport", "ethernet", "serial", "gigabit", "fastethernet", "adapter", "nic", "moduleport", "connectionpoint"])
        if not name or not interface_context:
            return
        name = str(name)
        if len(name) > 140 or looks_like_ip(name) or name.lower() in {"interfaces", "ports", "link", "links", "devices", "nodes"}:
            return
        ip_value = first_value(record, ["ip", "ipAddress", "ip_address", "address", "ipv4", "ipv4Address", "ipAddr"])
        mask_value = first_value(record, ["mask", "subnetMask", "subnet_mask", "netmask"])
        ipv4_block = first_value(record, ["ipv4", "ipConfig", "ip_config", "addressing"])
        if isinstance(ip_value, dict):
            ip_value = first_value(ip_value, ["address", "ip", "ipv4", "value"])
        if not mask_value and isinstance(ipv4_block, dict):
            mask_value = first_value(ipv4_block, ["mask", "subnetMask", "subnet_mask", "netmask", "prefixLength"])
        switchport_block = first_value(record, ["switchport", "switchPort", "layer2", "portConfig", "port_config"])
        mode = first_value(record, ["mode", "switchportMode", "switchport_mode", "portMode", "port_mode", "linkMode"])
        vlan = first_value(record, ["accessVlan", "access_vlan", "vlan", "vlanId", "vlan_id", "vid", "accessVID", "pvid"])
        if isinstance(switchport_block, dict):
            mode = mode or first_value(switchport_block, ["mode", "switchportMode", "portMode"])
            vlan = vlan or first_value(switchport_block, ["accessVlan", "access_vlan", "vlan", "vlanId", "vid", "pvid"])
        native_vlan = first_value(record, ["nativeVlan", "native_vlan", "nativeVID", "nativeVid"])
        allowed = first_value(record, ["allowedVlans", "trunkAllowedVlans", "trunk_allowed_vlans", "allowed_vlan", "allowed", "taggedVlans", "tagged"])
        allowed_vlans = self._coerce_vlan_list(allowed)
        device = self._context_device(record, parent, ancestors)
        ev = structured_evidence(path, record, 0.84)
        row = {
            "name": name,
            "normalized_name": normalize_interface_name(name),
            "device": str(device) if device else None,
            "description": first_value(record, ["description", "desc", "label"], "") or "",
            "ip_address": str(ip_value) if looks_like_ip(str(ip_value)) else None,
            "subnet_mask": str(mask_value) if mask_value else None,
            "cidr": network_cidr(str(ip_value), str(mask_value)) if looks_like_ip(str(ip_value)) and mask_value else None,
            "mode": str(mode).lower() if mode else ("trunk" if allowed_vlans else "access" if vlan not in (None, "") else None),
            "access_vlan": self._vlan_id(vlan),
            "trunk_allowed_vlans": allowed_vlans,
            "native_vlan": self._vlan_id(native_vlan),
            "dot1q_vlan": self._vlan_id(first_value(record, ["dot1q", "encapsulationVlan", "encapsulation_vlan"])),
            "acl_in": first_value(record, ["aclIn", "acl_in", "inAcl", "accessGroupIn", "inboundAcl"]),
            "acl_out": first_value(record, ["aclOut", "acl_out", "outAcl", "accessGroupOut", "outboundAcl"]),
            "status": first_value(record, ["status", "state", "lineProtocol", "adminStatus", "operStatus", "linkState"]),
            "mac": first_value(record, ["mac", "macAddress", "mac_address", "hwaddr"]),
            "source": "structured_import",
            "evidence": ev,
        }
        self._add_unique("interfaces", row, ["device", "name"])
        if row["ip_address"]:
            self._add_unique("ip_inventory", {"interface": name, "device": row.get("device"), "ip_address": row["ip_address"], "ip": row["ip_address"], "status": row.get("status"), "evidence": ev}, ["device", "interface", "ip_address"])
            self._add_unique("endpoint_inventory", {"device": row.get("device"), "interface": name, "ip_address": row["ip_address"], "mac": row.get("mac"), "source": "interface", "evidence": ev}, ["device", "interface", "ip_address"])
        if row.get("status"):
            self._add_unique("interface_status", {"device": row.get("device"), "port": name, "name": name, "status": row.get("status"), "vlan": row.get("access_vlan"), "duplex": first_value(record, ["duplex"]), "speed": first_value(record, ["speed", "bandwidth"]), "type": first_value(record, ["type", "media"]), "evidence": ev}, ["device", "port", "status"])
        if allowed_vlans or row["mode"] == "trunk":
            self._add_unique("trunk_operational", {"device": row.get("device"), "interface": name, "normalized_interface": row["normalized_name"], "status": row.get("status") or "structured", "native_vlan": row.get("native_vlan"), "allowed_vlans": allowed_vlans or ["all"], "active_vlans": [], "forwarding_vlans": [], "evidence": ev}, ["device", "interface"])

    def _vlan_id(self, value: Any) -> Optional[str]:
        if value in (None, "", [], {}):
            return None
        if isinstance(value, dict):
            value = first_value(value, ["id", "vlan", "vlanId", "vid", "name"])
        m = re.search(r"\d{1,4}", str(value))
        if not m:
            return None
        vid = m.group(0)
        return vid if safe_int(vid) <= 4094 else None

    def _coerce_vlan_list(self, value: Any) -> List[str]:
        result: List[str] = []
        if value in (None, "", {}, []):
            return result
        values: Iterable[Any]
        if isinstance(value, list):
            values = value
        else:
            values = re.split(r"[,;\s]+", str(value or ""))
        for part in values:
            if isinstance(part, dict):
                part = first_value(part, ["id", "vlan", "vlanId", "vid", "name"])
            text = str(part or "").strip()
            if not text:
                continue
            if text.lower() == "all":
                result.append("all")
            elif "-" in text:
                a, b = text.split("-", 1)
                if a.isdigit() and b.isdigit():
                    result.extend(str(x) for x in range(int(a), int(b) + 1) if x <= 4094)
            else:
                vid = self._vlan_id(text)
                if vid:
                    result.append(vid)
        return list(dict.fromkeys(result))

    def _expand_vlan_list(self, value: str) -> List[str]:
        return self._coerce_vlan_list(value)

    def _maybe_vlan(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        if _key_token(record.get("tag")) in {"devices", "nodes", "interfaces", "ports", "vlans", "links", "connections", "cables", "topology"}:
            return
        vlan = first_value(record, ["vlan", "vlanId", "vlan_id", "vid", "id", "number"])
        terms = _hint_terms(hint, *keys)
        vlan_context = _has_any_term(terms, ["vlan", "vlans", "vlanid", "vid", "pvid"]) or {"vlan", "vlanid", "vid", "pvid"} & {_key_token(k) for k in keys}
        if vlan in (None, "") or not vlan_context:
            return
        vlan_id = self._vlan_id(vlan)
        if not vlan_id:
            return
        ev = structured_evidence(path, record, 0.85)
        tag_terms = _hint_terms(record.get("tag"), hint)
        concrete_name = first_value(record, ["vlanName", "vlan_name", "label"])
        # A converter interface row often contains name=GigabitEthernet0/0 and
        # vlanId=10. That proves VLAN 10 exists, but the interface name is not the
        # VLAN name. Only use the generic name field when the record itself is a
        # VLAN context.
        if concrete_name in (None, "", [], {}) and _has_any_term(tag_terms, ["vlan", "vlans"]):
            concrete_name = first_value(record, ["name"])
        row = {
            "id": vlan_id,
            "name": str(concrete_name or f"VLAN_{vlan_id}"),
            "status": first_value(record, ["status", "state"]),
            "ports_hint": first_value(record, ["ports", "interfaces", "members"]),
            "source": "structured_import",
            "evidence": ev,
        }
        self._add_unique("vlans", row, ["id"])
        self._add_unique("vlan_brief", row, ["id"])

    def _endpoint_value(self, record: Dict[str, Any], names: List[str]) -> Any:
        value = first_value(record, names)
        return self._device_name_from_ref(value)

    def _endpoint_port(self, value: Any) -> Optional[str]:
        if isinstance(value, dict):
            p = first_value(value, [
                "port", "interface", "ifName", "if_name", "name", "portName", "port_name",
                "adapter", "adapterName", "slotPort", "modulePort", "portId", "interfaceId",
                "interfaceName", "sourcePort", "targetPort", "localPort", "remotePort",
            ])
            return str(p) if p not in (None, "", [], {}) else None
        return None

    def _link_from_endpoint_list(self, record: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        # Use explicit endpoint arrays only. Treating a topology container's
        # generic `nodes` list as a link caused false edges such as n1 -> n2.
        endpoints = first_value(record, ["endpoints", "points", "terminations", "connectionPoints", "connection_points"])
        if not isinstance(endpoints, list) or len(endpoints) < 2:
            return None, None, None, None
        a, b = endpoints[0], endpoints[1]
        src = self._device_name_from_ref(a)
        dst = self._device_name_from_ref(b)
        return src, dst, self._endpoint_port(a), self._endpoint_port(b)

    def _maybe_link(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        terms = _hint_terms(hint, *keys, record.get("tag"))
        key_tokens = {_key_token(k) for k in keys}
        endpoint_key_present = bool(key_tokens & {
            "source", "src", "from", "target", "dst", "to", "sourcedevice", "targetdevice",
            "source_node", "target_node", "sourcenode", "targetnode", "sourceid", "targetid", "srcid", "dstid", "fromid", "toid", "devicea", "deviceb",
            "nodea", "nodeb", "localdevice", "remotedevice", "localid", "remoteid", "neighbor", "endpoints",
            "connectionpoints", "terminations",
        })
        indexed_link_path = bool(re.search(r"(?:links|connections|cables|edges)\[\d+\]", hint))
        tag_is_link = _key_token(record.get("tag")) in {"link", "connection", "cable", "edge", "wire"}
        if not (endpoint_key_present or indexed_link_path or tag_is_link):
            return
        link_context = _has_any_term(terms, ["link", "links", "edge", "edges", "connection", "connections", "cable", "cables", "wire"])
        src_endpoint = first_value(record, ["source", "src", "from", "sourceDevice", "source_device", "sourceNode", "source_node", "sourceId", "srcId", "fromId", "localId", "nodeA", "a", "localDevice", "local_device", "deviceA", "device_a"])
        dst_endpoint = first_value(record, ["target", "dst", "to", "targetDevice", "target_device", "targetNode", "target_node", "targetId", "dstId", "toId", "remoteId", "nodeB", "b", "remoteDevice", "remote_device", "neighbor", "deviceB", "device_b"])
        src = self._device_name_from_ref(src_endpoint)
        dst = self._device_name_from_ref(dst_endpoint)
        local_int = first_value(record, ["sourceInterface", "source_interface", "localInterface", "local_interface", "fromPort", "sourcePort", "srcPort", "portA", "interfaceA", "localPort"])
        remote_int = first_value(record, ["targetInterface", "target_interface", "remoteInterface", "remote_interface", "toPort", "targetPort", "dstPort", "destinationPort", "portB", "interfaceB", "remotePort"])
        local_int = local_int or self._endpoint_port(src_endpoint)
        remote_int = remote_int or self._endpoint_port(dst_endpoint)
        if not (src and dst):
            esrc, edst, eint_a, eint_b = self._link_from_endpoint_list(record)
            src, dst = src or esrc, dst or edst
            local_int, remote_int = local_int or eint_a, remote_int or eint_b
        if not (link_context and src and dst and str(src) != str(dst)):
            return
        ev = structured_evidence(path, record, 0.86)
        row = {
            "device": str(src),
            "neighbor": str(dst),
            "local_interface": str(local_int) if local_int else None,
            "remote_interface": str(remote_int) if remote_int else None,
            "platform": first_value(record, ["platform", "type", "media", "cable", "cableType"]),
            "source": "structured_topology",
            "evidence": ev,
        }
        self._add_unique("cdp_links", row, ["device", "neighbor", "local_interface", "remote_interface"])
        self.objects["structured_relationships"].append({"type": "link", "a": row["device"], "a_port": row["local_interface"], "b": row["neighbor"], "b_port": row["remote_interface"], "evidence": ev})

    def _maybe_dhcp(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        terms = _hint_terms(hint, *keys)
        dhcp_context = _has_any_term(terms, ["dhcp"]) or any("dhcp" in k for k in keys)
        if not dhcp_context:
            return
        name = first_value(record, ["name", "pool", "poolName", "pool_name", "id"], "DHCP_POOL")
        network = first_value(record, ["network", "subnet", "cidr", "prefix"])
        mask = first_value(record, ["mask", "subnetMask", "subnet_mask", "netmask"])
        gateway = first_value(record, ["defaultRouter", "default_router", "gateway", "defaultGateway", "default_gateway", "router"])
        start_ip = first_value(record, ["start", "startIp", "start_ip", "rangeStart"])
        end_ip = first_value(record, ["end", "endIp", "end_ip", "rangeEnd"])
        if not (network or gateway or start_ip or end_ip):
            return
        if not network and looks_like_ip(str(start_ip)) and mask:
            network = start_ip
        cidr = str(network) if isinstance(network, str) and "/" in network else network_cidr(str(network), str(mask)) if network and mask else None
        ev = structured_evidence(path, record, 0.84)
        self._add_unique("dhcp_scopes", {
            "name": str(name), "network": str(network) if network else None, "mask": str(mask) if mask else None,
            "cidr": cidr, "default_gateway": str(gateway) if gateway else None,
            "start_ip": str(start_ip) if looks_like_ip(str(start_ip)) else None,
            "end_ip": str(end_ip) if looks_like_ip(str(end_ip)) else None,
            "dns": first_value(record, ["dns", "dnsServer", "dns_server", "nameServer"]),
            "evidence": ev,
        }, ["name", "cidr", "default_gateway"])

    def _maybe_acl(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        terms = _hint_terms(hint, *keys)
        acl_context = _has_any_term(terms, ["acl", "accesslist", "access", "firewallrule", "rule", "rules"])
        action = first_value(record, ["action", "permitDeny", "permission", "effect", "decision"])
        if not (acl_context and action):
            return
        acl_name = first_value(record, ["acl", "aclName", "acl_name", "name", "id", "list", "policy"], "STRUCTURED_ACL")
        ev = structured_evidence(path, record, 0.80)
        self._add_unique("acl_rules", {
            "acl_name": str(acl_name),
            "acl_type": first_value(record, ["type", "aclType"], "structured"),
            "sequence": first_value(record, ["seq", "sequence", "line", "order"]),
            "action": str(action).lower(),
            "protocol": first_value(record, ["protocol", "proto", "service"], "ip"),
            "source": first_value(record, ["source", "src", "sourceIp", "srcIp", "from"], "any"),
            "source_port": first_value(record, ["sourcePort", "srcPort", "sport"]),
            "destination": first_value(record, ["destination", "dst", "dest", "destinationIp", "dstIp", "to"], "any"),
            "destination_port": first_value(record, ["destinationPort", "dstPort", "dport", "port"]),
            "raw": _json_text(record, 600),
            "evidence": ev,
        }, ["acl_name", "sequence", "action", "protocol", "source", "destination", "destination_port"])

    def _maybe_route(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        terms = _hint_terms(hint, *keys)
        route_context = _has_any_term(terms, ["route", "routes", "routing"]) or any(_key_token(k) in {"nexthop", "gateway"} for k in keys)
        dest = first_value(record, ["destination", "dest", "network", "prefix", "cidr", "route", "target"])
        next_hop = first_value(record, ["nextHop", "next_hop", "gateway", "via", "router"])
        mask = first_value(record, ["mask", "netmask", "subnetMask"])
        if not (route_context and (dest or next_hop)):
            return
        cidr = str(dest) if isinstance(dest, str) and "/" in dest else network_cidr(str(dest), str(mask)) if dest and mask else None
        ev = structured_evidence(path, record, 0.79)
        row = {"destination": str(dest) if dest else "default", "cidr": cidr, "next_hop": str(next_hop) if next_hop else None, "interface": first_value(record, ["interface", "ifName", "outInterface"]), "protocol": first_value(record, ["protocol", "source", "type"], "structured"), "metric": first_value(record, ["metric", "cost", "distance"]), "evidence": ev}
        self.objects.setdefault("routing", {"static_routes": [], "protocols": []}).setdefault("static_routes", []).append(row)
        self._add_unique("route_table", row, ["destination", "next_hop", "interface"])

    def _maybe_nat(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        terms = _hint_terms(hint, *keys)
        nat_context = _has_any_term(terms, ["nat"]) or any("nat" in k for k in keys)
        if not nat_context:
            return
        inside = first_value(record, ["inside", "insideLocal", "inside_local", "source"])
        outside = first_value(record, ["outside", "insideGlobal", "inside_global", "translated", "destination"])
        if inside or outside:
            self._add_unique("nat_rules", {"inside": inside, "outside": outside, "type": first_value(record, ["type", "mode"], "structured"), "evidence": structured_evidence(path, record, 0.72)}, ["inside", "outside", "type"])

    def _maybe_wireless(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        ssid = first_value(record, ["ssid", "SSID", "wlan", "wlanName", "wirelessName", "networkName"])
        wireless_context = any(x in hint for x in ["wireless", "wlan", "ssid", "accesspoint", "access_point", "ap", "radio"])
        if ssid or wireless_context:
            value = ssid or first_value(record, ["name", "id", "label"])
            if value:
                self._add_unique("wireless_hints", {"type": "ssid" if ssid else "wireless", "value": str(value), "security": first_value(record, ["security", "auth", "authentication", "encryption", "wpa"]), "vlan": self._vlan_id(first_value(record, ["vlan", "vlanId", "vlan_id"])), "evidence": structured_evidence(path, record, 0.78)}, ["type", "value"])


    def _normalize_lab_result(self, value: Any) -> str:
        text = str(value or "").strip().lower()
        if text in {"success", "succeeded", "pass", "passed", "allowed", "permit", "permitted", "reachable", "ok", "true", "1"}:
            return "success"
        if text in {"failed", "fail", "blocked", "deny", "denied", "unreachable", "timeout", "false", "0"}:
            return "failed"
        return text or "unknown"

    def _maybe_lab_result(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        """Understand Packet Tracer lab-result matrices, not only topology/config.

        Many Packet Tracer workflows export a result matrix like:
        client -> target/service -> Success/Failed with observed SSID/VLAN/IP/AP.
        That is not a device schema, but it is high-value evidence for wireless
        segmentation. We convert it into access tests, endpoint inventory,
        SSID/VLAN/AP evidence, service inventory, and reviewable control rows.
        """
        event = str(first_value(record, ["event", "eventType", "type", "kind"], "") or "").strip().lower()
        client = first_value(record, ["client", "username", "user", "host", "station", "endpoint"])
        target = first_value(record, ["target", "destination", "dst", "server", "resource", "target_ip"])
        service = first_value(record, ["service", "application", "app", "protocol", "portName", "port_name"])
        result = first_value(record, ["result", "status", "outcome", "state", "reachability"])
        ssid = first_value(record, ["actual_ssid", "actualSSID", "ssid", "SSID", "wireless_ssid", "networkName"])
        vlan = self._vlan_id(first_value(record, ["actual_vlan", "actualVlan", "vlan", "vlanId", "vlan_id", "vid"]))
        ip = first_value(record, ["actual_ip", "actualIp", "ip", "ipAddress", "ip_address", "address", "ipv4"])
        ap_name = first_value(record, ["ap_name", "apName", "ap", "access_point", "accessPoint", "associated_ap"])
        details = first_value(record, ["details", "detail", "message", "notes", "description"])
        expected = first_value(record, ["expected", "expected_result", "expectedResult", "policy_expected"])
        matrix_like = bool(client and (target or service or result) and (ssid or vlan or ip or ap_name or "matrix" in hint or "result" in hint))
        if not (matrix_like or event in {"acl_check", "access_check", "connectivity_check", "reachability", "roaming"}):
            return

        ev = structured_evidence(path, record, 0.90)
        client_text = str(client) if client not in (None, "", [], {}) else None
        ap_text = str(ap_name) if ap_name not in (None, "", [], {}) else None
        ssid_text = str(ssid) if ssid not in (None, "", [], {}) else None
        ip_text = str(ip) if looks_like_ip(str(ip)) else None

        if client_text:
            self._add_unique("devices", {"id": client_text, "hostname": client_text, "type": "endpoint", "role": "lab_client", "evidence": ev}, ["id"])
            self._add_unique("endpoint_inventory", {
                "device": client_text,
                "ip_address": ip_text,
                "ssid": ssid_text,
                "vlan": vlan,
                "ap_name": ap_text,
                "source": "packet_tracer_lab_matrix",
                "evidence": ev,
            }, ["device", "ip_address", "ssid", "vlan"])
        if ip_text:
            self._add_unique("ip_inventory", {
                "device": client_text,
                "ip_address": ip_text,
                "ip": ip_text,
                "ssid": ssid_text,
                "vlan": vlan,
                "ap_name": ap_text,
                "status": "observed",
                "evidence": ev,
            }, ["device", "ip_address"])
        if ap_text:
            self._add_unique("devices", {"id": ap_text, "hostname": ap_text, "type": "access_point", "role": "observed_ap", "evidence": ev}, ["id"])
            self._add_unique("wireless_hints", {"type": "access_point", "value": ap_text, "ssid": ssid_text, "vlan": vlan, "evidence": ev}, ["type", "value", "ssid"])
        if ssid_text:
            self._add_unique("wireless_hints", {"type": "ssid", "value": ssid_text, "vlan": vlan, "ap": ap_text, "evidence": ev}, ["type", "value", "vlan"])
        if vlan:
            self._add_unique("vlans", {"id": str(vlan), "name": ssid_text or f"VLAN_{vlan}", "source": "packet_tracer_lab_matrix", "evidence": ev}, ["id"])
        if (service or target) and "roaming" not in event:
            service_name = str(service or target)
            target_text = str(target) if target not in (None, "", [], {}) else None
            self._add_unique("service_inventory", {"service": service_name, "target": target_text, "source": "packet_tracer_lab_matrix", "evidence": ev}, ["service", "target"])
            if target_text and looks_like_ip(target_text):
                self._add_unique("devices", {"id": target_text, "hostname": service_name, "type": "service", "role": "lab_target", "ip_address": target_text, "evidence": ev}, ["id"])

        if "roaming" in event:
            self._add_unique("roaming_events", {
                "client": client_text,
                "ap_name": ap_text or (str(target) if target not in (None, "", [], {}) else None),
                "target": str(target) if target not in (None, "", [], {}) else None,
                "details": str(details or ""),
                "source": "packet_tracer_lab_matrix",
                "evidence": ev,
            }, ["client", "ap_name", "details"])
            self.objects["structured_relationships"].append({"type": "roaming", "client": client_text, "ap": ap_text or target, "evidence": ev})
            return

        if result not in (None, "", [], {}) or event in {"acl_check", "access_check", "connectivity_check", "reachability"}:
            normalized = self._normalize_lab_result(result)
            allowed = normalized == "success"
            row = {
                "client": client_text,
                "target": str(target) if target not in (None, "", [], {}) else None,
                "service": str(service) if service not in (None, "", [], {}) else None,
                "result": normalized,
                "allowed": allowed,
                "expected_result": str(expected) if expected not in (None, "", [], {}) else None,
                "actual_ssid": ssid_text,
                "actual_vlan": vlan,
                "actual_ip": ip_text,
                "ap_name": ap_text,
                "event": event or "access_test",
                "details": str(details or ""),
                "source": "packet_tracer_lab_matrix",
                "evidence": ev,
            }
            self._add_unique("access_tests", row, ["client", "target", "service", "result", "actual_ip"])
            self.objects["structured_relationships"].append({
                "type": "access_test",
                "client": client_text,
                "ssid": ssid_text,
                "vlan": vlan,
                "ap": ap_text,
                "target": row["target"],
                "service": row["service"],
                "result": normalized,
                "evidence": ev,
            })
            verdict = "reachable" if allowed else "blocked/unavailable"
            self._add_unique("policy_controls", {
                "control": f"Observed access: {client_text or 'client'} → {row['service'] or row['target'] or 'target'}",
                "status": "pass" if allowed else "review",
                "severity": "Info" if allowed else "Medium",
                "confidence": 0.88,
                "detail": f"Lab matrix observed {verdict} from SSID {ssid_text or 'unknown'} VLAN {vlan or 'unknown'} to {row['target'] or 'unknown target'}.",
                "evidence": ev,
            }, ["control", "detail"])

    def _derive_lab_result_summary(self) -> None:
        tests = [row for row in self.objects.get("access_tests", []) or [] if isinstance(row, dict)]
        roaming = [row for row in self.objects.get("roaming_events", []) or [] if isinstance(row, dict)]
        if not tests and not roaming:
            return

        clients: Dict[str, Dict[str, Any]] = {}
        ssids, vlans, aps, services = set(), set(), set(), set()
        success_count = failed_count = 0
        for row in tests:
            client = row.get("client") or "unknown"
            bucket = clients.setdefault(client, {
                "client": client,
                "ssid": row.get("actual_ssid"),
                "vlan": row.get("actual_vlan"),
                "ip": row.get("actual_ip"),
                "ap": row.get("ap_name"),
                "allowed_count": 0,
                "blocked_count": 0,
                "services_allowed": [],
                "services_blocked": [],
                "targets": [],
            })
            if row.get("actual_ssid"):
                ssids.add(str(row.get("actual_ssid")))
                bucket["ssid"] = bucket.get("ssid") or row.get("actual_ssid")
            if row.get("actual_vlan"):
                vlans.add(str(row.get("actual_vlan")))
                bucket["vlan"] = bucket.get("vlan") or row.get("actual_vlan")
            if row.get("ap_name"):
                aps.add(str(row.get("ap_name")))
                bucket["ap"] = bucket.get("ap") or row.get("ap_name")
            if row.get("actual_ip"):
                bucket["ip"] = bucket.get("ip") or row.get("actual_ip")
            svc = row.get("service") or row.get("target") or "unknown"
            services.add(str(svc))
            if row.get("target"):
                bucket["targets"].append(row.get("target"))
            if row.get("result") == "success":
                success_count += 1
                bucket["allowed_count"] += 1
                bucket["services_allowed"].append(svc)
            elif row.get("result") == "failed":
                failed_count += 1
                bucket["blocked_count"] += 1
                bucket["services_blocked"].append(svc)

        matrix = []
        for bucket in clients.values():
            for key in ["services_allowed", "services_blocked", "targets"]:
                bucket[key] = list(dict.fromkeys([str(x) for x in bucket.get(key, []) if x not in (None, "")]))
            matrix.append(bucket)
        matrix.sort(key=lambda x: (str(x.get("vlan") or ""), str(x.get("client") or "")))
        self.objects["client_access_matrix"] = matrix

        summary = {
            "format": self.summary.get("format"),
            "total_tests": len(tests),
            "success": success_count,
            "failed": failed_count,
            "clients": len(clients),
            "ssids": len(ssids),
            "vlans": len(vlans),
            "aps": len(aps),
            "services": len(services),
            "roaming_events": len(roaming),
            "source": "packet_tracer_lab_matrix",
        }
        self.objects["lab_result_summary"] = [summary]
        self._add_schema_hint("packet_tracer_lab_results_matrix")
        self.summary["quality_notes"].append(
            f"Packet Tracer lab result matrix detected: {len(tests)} access tests, {len(clients)} clients, {len(ssids)} SSIDs, {len(vlans)} VLANs."
        )

    def _maybe_inventory_fact(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        model = first_value(record, ["model", "platform", "partNumber", "part_number", "product", "type"])
        serial = first_value(record, ["serial", "serialNumber", "serial_number", "sn"])
        version = first_value(record, ["version", "ios", "softwareVersion", "software_version", "firmware", "image"])
        name = first_value(record, self.DEVICE_KEYS)
        if any([model, serial, version]) and ("device" in hint or "inventory" in hint or "node" in hint or "equipment" in hint):
            ev = structured_evidence(path, record, 0.78)
            self._add_unique("device_inventory", {"device": str(name) if name else None, "model": model, "serial": serial, "version": version, "evidence": ev}, ["device", "model", "serial", "version"])
            if version:
                self._add_unique("device_facts", {"device": str(name) if name else None, "fact": "software_version", "value": version, "evidence": ev}, ["device", "fact", "value"])

    def _maybe_endpoint(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        ip = first_value(record, ["ip", "ipAddress", "ip_address", "address", "ipv4", "ipv4Address"])
        mac = first_value(record, ["mac", "macAddress", "mac_address", "hwaddr"])
        name = first_value(record, ["hostname", "name", "host", "device", "client", "label"])
        if looks_like_ip(str(ip)) or _mac_like(str(mac)):
            ev = structured_evidence(path, record, 0.74)
            self._add_unique("endpoint_inventory", {"device": str(name) if name else None, "ip_address": str(ip) if looks_like_ip(str(ip)) else None, "mac": str(mac).lower() if mac else None, "source": "structured_endpoint", "evidence": ev}, ["device", "ip_address", "mac"])

    def _maybe_mac_arp(self, record: Dict[str, Any], path: str, hint: str, keys: set) -> None:
        mac = first_value(record, ["mac", "macAddress", "mac_address", "hwaddr"])
        ip = first_value(record, ["ip", "ipAddress", "ip_address", "address", "ipv4"])
        vlan = self._vlan_id(first_value(record, ["vlan", "vlanId", "vid"] ))
        port = first_value(record, ["port", "interface", "ifName"])
        if mac and _mac_like(str(mac)) and ("mac" in hint or vlan or port):
            self._add_unique("mac_table", {"vlan": vlan, "mac": str(mac).lower(), "type": first_value(record, ["type"], "structured"), "interface": port, "normalized_interface": normalize_interface_name(str(port)) if port else None, "evidence": structured_evidence(path, record, 0.70)}, ["vlan", "mac", "interface"])
        if looks_like_ip(str(ip)) and mac and _mac_like(str(mac)):
            self._add_unique("arp_table", {"ip_address": str(ip), "mac": str(mac).lower(), "interface": port, "normalized_interface": normalize_interface_name(str(port)) if port else None, "evidence": structured_evidence(path, record, 0.70)}, ["ip_address", "mac", "interface"])

    def _enrich_from_relationships(self) -> None:
        # Infer missing device nodes from interfaces and links.
        for iface in self.objects.get("interfaces", []) or []:
            dev = iface.get("device")
            if dev:
                self._add_unique("devices", {"id": dev, "hostname": dev, "type": "device", "role": "inferred_from_interface", "evidence": iface.get("evidence")}, ["id"])
            for vid in [iface.get("access_vlan"), iface.get("native_vlan"), iface.get("dot1q_vlan")]:
                if vid:
                    self._add_unique("vlans", {"id": str(vid), "name": f"VLAN_{vid}", "source": "inferred_from_interface", "evidence": iface.get("evidence")}, ["id"])
            for vid in iface.get("trunk_allowed_vlans") or []:
                if str(vid).isdigit():
                    self._add_unique("vlans", {"id": str(vid), "name": f"VLAN_{vid}", "source": "inferred_from_trunk_allowed", "evidence": iface.get("evidence")}, ["id"])
        for link in self.objects.get("cdp_links", []) or []:
            for dev_key in ["device", "neighbor"]:
                dev = link.get(dev_key)
                if dev:
                    self._add_unique("devices", {"id": dev, "hostname": dev, "type": "device", "role": "inferred_from_link", "evidence": link.get("evidence")}, ["id"])
            for dev, port in [(link.get("device"), link.get("local_interface")), (link.get("neighbor"), link.get("remote_interface"))]:
                if dev and port:
                    self._add_unique("interfaces", {"device": dev, "name": port, "normalized_name": normalize_interface_name(port), "mode": None, "source": "inferred_from_link", "evidence": link.get("evidence")}, ["device", "name"])

    def _derive_validation_findings(self) -> None:
        findings = []
        def add(key: str, severity: str, title: str, detail: str, evidence: Optional[Dict[str, Any]] = None):
            findings.append({"key": key, "severity": severity, "title": title, "detail": detail, "evidence": evidence})
        devices = {str(d.get("id") or d.get("hostname")) for d in self.objects.get("devices", []) if d.get("id") or d.get("hostname")}
        vlan_ids = {str(v.get("id")) for v in self.objects.get("vlans", []) if v.get("id")}
        for iface in self.objects.get("interfaces", []) or []:
            if not iface.get("device"):
                add("orphan-interface", "Low", f"Interface {iface.get('name')} has no device owner", "The schema exposed an interface/port but did not include a clear parent device reference.", iface.get("evidence"))
            for vid in [iface.get("access_vlan"), iface.get("native_vlan"), iface.get("dot1q_vlan")]:
                if vid and str(vid) not in vlan_ids:
                    add("vlan-referenced-not-defined", "Medium", f"VLAN {vid} referenced but not explicitly defined", "The VLAN was found on an interface but no VLAN object/name was present in the structured source.", iface.get("evidence"))
            if iface.get("mode") == "trunk" and not iface.get("trunk_allowed_vlans"):
                add("trunk-without-allowed-list", "Medium", f"Trunk {iface.get('name')} has no allowed VLAN list", "The port is trunk-like, but the source did not prove allowed/active VLANs.", iface.get("evidence"))
        for link in self.objects.get("cdp_links", []) or []:
            for side in ["device", "neighbor"]:
                if link.get(side) and str(link.get(side)) not in devices:
                    add("link-endpoint-not-defined", "Low", f"Link endpoint {link.get(side)} was inferred", "A topology edge references a node that was not separately defined as a device.", link.get("evidence"))
        ip_seen: Dict[str, List[str]] = {}
        for item in (self.objects.get("ip_inventory", []) or []) + (self.objects.get("endpoint_inventory", []) or []):
            ip = item.get("ip_address") or item.get("ip")
            if looks_like_ip(str(ip)):
                owner = item.get("device") or item.get("interface") or "unknown"
                ip_seen.setdefault(str(ip), []).append(str(owner))
        for ip, owners in ip_seen.items():
            unique_owners = sorted(set(owners))
            if len(unique_owners) > 1:
                add("duplicate-ip", "High", f"Duplicate IP candidate {ip}", "The same IP appears on multiple owners: " + ", ".join(unique_owners[:8]), None)

        access_tests = [row for row in self.objects.get("access_tests", []) or [] if isinstance(row, dict)]
        if access_tests:
            if not any(row.get("expected_result") for row in access_tests):
                add(
                    "expected-policy-baseline-missing",
                    "Medium",
                    "Access matrix has observed results but no expected policy baseline",
                    "WiGuard can prove what happened, but it cannot judge pass/fail against design intent until an expected policy matrix is imported.",
                    access_tests[0].get("evidence"),
                )
            by_client: Dict[str, Dict[str, set]] = {}
            for row in access_tests:
                client = str(row.get("client") or "unknown")
                service = str(row.get("service") or row.get("target") or "").lower()
                result = str(row.get("result") or "").lower()
                bucket = by_client.setdefault(client, {"success": set(), "failed": set()})
                if result in bucket:
                    bucket[result].add(service)
            for client, bucket in by_client.items():
                if "internet" in bucket["success"] and "dns" in bucket["failed"]:
                    add(
                        "dns-internet-result-inconsistency",
                        "Medium",
                        f"{client} reached Internet but DNS test failed",
                        "The matrix indicates Internet reachability while DNS is blocked/unavailable. Verify whether the DNS target is intentionally internal-only or whether the internet test is bypassing normal DNS.",
                        None,
                    )
        self.objects["validation_findings"] = findings[:150]
        self.objects["import_warnings"].extend([f for f in findings if f["severity"] in {"High", "Medium"}][:50])
        if findings:
            self.summary["quality_notes"].append(f"{len(findings)} structured validation finding(s) were generated.")

    def _build_schema_map(self) -> None:
        rows = []
        for key in ["devices", "interfaces", "vlans", "cdp_links", "dhcp_scopes", "acl_rules", "route_table", "wireless_hints", "endpoint_inventory", "access_tests", "client_access_matrix", "service_inventory", "roaming_events"]:
            paths = {}
            for row in self.objects.get(key, []) or []:
                ev = row.get("evidence") if isinstance(row, dict) else None
                path = ev.get("source_path") if isinstance(ev, dict) else None
                if path:
                    paths[path] = paths.get(path, 0) + 1
            if paths:
                rows.append({"object_type": key, "count": len(self.objects.get(key, []) or []), "paths": [{"path": p, "count": c} for p, c in sorted(paths.items(), key=lambda x: (-x[1], x[0]))[:8]]})
        self.objects["schema_map"] = rows




def _dedupe_rows(rows: List[Any], identity_keys: List[str]) -> List[Any]:
    deduped: List[Any] = []
    seen: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        marker = tuple(str(row.get(k) or "") for k in identity_keys)
        if not any(marker):
            deduped.append(row)
            continue
        existing = seen.get(marker)
        if existing is None:
            seen[marker] = row
            deduped.append(row)
            continue
        # Keep the row with more populated fields/evidence; fill missing fields.
        for key, value in row.items():
            if existing.get(key) in (None, "", [], {}) and value not in (None, "", [], {}):
                existing[key] = value
        if len([v for v in row.values() if v not in (None, "", [], {})]) > len([v for v in existing.values() if v not in (None, "", [], {})]):
            existing.update(row)
    return deduped


def _dedupe_core_objects(objects: Dict[str, Any]) -> None:
    specs = {
        "devices": ["id"],
        "interfaces": ["device", "name"],
        "vlans": ["id"],
        "cdp_links": ["device", "neighbor", "local_interface", "remote_interface"],
        "lldp_links": ["device", "neighbor", "local_interface", "remote_interface"],
        "ip_inventory": ["device", "interface", "ip_address"],
        "endpoint_inventory": ["device", "ip_address", "mac"],
        "wireless_hints": ["type", "value", "ssid", "vlan"],
        "route_table": ["protocol", "destination", "next_hop", "interface"],
        "acl_rules": ["acl_name", "sequence", "action", "source", "destination", "port"],
        "dhcp_scopes": ["name", "cidr", "default_gateway"],
        "port_security": ["interface"],
        "spanning_tree": ["interface", "vlan"],
        "etherchannels": ["group", "port_channel"],
    }
    for key, identity in specs.items():
        if isinstance(objects.get(key), list):
            objects[key] = _dedupe_rows(objects.get(key), identity)

def _derive_inventory_from_interfaces(objects: Dict[str, Any]) -> None:
    """Backfill L3/endpoint inventory from parsed interface blocks.

    The IOS parser extracts interface IPs reliably, but older builds only
    populated `ip_inventory` from `show ip interface brief`. That made Packet
    Tracer imports look incomplete even when running-config contained valid IP
    addresses. This derivation is evidence-preserving and never invents values.
    """
    seen_ip = {
        (str(row.get("device") or ""), str(row.get("interface") or row.get("name") or ""), str(row.get("ip_address") or row.get("ip") or ""))
        for row in objects.get("ip_inventory", []) or []
        if isinstance(row, dict)
    }
    seen_endpoint = {
        (str(row.get("device") or ""), str(row.get("interface") or ""), str(row.get("ip_address") or ""))
        for row in objects.get("endpoint_inventory", []) or []
        if isinstance(row, dict)
    }
    for iface in list(objects.get("interfaces", []) or []):
        if not isinstance(iface, dict):
            continue
        ip = iface.get("ip_address") or iface.get("ip")
        name = iface.get("name") or iface.get("interface") or iface.get("normalized_name")
        if not ip or not name:
            continue
        device = iface.get("device") or iface.get("hostname")
        evidence = iface.get("evidence") if isinstance(iface.get("evidence"), dict) else structured_evidence("derived/interface_ip", iface, 0.72)
        ip_marker = (str(device or ""), str(name or ""), str(ip or ""))
        if ip_marker not in seen_ip:
            objects.setdefault("ip_inventory", []).append({
                "device": device,
                "interface": name,
                "name": name,
                "ip": ip,
                "ip_address": ip,
                "status": iface.get("status") or "configured",
                "source": "derived_from_interface_block",
                "evidence": evidence,
            })
            seen_ip.add(ip_marker)
        ep_marker = (str(device or ""), str(name or ""), str(ip or ""))
        if ep_marker not in seen_endpoint:
            objects.setdefault("endpoint_inventory", []).append({
                "device": device,
                "interface": name,
                "ip_address": ip,
                "mac": iface.get("mac"),
                "source": "derived_from_interface_block",
                "evidence": evidence,
            })
            seen_endpoint.add(ep_marker)


def finalize_objects(extractor: Any, objects: Dict[str, Any]) -> Dict[str, Any]:
    objects = merge_unique(blank_objects(), objects or {})
    _dedupe_core_objects(objects)
    extractor.bind_acls_to_interfaces(objects)
    _derive_inventory_from_interfaces(objects)
    objects["dhcp_gateway_matches"] = extractor.match_dhcp_gateways(objects)
    objects["subnet_inventory"] = extractor.derive_subnet_inventory(objects)
    objects["vlan_crosscheck"] = extractor.derive_vlan_crosscheck(objects)

    existing_controls = [row for row in (objects.get("policy_controls") or []) if isinstance(row, dict)]
    derived_controls = [row for row in (extractor.derive_policy_controls(objects) or []) if isinstance(row, dict)]
    seen_controls = {
        (str(row.get("control", "")), str(row.get("detail", "")))
        for row in existing_controls
    }
    for row in derived_controls:
        marker = (str(row.get("control", "")), str(row.get("detail", "")))
        if marker not in seen_controls:
            existing_controls.append(row)
            seen_controls.add(marker)
    objects["policy_controls"] = existing_controls

    existing_risks = [row for row in (objects.get("risk_atoms") or []) if isinstance(row, dict)]
    derived_risks = [row for row in (extractor.derive_risk_atoms(objects) or []) if isinstance(row, dict)]
    seen_risks = {
        (str(row.get("title", "")), str(row.get("why", "")))
        for row in existing_risks
    }
    for row in derived_risks:
        marker = (str(row.get("title", "")), str(row.get("why", "")))
        if marker not in seen_risks:
            existing_risks.append(row)
            seen_risks.add(marker)
    objects["risk_atoms"] = existing_risks

    _dedupe_core_objects(objects)
    objects["coverage_domains"] = extractor.coverage_domains(objects)
    objects["evidence_profile"] = extractor.evidence_profile(objects)
    return objects
