"""Packet Tracer conversion intelligence helpers.

The real .pkt/.pka binary format is proprietary, so WiGuard treats native Packet
Tracer files as an evidence container: it stores the original safely, attempts
external XML conversion when configured, recovers printable configuration text,
and then grades the extraction so analysts know exactly what was confirmed and
what must be re-uploaded from show commands.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .util import safe_int


INTERFACE_PREFIXES = {
    "fa": "FastEthernet",
    "gi": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "eth": "Ethernet",
    "po": "Port-channel",
    "se": "Serial",
    "lo": "Loopback",
    "vl": "Vlan",
}


def normalize_interface_name(name: str | None) -> str:
    """Normalize common Cisco interface aliases for correlation.

    Packet Tracer exports and show outputs often mix Fa0/1, FastEthernet0/1,
    Gi0/1, GigabitEthernet0/1, VLAN10, and Vlan10. A stable key makes topology
    and line-level evidence correlation much stronger.
    """
    value = str(name or "").strip()
    if not value:
        return ""
    value = value.replace(" ", "")
    patterns = [
        (r"^(FastEthernet|Fa)(.+)$", "FastEthernet"),
        (r"^(GigabitEthernet|Gi)(.+)$", "GigabitEthernet"),
        (r"^(TenGigabitEthernet|Te)(.+)$", "TenGigabitEthernet"),
        (r"^(Ethernet|Eth)(.+)$", "Ethernet"),
        (r"^(Port-channel|Po)(.+)$", "Port-channel"),
        (r"^(Serial|Se)(.+)$", "Serial"),
        (r"^(Loopback|Lo)(.+)$", "Loopback"),
        (r"^(Vlan|VLAN|Vl)(.+)$", "Vlan"),
    ]
    for pattern, prefix in patterns:
        m = re.match(pattern, value, re.I)
        if m:
            return f"{prefix}{m.group(2)}"
    return value


def object_total(objects: Dict[str, Any]) -> int:
    total = 0
    for value in objects.values():
        if isinstance(value, list):
            total += len(value)
        elif isinstance(value, dict):
            for subvalue in value.values():
                if isinstance(subvalue, list):
                    total += len(subvalue)
    return total


def _line_count(text: str) -> int:
    return len([line for line in (text or "").splitlines() if line.strip()])


def _count(objects: Dict[str, Any], key: str) -> int:
    value = objects.get(key)
    return len(value) if isinstance(value, list) else 0


def _routing_count(objects: Dict[str, Any]) -> int:
    routing = objects.get("routing") or {}
    if not isinstance(routing, dict):
        return 0
    return len(routing.get("static_routes", [])) + len(routing.get("protocols", []))


def _pct(value: float) -> int:
    return int(max(0, min(100, round(value * 100))))


def detect_packet_tracer_metadata(filename: str, raw: bytes, text: str, source_mode: str) -> Dict[str, Any]:
    ext = Path(filename or "").suffix.lower()
    printable = text or ""
    lowered = printable.lower()
    markers = []
    for token in ["packet tracer", "native_packet_tracer", "pkt", "pka", "cisco", "ios", "running-config", "fastethernet", "gigabitethernet", "access-list", "spanning-tree", "port-security", "etherchannel", "ssid", "wlan", "radius", "lldp", "cdp"]:
        if token in lowered:
            markers.append(token)
    return {
        "filename": filename,
        "extension": ext or "unknown",
        "bytes": len(raw or b""),
        "source_mode": source_mode,
        "native_packet_tracer": ext in {".pkt", ".pka"},
        "structured_source": source_mode in {"json_structured", "xml_structured", "external_xml_converter", "pkt_auto_xml_json_bridge"},
        "converter_used": source_mode == "external_xml_converter",
        "native_inspector_used": source_mode in {"pkt_native_inspection", "pkt_auto_xml_json_bridge"},
        "auto_xml_json_bridge_used": source_mode == "pkt_auto_xml_json_bridge",
        "printable_lines": _line_count(printable),
        "markers": markers[:12],
        "format_note": (
            "Native Packet Tracer binary was processed through the automatic background path: converter probe → internal XML bridge → normalized JSON → object extraction. Exact proprietary fidelity still depends on exported configs or converter output."
            if ext in {".pkt", ".pka"} and source_mode in {"pkt_binary_recovery", "pkt_native_inspection", "pkt_auto_xml_json_bridge"}
            else "Structured JSON/XML evidence was normalized into devices/interfaces/VLANs/links before policy analysis." if source_mode in {"json_structured", "xml_structured"}
            else "Text/XML/JSON evidence was decoded directly."
        ),
    }


def build_relationships(objects: Dict[str, Any]) -> Dict[str, Any]:
    interface_to_vlan = []
    vlan_to_interfaces: Dict[str, List[str]] = {}
    acl_to_interfaces: Dict[str, List[Dict[str, str]]] = {}
    dhcp_to_vlan = []
    trunk_summary = []

    for iface in objects.get("interfaces", []) or []:
        if not isinstance(iface, dict):
            continue
        name = iface.get("name") or "unknown"
        normalized = normalize_interface_name(name)
        vlans = []
        for key in ["access_vlan", "dot1q_vlan", "native_vlan"]:
            if iface.get(key):
                vlans.append({"type": key, "vlan": str(iface.get(key))})
                vlan_to_interfaces.setdefault(str(iface.get(key)), []).append(normalized or name)
        if iface.get("trunk_allowed_vlans"):
            trunk_summary.append({
                "interface": name,
                "normalized": normalized,
                "allowed_vlans": iface.get("trunk_allowed_vlans")[:80],
                "native_vlan": iface.get("native_vlan"),
                "evidence_line": iface.get("evidence", {}).get("source_line"),
            })
        if vlans:
            interface_to_vlan.append({
                "interface": name,
                "normalized": normalized,
                "mode": iface.get("mode"),
                "vlans": vlans,
                "evidence_line": iface.get("evidence", {}).get("source_line"),
            })
        for key, direction in [("acl_in", "in"), ("acl_out", "out")]:
            if iface.get(key):
                acl_to_interfaces.setdefault(str(iface.get(key)), []).append({
                    "interface": name,
                    "normalized": normalized,
                    "direction": direction,
                })

    for match in objects.get("dhcp_gateway_matches", []) or []:
        if not isinstance(match, dict):
            continue
        dhcp_to_vlan.append({
            "pool": match.get("pool"),
            "cidr": match.get("cidr"),
            "gateway": match.get("default_gateway"),
            "matched_interface": match.get("matched_interface"),
            "matched_vlan": match.get("matched_vlan"),
            "status": match.get("status"),
            "confidence": match.get("confidence"),
        })

    for trunk in objects.get("trunk_operational", []) or []:
        if not isinstance(trunk, dict):
            continue
        trunk_summary.append({
            "interface": trunk.get("interface"),
            "normalized": trunk.get("normalized_interface"),
            "allowed_vlans": trunk.get("allowed_vlans") or [],
            "active_vlans": trunk.get("active_vlans") or [],
            "forwarding_vlans": trunk.get("forwarding_vlans") or [],
            "native_vlan": trunk.get("native_vlan"),
            "operational_status": trunk.get("status"),
            "evidence_line": trunk.get("evidence", {}).get("source_line"),
        })

    return {
        "interface_to_vlan": interface_to_vlan,
        "vlan_to_interfaces": vlan_to_interfaces,
        "acl_to_interfaces": acl_to_interfaces,
        "dhcp_to_vlan": dhcp_to_vlan,
        "trunks": trunk_summary,
    }


def build_command_checklist(objects: Dict[str, Any], source_mode: str) -> List[Dict[str, Any]]:
    checks = [
        ("show running-config", _count(objects, "interfaces") > 0 and _count(objects, "vlans") > 0, "Core configuration, interfaces, VLANs, ACLs, DHCP and routing."),
        ("show vlan brief", _count(objects, "vlans") > 0, "Confirms VLAN IDs, names, status, and switchport hints."),
        ("show interfaces trunk", any((i.get("mode") == "trunk" or i.get("trunk_allowed_vlans")) for i in objects.get("interfaces", []) if isinstance(i, dict)), "Confirms real trunk membership and allowed VLAN list."),
        ("show ip interface brief", _count(objects, "ip_inventory") > 0 or any(i.get("ip_address") for i in objects.get("interfaces", []) if isinstance(i, dict)), "Confirms L3 interfaces, IP addresses, and up/down state."),
        ("show access-lists", _count(objects, "acl_rules") > 0, "Confirms segmentation rules and deny/permit enforcement."),
        ("show cdp neighbors detail", _count(objects, "cdp_links") > 0, "Confirms physical adjacency and topology edges."),
        ("show spanning-tree", _count(objects, "spanning_tree") > 0, "Confirms blocked/forwarding ports and L2 loop protection."),
        ("show port-security interface", _count(objects, "port_security") > 0, "Confirms secure MAC limits, violations, and sticky MAC behavior."),
        ("show etherchannel summary", _count(objects, "etherchannels") > 0, "Confirms bundle health for uplinks and redundant paths."),
        ("show lldp neighbors detail", _count(objects, "lldp_links") > 0, "Confirms non-CDP physical adjacency and multi-vendor topology edges."),
        ("show interfaces status", _count(objects, "interface_status") > 0, "Confirms access/trunk port operational status, VLAN placement, duplex, and speed."),
        ("show ip route", _count(objects, "route_table") > 0 or _routing_count(objects) > 0, "Confirms L3 forwarding, default routes, and protocol-learned paths."),
        ("show inventory / show version", _count(objects, "device_inventory") > 0 or _count(objects, "device_facts") > 0, "Confirms platform/model/IOS evidence for device identity."),
        ("show running-config | include aaa|username|snmp|transport|http", _count(objects, "security_hardening") > 0, "Confirms management-plane hardening and weak-service exposure."),
        ("show interfaces counters/errors", _count(objects, "interface_counters") > 0, "Confirms physical-layer stability, CRC/input/output errors, drops and link health."),
        ("show access-lists with counters", _count(objects, "acl_hit_counts") > 0, "Confirms whether segmentation rules are receiving runtime traffic matches."),
        ("show spanning-tree root", _count(objects, "stp_root") > 0, "Confirms root bridge, root ports, and L2 forwarding design."),
        ("show protocols / routing protocol summary", _count(objects, "protocol_summary") > 0, "Confirms active L3/NAT/DHCP/HSRP/routing protocol evidence."),
    ]
    result = []
    for command, ok, why in checks:
        result.append({
            "command": command,
            "status": "covered" if ok else "missing",
            "severity": "Info" if ok else ("High" if command in {"show running-config", "show access-lists"} else "Medium"),
            "why": why,
        })
    if _count(objects, "access_tests"):
        result.insert(0, {
            "command": "Packet Tracer lab results matrix",
            "status": "covered",
            "severity": "Info",
            "why": f"{_count(objects, 'access_tests')} observed access test(s), {_count(objects, 'client_access_matrix')} client summary row(s), and {_count(objects, 'roaming_events')} roaming event(s) were normalized.",
        })
        result.insert(1, {
            "command": "Expected access-policy baseline",
            "status": "covered" if any(row.get("expected_result") for row in objects.get("access_tests", []) if isinstance(row, dict)) else "recommended",
            "severity": "Medium",
            "why": "Add expected_result / policy_expected to each row to let WiGuard judge observed Success/Failed as compliant or non-compliant, not only observed.",
        })
    if source_mode in {"pkt_binary_recovery", "pkt_native_inspection", "pkt_auto_xml_json_bridge"}:
        result.insert(0, {
            "command": "Export Packet Tracer device configs as TXT or ZIP",
            "status": "recommended",
            "severity": "High",
            "why": "Native .pkt/.pka binary recovery can miss structured fields; exported configs raise confidence dramatically.",
        })
    return result


def build_quality_gates(objects: Dict[str, Any], source_mode: str) -> List[Dict[str, Any]]:
    evidence_profile = objects.get("evidence_profile", {}) or {}
    line_ratio = float(evidence_profile.get("line_mapping_ratio", 0) or 0)
    gates = [
        {"name": "Device identity", "status": "pass" if _count(objects, "devices") else "fail", "score": 1.0 if _count(objects, "devices") else 0.0, "detail": f"{_count(objects, 'devices')} device node(s) extracted."},
        {"name": "Interface coverage", "status": "pass" if _count(objects, "interfaces") >= 3 else "review", "score": min(1.0, _count(objects, "interfaces") / 8), "detail": f"{_count(objects, 'interfaces')} interface block(s)/hint(s) extracted."},
        {"name": "VLAN coverage", "status": "pass" if _count(objects, "vlans") else "fail", "score": min(1.0, _count(objects, "vlans") / 5), "detail": f"{_count(objects, 'vlans')} VLAN object(s) extracted."},
        {"name": "Security policy coverage", "status": "pass" if _count(objects, "acl_rules") else "review", "score": min(1.0, _count(objects, "acl_rules") / 10), "detail": f"{_count(objects, 'acl_rules')} ACL rule(s) extracted."},
        {"name": "Topology evidence", "status": "pass" if (_count(objects, "cdp_links") + _count(objects, "lldp_links")) else "review", "score": min(1.0, (_count(objects, "cdp_links") + _count(objects, "lldp_links")) / 4), "detail": f"{_count(objects, 'cdp_links') + _count(objects, 'lldp_links')} CDP/LLDP edge(s) extracted."},
        {"name": "Operational state coverage", "status": "pass" if _count(objects, "interface_status") or _count(objects, "trunk_operational") else "review", "score": min(1.0, (_count(objects, "interface_status") + _count(objects, "trunk_operational")) / 8), "detail": f"{_count(objects, 'interface_status')} interface status and {_count(objects, 'trunk_operational')} trunk operation row(s)."},
        {"name": "Security hardening extraction", "status": "pass" if _count(objects, "security_hardening") else "review", "score": min(1.0, _count(objects, "security_hardening") / 8), "detail": f"{_count(objects, 'security_hardening')} management-plane hardening indicator(s)."},
        {"name": "Policy control mapping", "status": "pass" if _count(objects, "policy_controls") else "review", "score": min(1.0, _count(objects, "policy_controls") / 5), "detail": f"{_count(objects, 'policy_controls')} derived control assertion(s)."},
        {"name": "Runtime validation evidence", "status": "pass" if (_count(objects, "acl_hit_counts") + _count(objects, "interface_counters")) else "review", "score": min(1.0, (_count(objects, "acl_hit_counts") + _count(objects, "interface_counters")) / 8), "detail": f"{_count(objects, 'acl_hit_counts')} ACL counter and {_count(objects, 'interface_counters')} interface counter row(s)."},
        {"name": "Structured schema understanding", "status": "pass" if _count(objects, "schema_map") else "review", "score": min(1.0, (_count(objects, "schema_map") + _count(objects, "structured_relationships")) / 10), "detail": f"{_count(objects, 'schema_map')} schema path group(s), {_count(objects, 'structured_relationships')} extracted structured relationship(s), {_count(objects, 'validation_findings')} validation finding(s)."},
        {"name": "Cross-layer VLAN consistency", "status": "fail" if (objects.get("vlan_crosscheck", {}) or {}).get("missing_from_trunks") else "pass" if (objects.get("vlan_crosscheck", {}) or {}).get("observed_total") else "review", "score": 0.35 if (objects.get("vlan_crosscheck", {}) or {}).get("missing_from_trunks") else min(1.0, ((objects.get("vlan_crosscheck", {}) or {}).get("observed_total", 0) / 5)), "detail": f"{len((objects.get('vlan_crosscheck', {}) or {}).get('missing_from_trunks', []))} VLAN trunk mismatch candidate(s)."},
        {"name": "Line-level traceability", "status": "pass" if line_ratio >= 0.70 else "review", "score": line_ratio, "detail": f"{_pct(line_ratio)}% of list objects have source-line evidence."},
        {"name": "Native Packet Tracer confidence", "status": "review" if source_mode == "pkt_binary_recovery" else "pass", "score": 0.45 if source_mode == "pkt_binary_recovery" else 0.92, "detail": "Native binary recovery used." if source_mode == "pkt_binary_recovery" else "Structured/text source decoded."},
    ]
    if _count(objects, "source_conversion_manifest"):
        manifest = (objects.get("source_conversion_manifest") or [{}])[0] if isinstance(objects.get("source_conversion_manifest"), list) else {}
        gates.insert(0, {
            "name": "Universal payload visibility",
            "status": "pass",
            "score": min(1.0, (_count(objects, "source_key_value_index") + _count(objects, "universal_network_facts")) / 120),
            "detail": f"Indexed {manifest.get('total_nodes', 0)} payload node(s), {manifest.get('leaf_values', 0)} leaf value(s), {_count(objects, 'source_key_value_index')} key/value row(s), and {_count(objects, 'universal_network_facts')} network fact candidate(s).",
        })
    if _count(objects, "external_converter_outputs"):
        outputs = objects.get("external_converter_outputs") or []
        gates.insert(0, {
            "name": "External Packet Tracer converter",
            "status": "pass",
            "score": 0.96,
            "detail": f"{len(outputs)} converter XML/JSON output(s) were parsed before WiGuard built the normalized object layer.",
        })
    if _count(objects, "internal_xml_bridge"):
        bridge = (objects.get("internal_xml_bridge") or [{}])[0] if isinstance(objects.get("internal_xml_bridge"), list) else {}
        gates.insert(0, {
            "name": "Internal XML → JSON bridge",
            "status": "pass" if (bridge.get("visible_counts") or {}) or bridge.get("external_converter_outputs") else "review",
            "score": 0.96 if bridge.get("external_converter_outputs") else (min(1.0, sum((bridge.get("visible_counts") or {}).values()) / 24) if isinstance(bridge.get("visible_counts"), dict) else 0.45),
            "detail": f"Bridge generated {bridge.get('xml_bytes', 0)} XML bytes and {bridge.get('normalized_json_bytes', 0)} normalized JSON bytes from visible native/converter evidence.",
        })
    if _count(objects, "native_pkt_profile"):
        native_profile = (objects.get("native_pkt_profile") or [{}])[0] if isinstance(objects.get("native_pkt_profile"), list) else {}
        gates.insert(0, {
            "name": "Native PKT binary inspection",
            "status": "review",
            "score": float(native_profile.get("confidence", 0.42) or 0.42),
            "detail": f"{native_profile.get('recoverability', 'native_binary')} · entropy={native_profile.get('entropy', 'n/a')} · visible strings={native_profile.get('visible_string_count', 0)}. Full config accuracy still requires Packet Tracer export.",
        })
        gates.insert(1, {
            "name": "Native PKT export readiness",
            "status": "fail" if native_profile.get("recoverability") == "opaque_native_binary" else "review",
            "score": 0.25 if native_profile.get("recoverability") == "opaque_native_binary" else 0.55,
            "detail": "Upload exported device configs/show outputs or configure PTEXPLORER_PATH to convert native .pkt/.pka into XML/config evidence.",
        })
    if _count(objects, "companion_exports"):
        gates.insert(0, {
            "name": "Companion export verification",
            "status": "pass",
            "score": 0.94,
            "detail": f"{_count(objects, 'companion_exports')} companion export/config bundle(s) merged with the native Packet Tracer import.",
        })
    if _count(objects, "access_tests"):
        lab_summary = (objects.get("lab_result_summary") or [{}])[0] if isinstance(objects.get("lab_result_summary"), list) else {}
        gates.insert(0, {
            "name": "Lab result matrix coverage",
            "status": "pass",
            "score": min(1.0, _count(objects, "access_tests") / 10),
            "detail": f"{_count(objects, 'access_tests')} access test(s), {lab_summary.get('clients', 0)} client(s), {lab_summary.get('services', 0)} service target(s), and {lab_summary.get('roaming_events', 0)} roaming event(s).",
        })
        gates.insert(1, {
            "name": "Client/SSID/VLAN correlation",
            "status": "pass" if _count(objects, "client_access_matrix") else "review",
            "score": min(1.0, (_count(objects, "endpoint_inventory") + _count(objects, "wireless_hints") + _count(objects, "vlans")) / 12),
            "detail": f"{_count(objects, 'client_access_matrix')} client matrix row(s), {_count(objects, 'wireless_hints')} wireless hint(s), {_count(objects, 'vlans')} VLAN(s).",
        })
    return gates


def build_conversion_profile(filename: str, raw: bytes, text: str, source_mode: str, objects: Dict[str, Any]) -> Dict[str, Any]:
    metadata = detect_packet_tracer_metadata(filename, raw, text, source_mode)
    metadata["internal_xml_bridge_used"] = source_mode in {"pkt_native_inspection", "pkt_auto_xml_json_bridge"} and bool(_count(objects, "internal_xml_bridge"))
    relationships = build_relationships(objects)
    checklist = build_command_checklist(objects, source_mode)
    gates = build_quality_gates(objects, source_mode)
    weighted_score = sum(float(g.get("score", 0)) for g in gates) / len(gates) if gates else 0
    # Native binary recovery is useful, but must be honestly discounted.
    if source_mode in {"pkt_native_inspection", "pkt_auto_xml_json_bridge"}:
        native_profile = (objects.get("native_pkt_profile") or [{}])[0] if isinstance(objects.get("native_pkt_profile"), list) else {}
        companion_verified = any(
            isinstance(row, dict) and row.get("status") == "parsed"
            for row in (objects.get("companion_exports") or [])
        )
        converter_verified = _count(objects, "external_converter_outputs") > 0 or bool(native_profile.get("external_converter_outputs"))
        native_cap = 0.97 if converter_verified else (0.92 if companion_verified else float(native_profile.get("confidence", 0.42) or 0.42))
        core_signal_keys = [
            "devices", "interfaces", "vlans", "acl_rules", "dhcp_scopes",
            "ip_inventory", "endpoint_inventory", "internal_xml_bridge",
            "decoded_payloads", "raw_evidence", "source_key_value_index",
            "universal_network_facts", "source_conversion_manifest",
        ]
        core_hits = sum(1 for key in core_signal_keys if _count(objects, key) > 0)
        evidence_ratio = 0.0
        if isinstance(objects.get("evidence_profile"), dict):
            evidence_ratio = float(objects.get("evidence_profile", {}).get("line_mapping_ratio", 0) or 0)
        native_recovery_score = min(native_cap, 0.24 + (core_hits * 0.055) + min(0.10, evidence_ratio * 0.20))
        weighted_score = min(native_cap, max(weighted_score, native_recovery_score))
    elif source_mode == "pkt_binary_recovery":
        weighted_score = min(weighted_score, 0.68)
    elif source_mode == "external_xml_converter":
        weighted_score = min(0.95, weighted_score + 0.06)
    missing = sum(1 for row in checklist if row.get("status") == "missing")
    readiness = "excellent" if weighted_score >= 0.86 and missing <= 2 else "good" if weighted_score >= 0.70 else "needs_more_evidence"
    return {
        "metadata": metadata,
        "relationships": relationships,
        "command_checklist": checklist,
        "quality_gates": gates,
        "readiness": readiness,
        "readiness_score": round(weighted_score, 3),
        "objects_total": object_total(objects),
        "high_value_objects": {
            "devices": _count(objects, "devices"),
            "interfaces": _count(objects, "interfaces"),
            "vlans": _count(objects, "vlans"),
            "dhcp_scopes": _count(objects, "dhcp_scopes"),
            "acl_rules": _count(objects, "acl_rules"),
            "routing_entries": _routing_count(objects),
            "cdp_links": _count(objects, "cdp_links"),
            "port_security": _count(objects, "port_security"),
            "spanning_tree": _count(objects, "spanning_tree"),
            "etherchannels": _count(objects, "etherchannels"),
            "interface_status": _count(objects, "interface_status"),
            "trunk_operational": _count(objects, "trunk_operational"),
            "route_table": _count(objects, "route_table"),
            "lldp_links": _count(objects, "lldp_links"),
            "security_hardening": _count(objects, "security_hardening"),
            "policy_controls": _count(objects, "policy_controls"),
            "deep_evidence_index": _count(objects, "deep_evidence_index"),
            "vlan_brief": _count(objects, "vlan_brief"),
            "acl_hit_counts": _count(objects, "acl_hit_counts"),
            "interface_counters": _count(objects, "interface_counters"),
            "stp_root": _count(objects, "stp_root"),
            "protocol_summary": _count(objects, "protocol_summary"),
            "risk_atoms": _count(objects, "risk_atoms"),
            "schema_map": _count(objects, "schema_map"),
            "structured_relationships": _count(objects, "structured_relationships"),
            "validation_findings": _count(objects, "validation_findings"),
            "endpoint_inventory": _count(objects, "endpoint_inventory"),
            "access_tests": _count(objects, "access_tests"),
            "client_access_matrix": _count(objects, "client_access_matrix"),
            "service_inventory": _count(objects, "service_inventory"),
            "roaming_events": _count(objects, "roaming_events"),
            "lab_result_summary": _count(objects, "lab_result_summary"),
            "native_pkt_profile": _count(objects, "native_pkt_profile"),
            "native_source_manifest": _count(objects, "native_source_manifest"),
            "binary_evidence_summary": _count(objects, "binary_evidence_summary"),
            "binary_signatures": _count(objects, "binary_signatures"),
            "native_visible_hints": _count(objects, "native_visible_hints"),
            "internal_xml_bridge": _count(objects, "internal_xml_bridge"),
            "converted_xml_preview": _count(objects, "converted_xml_preview"),
            "normalized_json_preview": _count(objects, "normalized_json_preview"),
            "auto_conversion_pipeline": _count(objects, "auto_conversion_pipeline"),
            "decoded_payloads": _count(objects, "decoded_payloads"),
            "companion_exports": _count(objects, "companion_exports"),
            "external_converter_outputs": _count(objects, "external_converter_outputs"),
            "evidence_registry": _count(objects, "evidence_registry"),
            "source_conversion_manifest": _count(objects, "source_conversion_manifest"),
            "source_payload_tree": _count(objects, "source_payload_tree"),
            "source_key_value_index": _count(objects, "source_key_value_index"),
            "universal_network_facts": _count(objects, "universal_network_facts"),
            "payload_tables": _count(objects, "payload_tables"),
            "universal_xml_preview": _count(objects, "universal_xml_preview"),
            "universal_json_preview": _count(objects, "universal_json_preview"),
        },
        "analyst_next_step": _next_step(source_mode, checklist, readiness),
        "coverage_domains": objects.get("coverage_domains", []),
        "vlan_crosscheck": objects.get("vlan_crosscheck", {}),
        "risk_atoms": objects.get("risk_atoms", [])[:80],
        "evidence_profile": objects.get("evidence_profile", {}),
        "schema_map": objects.get("schema_map", [])[:50],
        "structured_relationships": objects.get("structured_relationships", [])[:100],
        "validation_findings": objects.get("validation_findings", [])[:100],
        "import_warnings": objects.get("import_warnings", [])[:100],
        "structured_summary": objects.get("structured_summary", {}),
        "access_tests": objects.get("access_tests", [])[:200],
        "client_access_matrix": objects.get("client_access_matrix", [])[:80],
        "service_inventory": objects.get("service_inventory", [])[:80],
        "roaming_events": objects.get("roaming_events", [])[:80],
        "lab_result_summary": objects.get("lab_result_summary", [])[:5],
        "native_pkt_profile": objects.get("native_pkt_profile", [])[:2],
        "native_source_manifest": objects.get("native_source_manifest", [])[:5],
        "binary_evidence_summary": objects.get("binary_evidence_summary", [])[:5],
        "binary_signatures": objects.get("binary_signatures", [])[:80],
        "recovered_string_preview": objects.get("recovered_string_preview", [])[:80],
        "native_conversion_guidance": objects.get("native_conversion_guidance", [])[:20],
        "native_visible_hints": objects.get("native_visible_hints", [])[:160],
        "internal_xml_bridge": objects.get("internal_xml_bridge", [])[:5],
        "converted_xml_preview": objects.get("converted_xml_preview", [])[:3],
        "normalized_json_preview": objects.get("normalized_json_preview", [])[:3],
        "auto_conversion_pipeline": objects.get("auto_conversion_pipeline", [])[:20],
        "decoded_payloads": objects.get("decoded_payloads", [])[:80],
        "extraction_fidelity": objects.get("extraction_fidelity", [])[:3],
        "companion_exports": objects.get("companion_exports", [])[:20],
        "external_converter_outputs": objects.get("external_converter_outputs", [])[:20],
        "source_conversion_manifest": objects.get("source_conversion_manifest", [])[:5],
        "source_payload_tree": objects.get("source_payload_tree", [])[:120],
        "source_key_value_index": objects.get("source_key_value_index", [])[:160],
        "universal_network_facts": objects.get("universal_network_facts", [])[:160],
        "payload_tables": objects.get("payload_tables", [])[:60],
        "universal_xml_preview": objects.get("universal_xml_preview", [])[:2],
        "universal_json_preview": objects.get("universal_json_preview", [])[:2],
    }


def _next_step(source_mode: str, checklist: Iterable[Dict[str, Any]], readiness: str) -> str:
    if source_mode in {"pkt_binary_recovery", "pkt_native_inspection", "pkt_auto_xml_json_bridge"}:
        return "Native .pkt/.pka was automatically processed in the background: external converter probe → internal XML bridge → normalized JSON → object extraction. If the source file exposes little internal evidence, configure WIGUARD_PKT_CONVERTER_PATH/PTEXPLORER_PATH or upload exported show outputs/XML/JSON."
    missing = [row.get("command") for row in checklist if row.get("status") == "missing"]
    if missing:
        return "Upload these missing command outputs to increase confidence: " + ", ".join(missing[:4])
    if readiness == "excellent":
        return "Extraction is ready for report generation and evidence verification."
    return "Review low-confidence gates, then re-import a fuller command bundle."
