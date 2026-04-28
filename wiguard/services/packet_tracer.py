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
    for token in ["packet tracer", "cisco", "pkt", "pka", "ios", "running-config", "fastethernet", "gigabitethernet", "access-list", "spanning-tree", "port-security", "etherchannel", "ssid", "wlan", "radius", "lldp", "cdp"]:
        if token in lowered:
            markers.append(token)
    return {
        "filename": filename,
        "extension": ext or "unknown",
        "bytes": len(raw or b""),
        "source_mode": source_mode,
        "native_packet_tracer": ext in {".pkt", ".pka"},
        "converter_used": source_mode == "external_xml_converter",
        "printable_lines": _line_count(printable),
        "markers": markers[:12],
        "format_note": (
            "Native Packet Tracer file. Accuracy is highest when PTEXPLORER_PATH is configured or when configs/show outputs are exported as TXT/ZIP."
            if ext in {".pkt", ".pka"} and source_mode == "pkt_binary_recovery"
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
    if source_mode == "pkt_binary_recovery":
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
        {"name": "Cross-layer VLAN consistency", "status": "fail" if (objects.get("vlan_crosscheck", {}) or {}).get("missing_from_trunks") else "pass" if (objects.get("vlan_crosscheck", {}) or {}).get("observed_total") else "review", "score": 0.35 if (objects.get("vlan_crosscheck", {}) or {}).get("missing_from_trunks") else min(1.0, ((objects.get("vlan_crosscheck", {}) or {}).get("observed_total", 0) / 5)), "detail": f"{len((objects.get('vlan_crosscheck', {}) or {}).get('missing_from_trunks', []))} VLAN trunk mismatch candidate(s)."},
        {"name": "Line-level traceability", "status": "pass" if line_ratio >= 0.70 else "review", "score": line_ratio, "detail": f"{_pct(line_ratio)}% of list objects have source-line evidence."},
        {"name": "Native Packet Tracer confidence", "status": "review" if source_mode == "pkt_binary_recovery" else "pass", "score": 0.45 if source_mode == "pkt_binary_recovery" else 0.92, "detail": "Native binary recovery used." if source_mode == "pkt_binary_recovery" else "Structured/text source decoded."},
    ]
    return gates


def build_conversion_profile(filename: str, raw: bytes, text: str, source_mode: str, objects: Dict[str, Any]) -> Dict[str, Any]:
    metadata = detect_packet_tracer_metadata(filename, raw, text, source_mode)
    relationships = build_relationships(objects)
    checklist = build_command_checklist(objects, source_mode)
    gates = build_quality_gates(objects, source_mode)
    weighted_score = sum(float(g.get("score", 0)) for g in gates) / len(gates) if gates else 0
    # Native binary recovery is useful, but must be honestly discounted.
    if source_mode == "pkt_binary_recovery":
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
        },
        "analyst_next_step": _next_step(source_mode, checklist, readiness),
        "coverage_domains": objects.get("coverage_domains", []),
        "vlan_crosscheck": objects.get("vlan_crosscheck", {}),
        "risk_atoms": objects.get("risk_atoms", [])[:80],
        "evidence_profile": objects.get("evidence_profile", {}),
    }


def _next_step(source_mode: str, checklist: Iterable[Dict[str, Any]], readiness: str) -> str:
    if source_mode == "pkt_binary_recovery":
        return "Export configs/show outputs from Packet Tracer and upload them as TXT or ZIP to move from binary recovery to evidence-grade extraction."
    missing = [row.get("command") for row in checklist if row.get("status") == "missing"]
    if missing:
        return "Upload these missing command outputs to increase confidence: " + ", ".join(missing[:4])
    if readiness == "excellent":
        return "Extraction is ready for report generation and evidence verification."
    return "Review low-confidence gates, then re-import a fuller command bundle."
