"""Evidence registry and verified extraction contract helpers.

These helpers keep Packet Tracer extraction honest: every object is classified as
verified, recovered, inferred, or unmapped based on the evidence actually carried
by that object.  The native .pkt format remains proprietary, so native recovery
is never labeled as full-fidelity unless a companion export/converter payload is
present and parsed.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List


CORE_OBJECT_KEYS = {
    "devices", "vlans", "interfaces", "dhcp_scopes", "dhcp_excluded",
    "acl_rules", "nat_rules", "cdp_links", "lldp_links", "services",
    "ip_inventory", "interface_status", "trunk_operational", "route_table",
    "ospf_neighbors", "port_security", "spanning_tree", "etherchannels",
    "mac_table", "arp_table", "device_facts", "device_inventory",
    "security_hardening", "wireless_hints", "vlan_brief", "acl_hit_counts",
    "interface_counters", "stp_root", "protocol_summary", "command_blocks",
    "deep_evidence_index", "raw_evidence", "dhcp_gateway_matches",
    "subnet_inventory", "policy_controls", "risk_atoms", "coverage_domains",
    "schema_map", "import_warnings", "structured_relationships",
    "validation_findings", "endpoint_inventory", "access_tests",
    "client_access_matrix", "service_inventory", "roaming_events",
    "lab_result_summary", "native_pkt_profile", "binary_signatures",
    "recovered_string_preview", "native_conversion_guidance",
    "native_visible_hints", "internal_xml_bridge", "converted_xml_preview",
    "normalized_json_preview", "auto_conversion_pipeline", "decoded_payloads",
    "extraction_fidelity", "printable_segments_preview",
    "reconstructed_config_preview", "companion_exports",
}

HIGH_VALUE_KEYS = {
    "devices", "interfaces", "vlans", "dhcp_scopes", "acl_rules", "routing",
    "route_table", "cdp_links", "lldp_links", "ip_inventory", "endpoint_inventory",
    "interface_status", "trunk_operational", "port_security", "spanning_tree",
    "etherchannels", "mac_table", "arp_table", "wireless_hints",
}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evidence(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    ev = item.get("evidence")
    return ev if isinstance(ev, dict) else {}


def _object_name(category: str, obj: Dict[str, Any], idx: int) -> str:
    for key in (
        "hostname", "id", "name", "interface", "normalized_interface", "vlan",
        "ip_address", "acl", "acl_name", "pool", "service", "target", "neighbor",
        "control", "title", "stage", "type", "source", "line",
    ):
        value = obj.get(key)
        if value not in (None, "", []):
            return str(value)[:180]
    return f"{category}[{idx}]"


def _source_type(ev: Dict[str, Any], obj: Dict[str, Any]) -> str:
    if ev.get("source_line"):
        return "line"
    if ev.get("source_path"):
        return "path"
    if obj.get("path"):
        return "path"
    if obj.get("line") or obj.get("source_line"):
        return "line"
    if obj.get("offset") is not None:
        return "offset"
    if obj.get("source"):
        return "derived"
    return "unmapped"


def _evidence_status(category: str, ev: Dict[str, Any], obj: Dict[str, Any]) -> str:
    confidence = float(ev.get("confidence", obj.get("confidence", 0.0)) or 0.0)
    source = str(obj.get("source") or ev.get("source") or "").lower()
    if ev.get("source_line") or ev.get("source_path") or obj.get("path"):
        return "verified" if confidence >= 0.78 else "recovered"
    if category in {"native_visible_hints", "recovered_string_preview", "decoded_payloads", "printable_segments_preview", "reconstructed_config_preview", "internal_xml_bridge"}:
        return "recovered"
    if "native" in source or "reconstructed" in source or obj.get("offset") is not None:
        return "recovered"
    if category in {"policy_controls", "risk_atoms", "coverage_domains", "dhcp_gateway_matches", "subnet_inventory", "validation_findings"}:
        return "inferred"
    return "unmapped"


def build_evidence_registry(objects: Dict[str, Any], *, limit: int = 3000) -> List[Dict[str, Any]]:
    registry: List[Dict[str, Any]] = []
    for category, value in (objects or {}).items():
        if category in {"evidence_registry", "verified_extraction_contract", "packet_tracer_profile"}:
            continue
        if isinstance(value, dict):
            iterable: Iterable[Any] = []
            if category == "routing":
                rows = []
                for subkey, subval in value.items():
                    if isinstance(subval, list):
                        for item in subval:
                            if isinstance(item, dict):
                                rows.append({**item, "routing_section": subkey})
                iterable = rows
            else:
                iterable = []
        elif isinstance(value, list):
            iterable = value
        else:
            continue
        for idx, item in enumerate(iterable, start=1):
            if not isinstance(item, dict):
                continue
            ev = _evidence(item)
            status = _evidence_status(category, ev, item)
            source_type = _source_type(ev, item)
            source_text = ev.get("source_text") or item.get("text") or item.get("line") or item.get("preview") or item.get("detail") or item.get("note") or ""
            row = {
                "id": f"{category}:{idx}",
                "category": category,
                "name": _object_name(category, item, idx),
                "status": status,
                "source_type": source_type,
                "source_line": ev.get("source_line") or item.get("source_line") or item.get("line"),
                "source_path": ev.get("source_path") or item.get("path"),
                "source_text": str(source_text)[:500],
                "confidence": round(float(ev.get("confidence", item.get("confidence", 0.50)) or 0.50), 3),
                "high_value": category in HIGH_VALUE_KEYS,
            }
            registry.append(row)
            if len(registry) >= limit:
                return registry
    return registry


def summarize_evidence_registry(registry: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {"total": len(registry), "verified": 0, "recovered": 0, "inferred": 0, "unmapped": 0, "high_value_verified": 0, "high_value_total": 0}
    for row in registry:
        status = row.get("status") if row.get("status") in summary else "unmapped"
        summary[status] += 1
        if row.get("high_value"):
            summary["high_value_total"] += 1
            if status == "verified":
                summary["high_value_verified"] += 1
    total = summary["total"] or 1
    high_total = summary["high_value_total"] or 1
    summary["verified_ratio"] = round(summary["verified"] / total, 3)
    summary["high_value_verified_ratio"] = round(summary["high_value_verified"] / high_total, 3)
    return summary


def build_companion_export_plan(objects: Dict[str, Any], source_mode: str) -> List[Dict[str, Any]]:
    def count(key: str) -> int:
        return len(_safe_list((objects or {}).get(key)))

    native = source_mode in {"pkt_auto_xml_json_bridge", "pkt_native_inspection", "pkt_binary_recovery"}
    plan = [
        ("running-config", count("interfaces") > 0 and (count("vlans") > 0 or count("acl_rules") > 0), "Export/copy running-config for every router/switch.", "High"),
        ("show vlan brief", count("vlans") > 0 or count("vlan_brief") > 0, "Confirms VLAN names, status, and access-port membership.", "High"),
        ("show interfaces trunk", count("trunk_operational") > 0 or any(i.get("trunk_allowed_vlans") for i in _safe_list((objects or {}).get("interfaces"))), "Confirms trunk state, allowed VLANs, and native VLAN.", "High"),
        ("show ip interface brief", count("ip_inventory") > 0 or count("interface_status") > 0, "Confirms L3 interface IPs and operational state.", "Medium"),
        ("show access-lists", count("acl_rules") > 0 or count("acl_hit_counts") > 0, "Confirms ACL contents and live hit counters.", "High"),
        ("show cdp/lldp neighbors detail", count("cdp_links") + count("lldp_links") > 0, "Confirms physical adjacency and cable/path edges.", "Medium"),
        ("show spanning-tree", count("spanning_tree") > 0 or count("stp_root") > 0, "Confirms L2 root/blocked/forwarding state.", "Low"),
    ]
    rows = []
    for name, ok, why, severity in plan:
        rows.append({
            "artifact": name,
            "status": "covered" if ok else ("required_for_full_fidelity" if native else "recommended"),
            "severity": "Info" if ok else severity,
            "why": why,
        })
    return rows


def build_verified_extraction_contract(objects: Dict[str, Any], source_mode: str, registry: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    registry = registry if registry is not None else build_evidence_registry(objects)
    summary = summarize_evidence_registry(registry)
    native_profile = (_safe_list((objects or {}).get("native_pkt_profile")) or [{}])[0]
    fidelity = (_safe_list((objects or {}).get("extraction_fidelity")) or [{}])[0]
    companion_rows = _safe_list((objects or {}).get("companion_exports"))
    has_companion = any(row.get("status") == "parsed" for row in companion_rows if isinstance(row, dict))
    source_mode = source_mode or "unknown"
    native = source_mode in {"pkt_auto_xml_json_bridge", "pkt_native_inspection", "pkt_binary_recovery"}

    if has_companion and native:
        tier = "native_plus_companion_export"
        claim = "Verified where companion export supplies config/XML/JSON evidence; native-only fields remain recovered."
        can_claim_full = summary["high_value_verified_ratio"] >= 0.70
    elif source_mode in {"json_structured", "xml_structured", "text_config", "zip_text", "external_xml_converter"}:
        tier = "verified_export_parse"
        claim = "Structured/exported evidence parsed directly; confidence depends on object evidence mapping."
        can_claim_full = summary["high_value_verified_ratio"] >= 0.70
    elif native:
        recoverability = str(native_profile.get("recoverability") or fidelity.get("tier") or "native_binary")
        if recoverability == "opaque_native_binary":
            tier = "opaque_native_binary"
        elif summary["high_value_verified_ratio"] >= 0.45 or float(fidelity.get("score", 0) or 0) >= 0.65:
            tier = "strong_native_recovery"
        else:
            tier = "partial_native_recovery"
        claim = "Native Packet Tracer recovery is best-effort because .pkt/.pka is proprietary; upload companion exports for full-fidelity claims."
        can_claim_full = False
    else:
        tier = "partial_visible_recovery"
        claim = "Parsed visible evidence; upload fuller exports to raise traceability."
        can_claim_full = False

    return {
        "tier": tier,
        "can_claim_full_fidelity": bool(can_claim_full),
        "claim": claim,
        "source_mode": source_mode,
        "evidence_summary": summary,
        "companion_export_present": bool(has_companion),
        "companion_exports": companion_rows,
        "native_recoverability": native_profile.get("recoverability"),
        "native_confidence": native_profile.get("confidence") or fidelity.get("score"),
        "required_next_exports": build_companion_export_plan(objects, source_mode),
    }
