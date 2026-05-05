"""Targeted Packet Tracer XML/profile extraction helpers.

Many real-world Packet Tracer workflows use external tools that convert `.pkt`
or `.pka` into XML. Those XML files are not standardized: some expose nodes,
ports, links, VLANs, and configs as attributes; others use nested child tags.
The generic JSON/XML normalizer keeps every payload visible, but this module adds
a stricter topology-focused pass so converter XML produces real devices,
interfaces, VLANs, links, and embedded CLI text whenever the evidence is present.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from xml.etree import ElementTree as ET

from .packet_tracer import normalize_interface_name
from .structured_import import blank_objects, merge_unique

MAX_XML_PROFILE_ROWS = 2000
DEVICE_TAG_HINTS = ("device", "node", "router", "switch", "pc", "server", "accesspoint", "access_point", "ap", "wlc", "firewall")
INTERFACE_TAG_HINTS = ("interface", "port", "adapter", "nic", "moduleport", "connectionpoint")
LINK_TAG_HINTS = ("link", "connection", "cable", "edge", "wire")
CONFIG_TAG_HINTS = ("config", "runningconfig", "startupconfig", "cli", "command", "showoutput", "text")


def _strip_ns(tag: Any) -> str:
    return str(tag or "").split("}")[-1]


def _token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _clean(value: Any, limit: int = 500) -> str | None:
    if value in (None, "", [], {}):
        return None
    text = str(value).strip()
    if not text:
        return None
    return "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)[:limit]


def _first(record: Dict[str, Any], keys: List[str]) -> Any:
    lower = {_token(k): k for k in record.keys()}
    for key in keys:
        actual = lower.get(_token(key))
        if actual is not None and record.get(actual) not in (None, "", [], {}):
            return record.get(actual)
    return None


def _evidence(path: str, record: Dict[str, Any], confidence: float = 0.78) -> Dict[str, Any]:
    preview = ", ".join(f"{k}={_clean(v, 80)}" for k, v in list(record.items())[:12] if _clean(v, 80))
    return {"source_line": None, "source_path": path, "source_text": preview[:900], "confidence": confidence}


def _element_record(elem: ET.Element) -> Dict[str, Any]:
    record: Dict[str, Any] = {"tag": _strip_ns(elem.tag)}
    for key, value in elem.attrib.items():
        record[_strip_ns(key)] = value
    text = _clean(elem.text, 4000)
    if text:
        record["text"] = text
    # Include immediate child leaves and child attributes using stable names.
    tag_counts: Dict[str, int] = {}
    for child in list(elem):
        ctag = _strip_ns(child.tag)
        tag_counts[ctag] = tag_counts.get(ctag, 0) + 1
        suffix = "" if tag_counts[ctag] == 1 else f"_{tag_counts[ctag]}"
        ctext = _clean(child.text, 4000)
        if ctext and ctag not in record:
            record[ctag] = ctext
        for key, value in child.attrib.items():
            record[f"{ctag}{suffix}_{_strip_ns(key)}"] = value
    return record


def _looks_like_ios_text(text: str | None) -> bool:
    if not text:
        return False
    sample = text.lower()
    return any(token in sample for token in [
        "hostname ", "interface ", "switchport", "ip address", "ip route",
        "router ospf", "access-list", "ip access-list", "vlan ", "ip dhcp pool",
        "show running-config", "show vlan", "show interfaces", "line vty",
    ])


def _device_name(record: Dict[str, Any]) -> str | None:
    return _clean(_first(record, [
        "hostname", "hostName", "deviceName", "displayName", "label", "name",
        "nodeName", "sysName", "id", "uuid", "objectId",
    ]), 160)


def _device_type(record: Dict[str, Any], tag_hint: str = "") -> str | None:
    dtype = _clean(_first(record, ["type", "deviceType", "model", "platform", "class", "kind", "category"]), 120)
    if dtype:
        return dtype
    for hint in ["router", "switch", "firewall", "server", "accesspoint", "ap", "pc", "wlc"]:
        if hint in tag_hint:
            return "access point" if hint == "accesspoint" else hint
    return None


def _walk(elem: ET.Element, path: str, ancestors: List[Dict[str, Any]], rows: List[Tuple[str, Dict[str, Any], List[Dict[str, Any]]]]) -> None:
    if len(rows) >= MAX_XML_PROFILE_ROWS:
        return
    record = _element_record(elem)
    rows.append((path, record, ancestors))
    next_ancestors = ancestors + [record]
    for idx, child in enumerate(list(elem)):
        _walk(child, f"{path}/{_strip_ns(child.tag)}[{idx}]", next_ancestors, rows)


def _ancestor_device(ancestors: List[Dict[str, Any]]) -> str | None:
    for rec in reversed(ancestors):
        name = _device_name(rec)
        tag = _token(rec.get("tag"))
        if name and any(h in tag for h in DEVICE_TAG_HINTS):
            return name
    for rec in reversed(ancestors):
        name = _device_name(rec)
        if name:
            return name
    return None


def _resolve_device_ref(value: Any, id_to_name: Dict[str, str]) -> str | None:
    text = _clean(value, 160)
    if not text:
        return None
    return id_to_name.get(text, text)


def extract_packet_tracer_xml_objects(xml_text: str, source_name: str = "packet_tracer_xml") -> Tuple[Dict[str, Any], str, Dict[str, Any]]:
    """Extract topology objects from non-standard Packet Tracer converter XML.

    Returns `(objects, embedded_cli_text, summary)`. It never raises for bad XML;
    callers can merge the returned objects with the generic normalizer safely.
    """
    objects = blank_objects()
    text_chunks: List[str] = []
    summary = {
        "source": source_name,
        "status": "empty",
        "records_walked": 0,
        "devices": 0,
        "interfaces": 0,
        "vlans": 0,
        "links": 0,
        "embedded_cli_chunks": 0,
    }
    try:
        root = ET.fromstring(xml_text or "")
    except Exception as exc:
        summary.update({"status": "xml_parse_failed", "error": str(exc)[:500]})
        objects["import_warnings"].append({"severity": "High", "title": "Packet Tracer XML profile parse failed", "detail": str(exc)[:500]})
        return objects, "", summary

    rows: List[Tuple[str, Dict[str, Any], List[Dict[str, Any]]]] = []
    _walk(root, f"/{_strip_ns(root.tag)}", [], rows)
    summary["records_walked"] = len(rows)

    # Build a resolver table first so topology links that reference node ids
    # display human device names (R1/SW1) instead of raw converter ids (n1/n2).
    id_to_name: Dict[str, str] = {}
    for path, record, ancestors in rows:
        tag_hint = _token(record.get("tag"))
        keys_blob = " ".join(_token(k) for k in record.keys())
        is_container_tag = tag_hint in {"devices", "nodes", "interfaces", "ports", "vlans", "links", "connections", "cables"}
        name = _device_name(record)
        is_device_context = (not is_container_tag) and (any(h in tag_hint for h in DEVICE_TAG_HINTS) or any(h in keys_blob for h in ["devicename", "hostname", "nodename", "model", "platform"]))
        if name and is_device_context:
            for ref_key in ["id", "uuid", "objectId", "nodeId", "deviceId", "name", "hostname", "deviceName", "nodeName"]:
                ref = _clean(_first(record, [ref_key]), 160)
                if ref:
                    id_to_name[ref] = name

    for path, record, ancestors in rows:
        tag_hint = _token(record.get("tag"))
        is_container_tag = tag_hint in {"devices", "nodes", "interfaces", "ports", "vlans", "links", "connections", "cables"}
        keys_blob = " ".join(_token(k) for k in record.keys())
        ev = _evidence(path, record)

        # Embedded config/show text: feed it to ConfigExtractor later.
        for key in ["text", "config", "runningConfig", "startupConfig", "cli", "commands", "showOutput", "configuration"]:
            value = _clean(record.get(key), 20000)
            if value and (_looks_like_ios_text(value) or any(h in tag_hint for h in CONFIG_TAG_HINTS)):
                text_chunks.append(f"! packet-tracer-xml-profile: {path}\n{value}")
                objects["raw_evidence"].append({"name": key, "source": source_name, "preview": value[:1200], "evidence": ev})
                break

        # Devices / nodes.
        name = _device_name(record)
        dtype = _device_type(record, tag_hint)
        is_device_context = (not is_container_tag) and (any(h in tag_hint for h in DEVICE_TAG_HINTS) or any(h in keys_blob for h in ["devicename", "hostname", "nodename", "model", "platform"]))
        if name and is_device_context:
            converter_id = _clean(_first(record, ["id", "uuid", "objectId", "nodeId", "deviceId"]), 160)
            objects["devices"].append({
                # Use the human hostname as the canonical id so generic structured
                # extraction and the targeted XML profile merge cleanly. Preserve
                # the converter/native id separately for evidence traceability.
                "id": name,
                "hostname": name,
                "converter_id": converter_id if converter_id and converter_id != name else None,
                "type": dtype or "network-device",
                "role": _clean(_first(record, ["role", "function", "category"]), 120) or "xml_topology",
                "model": _clean(_first(record, ["model", "platform", "pid"]), 140),
                "source": "packet_tracer_xml_profile",
                "evidence": ev,
            })

        # Interfaces / ports.
        iface_name = _clean(_first(record, [
            "interface", "interfaceName", "ifName", "port", "portName", "name",
            "label", "slotPort", "localInterface", "remoteInterface",
        ]), 160)
        is_iface_context = (not is_container_tag) and (any(h in tag_hint for h in INTERFACE_TAG_HINTS) or any(h in keys_blob for h in ["interfacename", "ifname", "portname", "macaddress"]))
        if iface_name and is_iface_context:
            vlan = _clean(_first(record, ["vlan", "vlanId", "accessVlan", "nativeVlan", "pvid"]), 40)
            ip = _clean(_first(record, ["ip", "ipAddress", "address", "ipv4", "gateway"]), 80)
            mask = _clean(_first(record, ["mask", "subnetMask", "netmask"]), 80)
            mode = _clean(_first(record, ["mode", "switchportMode", "portMode", "encapsulation"]), 80)
            objects["interfaces"].append({
                "device": _ancestor_device(ancestors),
                "name": iface_name,
                "normalized_name": normalize_interface_name(iface_name),
                "description": _clean(_first(record, ["description", "desc"]), 220),
                "mode": mode or ("access" if vlan else None),
                "access_vlan": vlan,
                "native_vlan": _clean(_first(record, ["nativeVlan", "native_vlan"]), 40),
                "ip_address": ip if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) else None,
                "subnet_mask": mask,
                "mac": _clean(_first(record, ["mac", "macAddress", "addressMac"]), 80),
                "status": _clean(_first(record, ["status", "state", "linkStatus"]), 80),
                "source": "packet_tracer_xml_profile",
                "evidence": ev,
            })

        # VLANs.
        vlan_value = _clean(_first(record, ["vlan", "vlanId", "vlan_id", "vid", "id", "number"]), 40)
        is_vlan_context = (not is_container_tag) and ("vlan" in tag_hint or "vlan" in keys_blob or "vid" in keys_blob)
        if vlan_value and is_vlan_context:
            match = re.search(r"\d{1,4}", vlan_value)
            if match and 1 <= int(match.group(0)) <= 4094:
                vlan_id = match.group(0)
                objects["vlans"].append({
                    "id": vlan_id,
                    "name": _clean(_first(record, ["name", "vlanName", "label"]), 120) or f"VLAN_{vlan_id}",
                    "status": _clean(_first(record, ["status", "state"]), 80),
                    "source": "packet_tracer_xml_profile",
                    "evidence": ev,
                })

        # Links / cables / edges.
        is_link_context = (not is_container_tag) and (any(h in tag_hint for h in LINK_TAG_HINTS) or any(h in keys_blob for h in ["source", "target", "from", "to", "endpoint", "remoteport"]))
        if is_link_context:
            src = _resolve_device_ref(_first(record, ["source", "src", "from", "sourceDevice", "sourceNode", "source_node", "sourceNodeId", "source_nodeId", "source_node_id", "deviceA", "nodeA", "localDevice"]), id_to_name)
            dst = _resolve_device_ref(_first(record, ["target", "dst", "to", "targetDevice", "targetNode", "target_node", "targetNodeId", "target_nodeId", "target_node_id", "deviceB", "nodeB", "remoteDevice", "neighbor"]), id_to_name)
            local_int = _clean(_first(record, ["sourceInterface", "sourcePort", "source_port", "localInterface", "localPort", "portA", "interfaceA"]), 160)
            remote_int = _clean(_first(record, ["targetInterface", "targetPort", "target_port", "remoteInterface", "remotePort", "portB", "interfaceB"]), 160)
            if src and dst and src != dst:
                objects["cdp_links"].append({
                    "device": src,
                    "neighbor": dst,
                    "local_interface": local_int,
                    "remote_interface": remote_int,
                    "platform": _clean(_first(record, ["type", "cableType", "media"]), 100),
                    "source": "packet_tracer_xml_profile",
                    "evidence": ev,
                })
                objects["structured_relationships"].append({"type": "link", "a": src, "b": dst, "a_port": local_int, "b_port": remote_int, "evidence": ev})

    # De-duplicate through merge_unique by merging into a fresh object skeleton.
    cleaned = blank_objects()
    cleaned = merge_unique(cleaned, objects)
    summary.update({
        "status": "understood" if any(cleaned.get(k) for k in ["devices", "interfaces", "vlans", "cdp_links"]) or text_chunks else "no_topology_profile_detected",
        "devices": len(cleaned.get("devices", []) or []),
        "interfaces": len(cleaned.get("interfaces", []) or []),
        "vlans": len(cleaned.get("vlans", []) or []),
        "links": len(cleaned.get("cdp_links", []) or []),
        "embedded_cli_chunks": len(text_chunks),
    })
    if summary["status"] == "no_topology_profile_detected":
        cleaned["import_warnings"].append({
            "severity": "Medium",
            "title": "Packet Tracer XML profile found no concrete topology objects",
            "detail": "The XML parsed, but no device/interface/VLAN/link profile matched common Packet Tracer converter schemas. The universal payload index still preserves the raw XML paths.",
        })
    cleaned["schema_map"].append({
        "object_type": "packet_tracer_xml_profile",
        "count": summary["records_walked"],
        "paths": [{"path": summary["source"], "count": summary["records_walked"]}],
        "evidence": {"source_path": summary["source"], "source_text": str(summary), "confidence": 0.72},
    })
    return cleaned, "\n\n".join(text_chunks), summary
