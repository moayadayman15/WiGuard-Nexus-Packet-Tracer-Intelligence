from .util import now_iso, network_cidr
from .wireless import wireless_dashboard, wireless_risk_score
from .compliance import build_compliance_matrix




EXTRACTED_LIST_KEYS = {
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
    "validation_findings", "endpoint_inventory",
    "access_tests", "client_access_matrix", "service_inventory",
    "roaming_events", "lab_result_summary",
    "native_pkt_profile", "binary_signatures", "recovered_string_preview",
    "native_conversion_guidance", "native_visible_hints", "internal_xml_bridge",
    "converted_xml_preview", "normalized_json_preview", "auto_conversion_pipeline",
    "decoded_payloads", "extraction_fidelity", "printable_segments_preview",
    "reconstructed_config_preview", "evidence_registry", "verified_extraction_contract",
    "companion_exports",
}

def _safe_list(value):
    """Return a list only when the stored value is actually a list.

    Imported workspaces can contain partial/corrupted parser output while a user is
    iterating on Packet Tracer evidence. Intelligence builders should degrade
    gracefully instead of taking the whole Flask page down.
    """
    return value if isinstance(value, list) else []


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _evidence(item):
    if not isinstance(item, dict):
        return {}
    value = item.get("evidence")
    return value if isinstance(value, dict) else {}


def sanitize_objects(objects):
    """Normalize extracted objects for UI/report builders.

    This removes None rows produced by failed/partial imports and replaces
    `evidence: null` with an empty evidence object. It intentionally preserves
    non-list dictionaries like routing/vlan_crosscheck/evidence_profile.
    """
    objects = _safe_dict(objects)
    clean = {}
    for key, value in objects.items():
        if key in EXTRACTED_LIST_KEYS and not isinstance(value, list):
            clean[key] = []
            continue
        if isinstance(value, list):
            rows = []
            for item in value:
                if isinstance(item, dict):
                    item = dict(item)
                    if not isinstance(item.get("evidence"), dict):
                        item["evidence"] = {}
                    rows.append(item)
                elif item is not None and key not in EXTRACTED_LIST_KEYS:
                    rows.append(item)
            clean[key] = rows
        elif value is None:
            clean[key] = {}
        else:
            clean[key] = value
    return clean


def wireless_ssids(state):
    wireless_policy = _safe_dict(state.get("wireless_policy"))
    return [ssid for ssid in _safe_list(wireless_policy.get("ssids")) if isinstance(ssid, dict)]


def get_objects(state):
    active = _safe_dict(state.get("active_extraction"))
    return sanitize_objects(active.get("objects"))


def object_counts(objects):
    objects = sanitize_objects(objects)
    routing = _safe_dict(objects.get("routing"))
    return {
        "devices": len(_safe_list(objects.get("devices"))),
        "interfaces": len(_safe_list(objects.get("interfaces"))),
        "vlans": len(_safe_list(objects.get("vlans"))),
        "dhcp_scopes": len(_safe_list(objects.get("dhcp_scopes"))),
        "acl_rules": len(_safe_list(objects.get("acl_rules"))),
        "routing": len(_safe_list(routing.get("static_routes"))) + len(_safe_list(routing.get("protocols"))),
        "nat_rules": len(_safe_list(objects.get("nat_rules"))),
        "cdp_links": len(_safe_list(objects.get("cdp_links"))),
        "lldp_links": len(_safe_list(objects.get("lldp_links"))),
        "ip_inventory": len(_safe_list(objects.get("ip_inventory"))),
        "interface_status": len(_safe_list(objects.get("interface_status"))),
        "trunk_operational": len(_safe_list(objects.get("trunk_operational"))),
        "route_table": len(_safe_list(objects.get("route_table"))),
        "ospf_neighbors": len(_safe_list(objects.get("ospf_neighbors"))),
        "port_security": len(_safe_list(objects.get("port_security"))),
        "spanning_tree": len(_safe_list(objects.get("spanning_tree"))),
        "etherchannels": len(_safe_list(objects.get("etherchannels"))),
        "mac_table": len(_safe_list(objects.get("mac_table"))),
        "arp_table": len(_safe_list(objects.get("arp_table"))),
        "device_facts": len(_safe_list(objects.get("device_facts"))),
        "device_inventory": len(_safe_list(objects.get("device_inventory"))),
        "security_hardening": len(_safe_list(objects.get("security_hardening"))),
        "wireless_hints": len(_safe_list(objects.get("wireless_hints"))),
        "command_blocks": len(_safe_list(objects.get("command_blocks"))),
        "subnet_inventory": len(_safe_list(objects.get("subnet_inventory"))),
        "policy_controls": len(_safe_list(objects.get("policy_controls"))),
        "deep_evidence_index": len(_safe_list(objects.get("deep_evidence_index"))),
        "raw_evidence": len(_safe_list(objects.get("raw_evidence"))),
        "schema_map": len(_safe_list(objects.get("schema_map"))),
        "structured_relationships": len(_safe_list(objects.get("structured_relationships"))),
        "validation_findings": len(_safe_list(objects.get("validation_findings"))),
        "endpoint_inventory": len(_safe_list(objects.get("endpoint_inventory"))),
        "access_tests": len(_safe_list(objects.get("access_tests"))),
        "client_access_matrix": len(_safe_list(objects.get("client_access_matrix"))),
        "service_inventory": len(_safe_list(objects.get("service_inventory"))),
        "roaming_events": len(_safe_list(objects.get("roaming_events"))),
        "lab_result_summary": len(_safe_list(objects.get("lab_result_summary"))),
    }


def vlan_ids(objects):
    ids = set()
    for v in _safe_list(objects.get("vlans")):
        if v.get("id"):
            ids.add(str(v.get("id")))
    for i in _safe_list(objects.get("interfaces")):
        for key in ["access_vlan", "dot1q_vlan", "native_vlan"]:
            if i.get(key):
                ids.add(str(i[key]))
        for v in i.get("trunk_allowed_vlans", []) or []:
            if str(v).isdigit():
                ids.add(str(v))
    return ids


def dhcp_cidrs(objects):
    return {p["cidr"] for p in _safe_list(objects.get("dhcp_scopes")) if isinstance(p, dict) and p.get("cidr")}


def interfaces_for_vlan(objects, vlan_id):
    vlan_id = str(vlan_id)
    result = []
    for i in _safe_list(objects.get("interfaces")):
        if str(i.get("access_vlan")) == vlan_id or str(i.get("dot1q_vlan")) == vlan_id or str(i.get("native_vlan")) == vlan_id:
            result.append(i)
    return result


def trunk_interfaces(objects):
    return [i for i in _safe_list(objects.get("interfaces")) if isinstance(i, dict) and (i.get("mode") == "trunk" or i.get("trunk_allowed_vlans"))]


def trunk_carries_vlan(interface, vlan_id):
    allowed = [str(x) for x in interface.get("trunk_allowed_vlans", [])]
    return "all" in allowed or str(vlan_id) in allowed


def find_vlan_line(objects, vlan_id):
    for v in _safe_list(objects.get("vlans")):
        if str(v.get("id")) == str(vlan_id):
            return _evidence(v).get("source_line")
    for i in _safe_list(objects.get("interfaces")):
        if str(i.get("access_vlan")) == str(vlan_id) or str(i.get("dot1q_vlan")) == str(vlan_id) or str(i.get("native_vlan")) == str(vlan_id):
            return _evidence(i).get("source_line")
        if str(vlan_id) in [str(x) for x in i.get("trunk_allowed_vlans", [])]:
            return _evidence(i).get("source_line")
    return None


def find_dhcp_line(objects, cidr):
    for p in _safe_list(objects.get("dhcp_scopes")):
        if p.get("cidr") == cidr:
            return _evidence(p).get("source_line")
    return None


def find_dhcp_pool(objects, cidr):
    for p in _safe_list(objects.get("dhcp_scopes")):
        if p.get("cidr") == cidr:
            return p
    return None


def acl_names_applied_to_vlan(objects, vlan_id):
    names = []
    for iface in interfaces_for_vlan(objects, vlan_id):
        if iface.get("acl_in"):
            names.append((iface.get("acl_in"), "in", iface))
        if iface.get("acl_out"):
            names.append((iface.get("acl_out"), "out", iface))
    return names


def rules_by_acl(objects, acl_name):
    return [r for r in _safe_list(objects.get("acl_rules")) if isinstance(r, dict) and str(r.get("acl_name")) == str(acl_name)]


def _guest_internal_deny_candidate(rule, guest_subnet):
    if rule.get("action") != "deny":
        return False
    expression = rule.get("expression", "").lower()
    parsed = rule.get("parsed", {}) or {}
    source = str(parsed.get("source") or "").lower()
    dest = str(parsed.get("destination") or "").lower()
    guest_net = str(guest_subnet or "").split("/")[0]
    guest_prefix = ".".join(guest_net.split(".")[:3]) + "." if guest_net else ""
    source_matches = guest_net in expression or (guest_prefix and guest_prefix in expression) or source == "any"
    dest_internal = "10.10." in expression or dest.startswith("10.") or "internal" in expression
    return source_matches and dest_internal


def guest_isolation_status(objects, guest):
    vlan = str(guest.get("expected_vlan"))
    subnet = guest.get("expected_subnet")
    applied = acl_names_applied_to_vlan(objects, vlan)
    deny_candidates = []
    for acl_name, direction, iface in applied:
        for rule in rules_by_acl(objects, acl_name):
            if _guest_internal_deny_candidate(rule, subnet):
                deny_candidates.append((rule, acl_name, direction, iface))
    if deny_candidates:
        rule, acl_name, direction, iface = deny_candidates[0]
        return {
            "status": "Pass",
            "rule": rule,
            "acl_name": acl_name,
            "direction": direction,
            "interface": iface,
            "reason": f"ACL {acl_name} is applied {direction} on {iface.get('name')} and contains a deny rule for guest-to-internal traffic.",
            "confidence": 0.94,
        }
    # Detections without application are not enough.
    for rule in _safe_list(objects.get("acl_rules")):
        if _guest_internal_deny_candidate(rule, subnet):
            return {
                "status": "Review",
                "rule": rule,
                "acl_name": rule.get("acl_name"),
                "direction": None,
                "interface": None,
                "reason": f"Deny rule exists in ACL {rule.get('acl_name')}, but no interface binding was confirmed for VLAN {vlan}.",
                "confidence": 0.62,
            }
    return {
        "status": "Fail",
        "rule": None,
        "acl_name": None,
        "direction": None,
        "interface": None,
        "reason": f"No applied deny ACL was found for guest VLAN {vlan}.",
        "confidence": 0.78,
    }


def _diff_item(id_, asset, category, expected, actual, status, severity, evidence_line=None, confidence=0.75, recommendation=None, evidence_reason=None):
    return {
        "id": id_,
        "asset": asset,
        "category": category,
        "expected": expected,
        "actual": actual,
        "status": status,
        "severity": severity,
        "evidence_line": evidence_line,
        "confidence": confidence,
        "recommendation": recommendation,
        "evidence_reason": evidence_reason,
    }


def build_policy_diff(state):
    objects = get_objects(state)
    ids = vlan_ids(objects)
    cidrs = dhcp_cidrs(objects)
    diffs = []
    trunks = trunk_interfaces(objects)

    for ssid in wireless_ssids(state):
        expected_vlan = str(ssid.get("expected_vlan"))
        asset = ssid["ssid"]
        vlan_line = find_vlan_line(objects, expected_vlan)
        vlan_status = "Pass" if expected_vlan in ids else "Fail"
        diffs.append(_diff_item(
            f"SSID-VLAN-{asset}", asset, "SSID-to-VLAN", f"VLAN {expected_vlan}",
            f"VLAN {expected_vlan} found in extracted evidence" if vlan_status == "Pass" else "Not found in extracted wired policy",
            vlan_status, "High" if vlan_status == "Fail" else "Info", vlan_line,
            0.95 if vlan_status == "Pass" else 0.72,
            "Create/restore the VLAN or upload complete VLAN evidence." if vlan_status != "Pass" else "No action required.",
            "Confirmed via VLAN/interface evidence." if vlan_line else "No line-level VLAN evidence found."
        ))

        cidr = ssid.get("expected_subnet")
        pool = find_dhcp_pool(objects, cidr)
        dhcp_status = "Pass" if cidr in cidrs else "Review"
        diffs.append(_diff_item(
            f"DHCP-{asset}", asset, "DHCP Scope", cidr,
            f"Scope {cidr} found in pool {pool.get('name')}" if pool else "No matching DHCP evidence",
            dhcp_status, "Medium" if dhcp_status != "Pass" else "Info", find_dhcp_line(objects, cidr),
            0.93 if pool else 0.48,
            "Upload DHCP pool output or create the matching DHCP network statement." if not pool else "No action required.",
            "Matched expected CIDR to extracted DHCP pool." if pool else "Expected subnet was absent from DHCP pool evidence."
        ))

        if pool:
            matched_gateway = None
            for m in _safe_list(objects.get("dhcp_gateway_matches")):
                if m.get("pool") == pool.get("name"):
                    matched_gateway = m
                    break
            gw_status = "Pass" if matched_gateway and matched_gateway.get("matched_vlan") == expected_vlan else "Review"
            diffs.append(_diff_item(
                f"DHCP-GW-{asset}", asset, "Gateway/DHCP Matching", f"DHCP gateway on VLAN {expected_vlan}",
                f"Gateway {pool.get('default_gateway')} matched {matched_gateway.get('matched_interface') if matched_gateway else 'no interface'}",
                gw_status, "Medium" if gw_status != "Pass" else "Info", _evidence(pool).get("source_line"),
                0.90 if gw_status == "Pass" else 0.55,
                "Check default-router vs routed subinterface/SVI IP." if gw_status != "Pass" else "No action required.",
                "DHCP default-router compared with extracted interface IP/VLAN."
            ))

        if trunks:
            carrying = [t for t in trunks if trunk_carries_vlan(t, expected_vlan)]
            trunk_status = "Pass" if carrying else "Fail"
            evidence = _evidence(carrying[0]).get("source_line") if carrying else _evidence(trunks[0]).get("source_line")
            diffs.append(_diff_item(
                f"TRUNK-{asset}", asset, "Trunk Coverage", f"A trunk carries VLAN {expected_vlan}",
                f"{len(carrying)} trunk interface(s) carry VLAN {expected_vlan}" if carrying else f"No trunk evidence carries VLAN {expected_vlan}",
                trunk_status, "High" if trunk_status != "Pass" else "Info", evidence,
                0.90 if trunk_status == "Pass" else 0.78,
                "Add the WLAN VLAN to AP/uplink trunk allowed lists." if trunk_status != "Pass" else "No action required.",
                "Checked switchport trunk allowed VLAN evidence."
            ))
        else:
            diffs.append(_diff_item(
                f"TRUNK-{asset}", asset, "Trunk Coverage", f"A trunk carries VLAN {expected_vlan}", "No trunk evidence uploaded",
                "Review", "Medium", None, 0.42,
                "Upload show interfaces trunk / switchport running-config.",
                "Trunk analysis requires trunk output or switchport mode trunk lines."
            ))

        applied = acl_names_applied_to_vlan(objects, expected_vlan)
        if ssid.get("internal_access") is False:
            isolation = guest_isolation_status(objects, ssid)
            diffs.append(_diff_item(
                f"GUEST-ISOLATION-{asset}", asset, "Guest Isolation", "Guest denied from internal networks",
                isolation["reason"], isolation["status"], "Critical" if isolation["status"] != "Pass" else "Info",
                _evidence(isolation.get("rule")).get("source_line") if isolation.get("rule") else None,
                isolation["confidence"],
                "Apply a deny ACL inbound on the guest VLAN gateway before any permit-any rule." if isolation["status"] != "Pass" else "No action required.",
                "ACL deny must be both present and applied on the guest VLAN path."
            ))
        elif ssid.get("internal_access") == "limited":
            status = "Pass" if applied else "Review"
            diffs.append(_diff_item(
                f"ACL-DIRECTION-{asset}", asset, "ACL Direction", f"Limited role has an applied ACL on VLAN {expected_vlan}",
                f"Applied ACL(s): {', '.join(x[0] for x in applied)}" if applied else "No applied ACL was confirmed",
                status, "High" if status != "Pass" else "Info",
                _evidence(applied[0][2]).get("source_line") if applied else None,
                0.86 if applied else 0.50,
                "Apply the student policy ACL to the VLAN gateway in the correct direction." if not applied else "No action required.",
                "Limited access roles need interface-bound ACL evidence."
            ))
    return diffs


def build_root_causes(state):
    causes = []
    for d in build_policy_diff(state):
        if d["status"] == "Pass":
            continue
        category = d["category"]
        if category == "SSID-to-VLAN":
            hypotheses = [
                f"{d['asset']} expected VLAN is absent from extracted VLAN/interface evidence.",
                "Uploaded data may not include show vlan brief or complete running-config.",
                "Wireless policy may be mapped to a VLAN not deployed on the wired side.",
            ]
            commands = ["show vlan brief", "show running-config | section vlan", "show interfaces switchport"]
            owner = "Wireless / Switching Team"
        elif category == "Trunk Coverage":
            hypotheses = [
                "The WLAN VLAN may not be allowed on AP or uplink trunks.",
                "show interfaces trunk evidence is missing or incomplete.",
                "A trunk allowed-list may have drifted from the intended policy.",
            ]
            commands = ["show interfaces trunk", "show running-config interface <uplink>", "show cdp neighbors detail"]
            owner = "Network Operations"
        elif category == "Guest Isolation":
            hypotheses = [
                "Guest deny ACL is missing, not applied, or applied in the wrong direction.",
                "A permit-any rule may allow internal access before the deny is enforced.",
                "Guest VLAN gateway evidence is incomplete.",
            ]
            commands = ["show access-lists", "show running-config | include access-group", "show running-config interface <guest-gateway>"]
            owner = "Network Security Team"
        elif category == "Gateway/DHCP Matching":
            hypotheses = [
                "DHCP default-router does not match the extracted gateway interface for the expected VLAN.",
                "The gateway may live on another device not included in this import.",
            ]
            commands = ["show running-config | section ip dhcp", "show ip interface brief", "show running-config interface <vlan/subinterface>"]
            owner = "Network Operations"
        else:
            hypotheses = [
                "Expected evidence was not found or is incomplete.",
                "Upload a broader command bundle to raise confidence.",
            ]
            commands = ["show running-config", "show access-lists", "show ip route"]
            owner = "Network Operations"
        causes.append({
            "finding_id": d["id"],
            "asset": d["asset"],
            "severity": d["severity"],
            "confidence": d.get("confidence", 0.65),
            "evidence_line": d.get("evidence_line"),
            "evidence_reason": d.get("evidence_reason"),
            "hypotheses": hypotheses,
            "verification_commands": commands,
            "owner": owner,
            "recommended_fix": d.get("recommendation"),
        })
    return causes


def risk_score(state):
    diffs = build_policy_diff(state)
    score = 100
    for d in diffs:
        if d["status"] == "Fail":
            score -= 25 if d["severity"] == "Critical" else 14
        elif d["status"] == "Review":
            score -= 7
    score = max(0, score)
    grade = "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs Improvement" if score >= 60 else "Critical"
    level = "Low" if score >= 90 else "Medium" if score >= 60 else "High"
    return {"score": score, "grade": grade, "risk_level": level}


def build_topology(state):
    objects = get_objects(state)
    nodes = []
    edges = []
    seen = set()

    def add_node(node_id, label, type_, confidence=0.7, meta=None):
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({"id": node_id, "label": label, "type": type_, "confidence": confidence, "meta": meta or {}})

    def add_edge(src, dst, type_, status="review", confidence=0.7, label=""):
        edges.append({"from": src, "to": dst, "type": type_, "status": status, "confidence": confidence, "label": label})

    for d in _safe_list(objects.get("devices")):
        add_node(d.get("id") or d.get("hostname"), d.get("hostname"), d.get("type"), _evidence(d).get("confidence", 0.5))

    for ssid in wireless_ssids(state):
        ssid_id = f"SSID:{ssid['ssid']}"
        vlan_id = f"VLAN:{ssid.get('expected_vlan')}"
        add_node(ssid_id, ssid["ssid"], "ssid", 1.0, {"role": ssid.get("role")})
        add_node(vlan_id, f"VLAN {ssid.get('expected_vlan')}", "vlan", 0.9)
        add_edge(ssid_id, vlan_id, "policy-map", "expected", 1.0, ssid.get("role", ""))

    for i in _safe_list(objects.get("interfaces")):
        iface_id = f"IF:{i.get('name')}"
        add_node(iface_id, i.get("name"), "interface", _evidence(i).get("confidence", 0.75), {"mode": i.get("mode")})
        for key in ["access_vlan", "dot1q_vlan", "native_vlan"]:
            if i.get(key):
                vlan_id = f"VLAN:{i.get(key)}"
                add_node(vlan_id, f"VLAN {i.get(key)}", "vlan", 0.85)
                add_edge(vlan_id, iface_id, key, "confirmed", 0.85)
        for v in i.get("trunk_allowed_vlans", []) or []:
            if str(v).isdigit():
                vlan_id = f"VLAN:{v}"
                add_node(vlan_id, f"VLAN {v}", "vlan", 0.75)
                add_edge(iface_id, vlan_id, "trunk-allows", "confirmed", 0.78)
        for acl_key, direction in [("acl_in", "in"), ("acl_out", "out")]:
            if i.get(acl_key):
                acl_id = f"ACL:{i.get(acl_key)}"
                add_node(acl_id, i.get(acl_key), "acl", 0.88)
                add_edge(iface_id, acl_id, f"access-group-{direction}", "enforced", 0.88)

    for p in _safe_list(objects.get("dhcp_scopes")):
        pool_id = f"DHCP:{p.get('name')}"
        add_node(pool_id, p.get("name"), "dhcp", _evidence(p).get("confidence", 0.8), {"cidr": p.get("cidr")})
        for m in _safe_list(objects.get("dhcp_gateway_matches")):
            if m.get("pool") == p.get("name") and m.get("matched_vlan"):
                add_edge(pool_id, f"VLAN:{m.get('matched_vlan')}", "serves", m.get("status", "review"), m.get("confidence", 0.6), p.get("cidr", ""))

    for link in _safe_list(objects.get("cdp_links")):
        if link.get("neighbor"):
            add_node(link["neighbor"], link["neighbor"], "neighbor", _evidence(link).get("confidence", 0.7), {"source": "cdp", "platform": link.get("platform")})
            if link.get("local_interface"):
                add_edge(f"IF:{link.get('local_interface')}", link["neighbor"], "cdp", "confirmed", _evidence(link).get("confidence", 0.7), link.get("remote_interface", ""))

    for link in _safe_list(objects.get("lldp_links")):
        if link.get("neighbor"):
            add_node(link["neighbor"], link["neighbor"], "neighbor", _evidence(link).get("confidence", 0.68), {"source": "lldp", "platform": link.get("platform")})
            if link.get("local_interface"):
                add_edge(f"IF:{link.get('local_interface')}", link["neighbor"], "lldp", "confirmed", _evidence(link).get("confidence", 0.68), link.get("remote_interface", ""))

    if objects.get("policy_controls"):
        add_node("Extracted-Reality", "Extracted Wired Reality", "network", 0.72)
    for control in _safe_list(objects.get("policy_controls"))[:16]:
        if not isinstance(control, dict):
            continue
        evidence = _evidence(control)
        cid = f"CTRL:{control.get('control') or 'unknown'}"
        add_node(cid, control.get("control") or "Unknown control", "control", control.get("confidence", 0.65), {"status": control.get("status"), "severity": control.get("severity")})
        if evidence.get("source_line"):
            add_edge(cid, "Extracted-Reality", "evidence-control", control.get("status", "review"), control.get("confidence", 0.65), f"line {evidence.get('source_line')}")

    if not nodes:
        add_node("Expected-Wireless", "Expected Wireless Policy", "policy", 1.0)
        add_node("Extracted-Wired", "Extracted Wired Reality", "network", 0.5)
        add_edge("Expected-Wireless", "Extracted-Wired", "validation", "review", 0.6)
    return {"nodes": nodes, "edges": edges}


def run_access_simulation(state, client, action):
    objects = get_objects(state)
    client_role = client.split(" - ")[-1] if " - " in client else client
    client_obj = next((c for c in state.get("clients", []) if c.get("role") in client_role or c.get("name") in client), {})
    ssid = next((s for s in wireless_ssids(state) if s.get("role") == client_obj.get("role") or s.get("role") == client_role), {})
    vlan = ssid.get("expected_vlan") or client_obj.get("vlan")
    path = [f"Client: {client}", f"Role: {ssid.get('role', client_role)}", f"SSID: {ssid.get('ssid', 'unknown')}", f"VLAN: {vlan}"]
    decision_points = []
    desired_service = "Internal Portal" if "Internal" in action else "Internet" if "Internet" in action else "ERP" if "ERP" in action else action
    allowed = desired_service in (ssid.get("allowed_services") or []) or (desired_service == "Internet" and ssid.get("internet"))

    if ssid.get("internal_access") is False and ("Internal" in action or "ERP" in action or "File" in action):
        isolation = guest_isolation_status(objects, ssid)
        decision_points.append(isolation["reason"])
        if isolation["status"] == "Pass":
            return {"status": "Pass", "severity": "Info", "detail": "Access blocked as expected by applied guest isolation ACL.", "path": path + ["Applied ACL deny"], "decision_points": decision_points}
        return {"status": "Fail", "severity": "Critical", "detail": "Guest/internal access could not be proven blocked by an applied ACL.", "path": path + ["No proven applied deny"], "decision_points": decision_points}

    if allowed:
        decision_points.append(f"{desired_service} is allowed by the expected wireless policy.")
        return {"status": "Pass", "severity": "Info", "detail": f"{client} simulated action '{action}' is allowed by policy.", "path": path + [desired_service], "decision_points": decision_points}
    decision_points.append(f"{desired_service} is not listed as an allowed service for this role.")
    return {"status": "Review", "severity": "Medium", "detail": f"{client} simulated action '{action}' needs manual validation against ACL/routing evidence.", "path": path + [desired_service], "decision_points": decision_points}


def build_timeline(state):
    timeline = []
    for e in state.get("events", []):
        timeline.append({"time": e.get("created_at"), "type": e.get("type"), "severity": e.get("severity"), "detail": e.get("detail")})
    for imp in state.get("imports", []):
        timeline.append({"time": imp.get("imported_at"), "type": "import", "severity": "Info", "detail": f"Imported {imp.get('filename')} with {imp.get('object_count', 0)} objects"})
    for d in build_policy_diff(state):
        if d["status"] != "Pass":
            timeline.append({"time": state.get("active_extraction", {}).get("imported_at", "N/A"), "type": "policy_diff", "severity": d["severity"], "detail": f"{d['id']}: {d['actual']}"})
    return sorted(timeline, key=lambda x: x.get("time") or "", reverse=True)


def build_playbooks(state):
    result = []
    for c in build_root_causes(state):
        fix = c.get("recommended_fix") or "Run the verification commands and remediate the confirmed drift."
        result.append({
            "finding_id": c["finding_id"],
            "owner": c["owner"],
            "severity": c["severity"],
            "steps": [
                "Confirm the affected SSID/VLAN/service path in the evidence view.",
                "Run the verification commands listed below.",
                fix,
                "Re-import fresh outputs into WiGuard.",
                "Verify that the finding changes to Pass with line-level evidence.",
            ],
            "commands": c["verification_commands"],
        })
    return result


def build_snapshot_diff(state):
    imports = state.get("imports", [])
    current_counts = object_counts(get_objects(state))
    previous = imports[1].get("counts", {}) if len(imports) > 1 else {}
    changes = []
    for key in sorted(set(current_counts) | set(previous)):
        before = previous.get(key, 0)
        after = current_counts.get(key, 0)
        changes.append({"object_type": key, "before": before, "after": after, "delta": after - before})
    return {"baseline": imports[1].get("filename") if len(imports) > 1 else None, "current": imports[0].get("filename") if imports else None, "changes": changes}



def _registry_summary(objects):
    registry = _safe_list(objects.get("evidence_registry"))
    summary = {"verified": 0, "recovered": 0, "inferred": 0, "unmapped": 0, "total": len(registry)}
    high_value = {"devices", "interfaces", "vlans", "acl_rules", "dhcp_scopes", "cdp_links", "lldp_links", "ip_inventory", "route_table", "trunk_operational"}
    hv_total = hv_verified = 0
    for row in registry:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "unmapped").lower()
        if status not in summary:
            status = "unmapped"
        summary[status] += 1
        if row.get("category") in high_value:
            hv_total += 1
            if status == "verified":
                hv_verified += 1
    summary["verified_ratio"] = round(summary["verified"] / summary["total"], 3) if summary["total"] else 0
    summary["high_value_total"] = hv_total
    summary["high_value_verified"] = hv_verified
    summary["high_value_verified_ratio"] = round(hv_verified / hv_total, 3) if hv_total else 0
    return summary


def build_extraction_diagnostics(state):
    """Build a truth-first diagnostics model for imports and reports.

    The UI should never imply that a native .pkt was parsed with complete
    fidelity unless the evidence contract proves it. This function converts
    pipeline, object coverage, registry status and missing exports into an
    analyst-facing checklist.
    """
    active = _safe_dict(state.get("active_extraction"))
    objects = get_objects(state)
    profile = _safe_dict(active.get("conversion_profile") or objects.get("packet_tracer_profile"))
    contracts = _safe_list(objects.get("verified_extraction_contract"))
    contract = contracts[0] if contracts and isinstance(contracts[0], dict) else {}
    registry = _registry_summary(objects)
    counts = object_counts(objects)
    native = bool((active.get("filename") or "").lower().endswith((".pkt", ".pka")) or profile.get("native_packet_tracer"))
    source_mode = active.get("source_mode") or profile.get("source_mode") or "unknown"

    required_exports = contract.get("required_next_exports") or []
    blockers = []
    if native and not contract.get("companion_export_present") and not contract.get("can_claim_full_fidelity"):
        blockers.append({
            "id": "PT-COMPANION-EXPORT-MISSING",
            "severity": "High",
            "title": "Native Packet Tracer upload has no companion export",
            "detail": "Upload exported running-config, show-command text, XML, JSON or ZIP to convert best-effort recovery into verified evidence.",
        })
    if registry["total"] and registry["high_value_verified_ratio"] < 0.75:
        blockers.append({
            "id": "EVIDENCE-HIGH-VALUE-LOW",
            "severity": "Medium",
            "title": "High-value objects are not fully verified",
            "detail": f"Only {int(registry['high_value_verified_ratio']*100)}% of high-value objects are verified by line/path evidence.",
        })
    if counts.get("interfaces", 0) == 0:
        blockers.append({"id": "NO-INTERFACES", "severity": "High", "title": "No interfaces extracted", "detail": "Topology and VLAN analysis need interface blocks or show ip interface brief/status outputs."})
    if counts.get("vlans", 0) == 0:
        blockers.append({"id": "NO-VLANS", "severity": "Medium", "title": "No VLAN evidence extracted", "detail": "Upload show vlan brief or running-config VLAN blocks to confirm segmentation."})
    if counts.get("cdp_links", 0) + counts.get("lldp_links", 0) == 0:
        blockers.append({"id": "NO-L2-NEIGHBORS", "severity": "Low", "title": "No CDP/LLDP topology links", "detail": "Physical adjacency will remain inferred until CDP/LLDP evidence is uploaded."})

    pipeline = []
    raw_pipeline = active.get("pipeline") or profile.get("auto_conversion_pipeline") or []
    if isinstance(raw_pipeline, list):
        for idx, stage in enumerate(raw_pipeline[:20], start=1):
            if isinstance(stage, dict):
                pipeline.append({
                    "step": idx,
                    "stage": stage.get("stage") or stage.get("name") or f"stage_{idx}",
                    "status": stage.get("status") or "recorded",
                    "confidence": stage.get("confidence"),
                    "detail": stage.get("detail") or stage.get("message") or "",
                })
            else:
                pipeline.append({"step": idx, "stage": str(stage), "status": "recorded", "confidence": None, "detail": ""})

    readiness_score = profile.get("readiness_score")
    if readiness_score is None:
        readiness_score = int(min(100, 25 + counts.get("interfaces", 0) * 4 + counts.get("vlans", 0) * 6 + registry["verified_ratio"] * 45))

    actions = []
    if required_exports:
        for item in required_exports[:8]:
            actions.append({
                "priority": item.get("severity", "Medium"),
                "action": f"Upload/export: {item.get('artifact')}",
                "why": item.get("why", "Required to raise extraction confidence."),
            })
    else:
        actions.append({"priority": "Info", "action": "Re-run import after every topology/config change", "why": "Keeps report artifacts synchronized with evidence."})
    if counts.get("acl_rules", 0) == 0:
        actions.append({"priority": "Medium", "action": "Add show access-lists / running-config ACL evidence", "why": "Segmentation claims need ACL proof, not only VLAN placement."})
    if counts.get("route_table", 0) == 0:
        actions.append({"priority": "Low", "action": "Add show ip route", "why": "End-to-end reachability/root-cause analysis becomes stronger with L3 forwarding evidence."})

    return {
        "generated_at": now_iso(),
        "filename": active.get("filename"),
        "source_mode": source_mode,
        "native_packet_tracer": native,
        "tier": contract.get("tier") or profile.get("readiness") or "unknown",
        "claim": contract.get("claim") or profile.get("analyst_next_step") or "Import evidence to generate a contract.",
        "can_claim_full_fidelity": bool(contract.get("can_claim_full_fidelity")),
        "readiness_score": readiness_score,
        "object_counts": counts,
        "evidence_summary": registry,
        "pipeline": pipeline,
        "blockers": blockers,
        "recommended_actions": actions,
        "required_exports": required_exports,
    }


def build_topology_insights(state):
    topology = build_topology(state)
    objects = get_objects(state)
    nodes = _safe_list(topology.get("nodes"))
    edges = _safe_list(topology.get("edges"))
    type_counts = {}
    for n in nodes:
        t = str(n.get("type") or "unknown").lower() if isinstance(n, dict) else "unknown"
        type_counts[t] = type_counts.get(t, 0) + 1
    strong_status = {"confirmed", "enforced", "expected", "pass", "serves"}
    confirmed_edges = [e for e in edges if isinstance(e, dict) and str(e.get("status") or "").lower() in strong_status]
    inferred_edges = [e for e in edges if isinstance(e, dict) and e not in confirmed_edges]
    connected = set()
    for e in edges:
        if isinstance(e, dict):
            connected.add(e.get("from")); connected.add(e.get("to"))
    orphan_nodes = [n for n in nodes if isinstance(n, dict) and n.get("id") not in connected]
    suggestions = []
    if not _safe_list(objects.get("cdp_links")) and not _safe_list(objects.get("lldp_links")):
        suggestions.append("Import show cdp neighbors detail or show lldp neighbors detail to confirm physical links.")
    if not _safe_list(objects.get("trunk_operational")):
        suggestions.append("Import show interfaces trunk to confirm active trunk VLANs and native VLANs.")
    if not _safe_list(objects.get("route_table")):
        suggestions.append("Import show ip route to connect VLAN/interface evidence to L3 reachability.")
    return {
        "generated_at": now_iso(),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_types": type_counts,
        "confirmed_edges": len(confirmed_edges),
        "inferred_edges": len(inferred_edges),
        "orphan_nodes": [{"id": n.get("id"), "label": n.get("label"), "type": n.get("type")} for n in orphan_nodes[:30]],
        "edge_confidence_average": round(sum(float(e.get("confidence") or 0) for e in edges if isinstance(e, dict)) / len(edges), 3) if edges else 0,
        "suggestions": suggestions,
    }


def build_validation_rule_assessment(state):
    objects = get_objects(state)
    diffs = build_policy_diff(state)
    risk_atoms = _safe_list(objects.get("risk_atoms"))
    controls = _safe_list(objects.get("policy_controls"))
    registry = _registry_summary(objects)
    rules = _safe_list(state.get("rules"))
    enabled_rules = [r for r in rules if not isinstance(r, dict) or r.get("enabled", True)]
    failed = [d for d in diffs if d.get("status") == "Fail"]
    review = [d for d in diffs if d.get("status") == "Review"]
    gaps = []
    if not _safe_list(objects.get("acl_rules")):
        gaps.append({"id": "RULE-GAP-ACL", "severity": "High", "detail": "ACL validation rules cannot become confirmed without ACL evidence."})
    if not _safe_list(objects.get("interface_counters")):
        gaps.append({"id": "RULE-GAP-RUNTIME", "severity": "Low", "detail": "Runtime counters are missing, so traffic-based rules stay review-level."})
    if registry["total"] and registry["verified_ratio"] < 0.5:
        gaps.append({"id": "RULE-GAP-EVIDENCE", "severity": "Medium", "detail": "Most rule inputs are recovered/inferred, not verified."})
    return {
        "generated_at": now_iso(),
        "classic_rules_total": len(rules),
        "classic_rules_enabled": len(enabled_rules),
        "policy_controls_extracted": len(controls),
        "risk_atoms": len(risk_atoms),
        "findings_total": len(diffs),
        "failed_findings": len(failed),
        "review_findings": len(review),
        "evidence_verified_ratio": registry["verified_ratio"],
        "gaps": gaps,
    }

PROFESSIONAL_EVIDENCE_CATEGORIES = [
    {"key": "devices", "label": "Device Inventory", "required_for": "Topology identity", "min_count": 1, "critical": True},
    {"key": "interfaces", "label": "Interface Blocks", "required_for": "VLAN/trunk/IP analysis", "min_count": 1, "critical": True},
    {"key": "vlans", "label": "VLAN Evidence", "required_for": "Segmentation claims", "min_count": 1, "critical": True},
    {"key": "ip_inventory", "label": "IP Inventory", "required_for": "L3 addressing", "min_count": 1, "critical": False},
    {"key": "trunk_operational", "label": "Trunk Operational State", "required_for": "Allowed/native VLAN proof", "min_count": 1, "critical": False},
    {"key": "acl_rules", "label": "ACL Rules", "required_for": "Access-control claims", "min_count": 1, "critical": False},
    {"key": "dhcp_scopes", "label": "DHCP Scopes", "required_for": "Client addressing", "min_count": 1, "critical": False},
    {"key": "route_table", "label": "Routing Table", "required_for": "Reachability/root cause", "min_count": 1, "critical": False},
    {"key": "cdp_links", "label": "CDP Links", "required_for": "Physical topology", "min_count": 1, "critical": False},
    {"key": "lldp_links", "label": "LLDP Links", "required_for": "Physical topology", "min_count": 1, "critical": False},
    {"key": "raw_evidence", "label": "Raw Evidence Lines", "required_for": "Audit traceability", "min_count": 1, "critical": True},
]


def _evidence_rows_by_category(objects):
    rows = _safe_list(objects.get("evidence_registry"))
    grouped = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cat = row.get("category") or "unknown"
        grouped.setdefault(cat, {"verified": 0, "recovered": 0, "inferred": 0, "unmapped": 0, "total": 0})
        status = str(row.get("status") or "unmapped").lower()
        if status not in {"verified", "recovered", "inferred", "unmapped"}:
            status = "unmapped"
        grouped[cat][status] += 1
        grouped[cat]["total"] += 1
    return grouped


def build_evidence_quality_matrix(state):
    """Return a conservative, category-level evidence QA matrix."""
    objects = get_objects(state)
    counts = object_counts(objects)
    grouped = _evidence_rows_by_category(objects)
    diagnostics = build_extraction_diagnostics(state)
    contract = (_safe_list(objects.get("verified_extraction_contract")) or [{}])[0]
    source_mode = diagnostics.get("source_mode") or (state.get("active_extraction", {}) or {}).get("source_mode") or "unknown"
    rows = []
    for spec in PROFESSIONAL_EVIDENCE_CATEGORIES:
        key = spec["key"]
        count = int(counts.get(key, 0) or 0)
        ev = grouped.get(key, {"verified": 0, "recovered": 0, "inferred": 0, "unmapped": 0, "total": 0})
        verified_ratio = round((ev.get("verified", 0) / ev.get("total", 1)), 3) if ev.get("total") else 0
        if count <= 0:
            status = "missing"
            claim_level = "not_available"
            action = f"Upload/export evidence for {spec['label']} ({spec['required_for']})."
        elif ev.get("verified", 0) > 0 and verified_ratio >= 0.70:
            status = "pass"
            claim_level = "verified"
            action = "No immediate action; keep source artifact in evidence package."
        elif ev.get("verified", 0) > 0:
            status = "review"
            claim_level = "partially_verified"
            action = "Add line/path-backed exports to raise verified ratio."
        elif ev.get("recovered", 0) > 0 or str(source_mode).startswith("pkt_"):
            status = "review"
            claim_level = "recovered_native"
            action = "Use a companion export to convert recovered evidence into verified evidence."
        else:
            status = "review"
            claim_level = "unmapped"
            action = "Map this object class to raw source lines before reporting as fact."
        rows.append({
            "category": key,
            "label": spec["label"],
            "required_for": spec["required_for"],
            "critical": spec["critical"],
            "count": count,
            "evidence_total": ev.get("total", 0),
            "verified": ev.get("verified", 0),
            "recovered": ev.get("recovered", 0),
            "inferred": ev.get("inferred", 0),
            "unmapped": ev.get("unmapped", 0),
            "verified_ratio": verified_ratio,
            "status": status,
            "claim_level": claim_level,
            "recommended_action": action,
        })
    critical_missing = [r for r in rows if r["critical"] and r["status"] == "missing"]
    missing_rows = [r for r in rows if r["status"] == "missing"]
    review_rows = [r for r in rows if r["status"] == "review"]
    pass_rows = [r for r in rows if r["status"] == "pass"]
    score = 100 - len(critical_missing) * 18 - len([r for r in missing_rows if not r["critical"]]) * 8 - len(review_rows) * 5
    score = max(0, min(100, score))
    grade = "Evidence-ready" if score >= 90 else "Reportable with caveats" if score >= 70 else "Needs companion exports" if score >= 45 else "Insufficient evidence"
    return {
        "generated_at": now_iso(),
        "score": score,
        "grade": grade,
        "source_mode": source_mode,
        "full_fidelity_allowed": bool(contract.get("can_claim_full_fidelity")),
        "rows": rows,
        "summary": {
            "passed": len(pass_rows),
            "review": len(review_rows),
            "missing": len(missing_rows),
            "critical_missing": len(critical_missing),
        },
        "top_actions": [r["recommended_action"] for r in rows if r["status"] != "pass"][:8],
    }


def build_analyst_signoff(state):
    """Create a publish/no-publish checklist for reports and demos."""
    diagnostics = build_extraction_diagnostics(state)
    matrix = build_evidence_quality_matrix(state)
    blockers = _safe_list(diagnostics.get("blockers"))
    high_blockers = [b for b in blockers if str(b.get("severity") or "").lower() == "high"]
    critical_missing = matrix.get("summary", {}).get("critical_missing", 0)
    can_publish_technical = critical_missing == 0 and matrix.get("score", 0) >= 55
    can_publish_executive = len(high_blockers) == 0 and matrix.get("score", 0) >= 70
    allowed_claims = [
        "All listed objects are separated by evidence strength: verified, recovered, inferred, or unmapped.",
        "Native .pkt/.pka extraction is best-effort unless companion exports are parsed.",
        "Reports include diagnostics, blockers, and required next exports.",
    ]
    if diagnostics.get("can_claim_full_fidelity"):
        allowed_claims.append("Full-fidelity claims are allowed for the verified object classes covered by companion/export evidence.")
    forbidden_claims = []
    if not diagnostics.get("can_claim_full_fidelity"):
        forbidden_claims.append("Do not claim 100% Packet Tracer parsing fidelity from native .pkt/.pka alone.")
    if high_blockers:
        forbidden_claims.append("Do not publish executive-level conclusions without listing High blockers.")
    if critical_missing:
        forbidden_claims.append("Do not claim complete topology/policy coverage while critical evidence categories are missing.")
    required_actions = []
    for b in high_blockers[:5]:
        required_actions.append({"priority": b.get("severity", "High"), "action": b.get("title") or b.get("id"), "why": b.get("detail", "Required before sign-off.")})
    for action in matrix.get("top_actions", [])[:5]:
        required_actions.append({"priority": "Evidence", "action": action, "why": "Raises report defensibility and extraction quality."})
    return {
        "generated_at": now_iso(),
        "can_publish_executive": can_publish_executive,
        "can_publish_technical": can_publish_technical,
        "can_claim_full_fidelity": bool(diagnostics.get("can_claim_full_fidelity")),
        "evidence_score": matrix.get("score", 0),
        "evidence_grade": matrix.get("grade", "unknown"),
        "blockers": blockers,
        "required_actions": required_actions[:10],
        "allowed_claims": allowed_claims,
        "forbidden_claims": forbidden_claims,
    }


def build_topology_dot(state):
    """Generate a small Graphviz DOT representation for artifact/export review."""
    topology = build_topology(state)
    def esc(value):
        return str(value or "").replace('"', r'\"')[:140]
    lines = ["digraph WiGuardTopology {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    for node in _safe_list(topology.get("nodes")):
        if not isinstance(node, dict):
            continue
        label = f"{node.get('label') or node.get('id')}\\n{node.get('type','unknown')}\\n{int(float(node.get('confidence') or 0)*100)}%"
        lines.append(f'  "{esc(node.get("id"))}" [label="{esc(label)}"];')
    for edge in _safe_list(topology.get("edges")):
        if not isinstance(edge, dict):
            continue
        label = f"{edge.get('type','link')} / {edge.get('status','review')} / {int(float(edge.get('confidence') or 0)*100)}%"
        lines.append(f'  "{esc(edge.get("from"))}" -> "{esc(edge.get("to"))}" [label="{esc(label)}"];')
    lines.append("}")
    return "\n".join(lines)


def build_report(state, report_type="full"):
    score = risk_score(state)
    diffs = build_policy_diff(state)
    causes = build_root_causes(state)
    objects = get_objects(state)
    counts = object_counts(objects)
    wireless = wireless_dashboard(state, diffs)
    base = {
        "report_type": report_type,
        "generated_at": now_iso(),
        "project": next((p for p in state.get("projects", []) if p["id"] == state.get("current_project")), {}),
        "risk": score,
        "summary": {
            "objects": counts,
            "total_diffs": len(diffs),
            "failed": sum(1 for d in diffs if d["status"] == "Fail"),
            "review": sum(1 for d in diffs if d["status"] == "Review"),
            "passed": sum(1 for d in diffs if d["status"] == "Pass"),
            "confidence": state.get("active_extraction", {}).get("confidence_summary", {}),
            "missing_evidence": state.get("active_extraction", {}).get("missing_evidence", []),
            "conversion_profile": state.get("active_extraction", {}).get("conversion_profile", objects.get("packet_tracer_profile", {})),
        },
        "executive_summary": build_executive_summary(score, diffs),
        "policy_diff": diffs,
        "root_causes": causes,
        "wireless": wireless,
        "packet_tracer_conversion": state.get("active_extraction", {}).get("conversion_profile", objects.get("packet_tracer_profile", {})),
        "compliance": build_compliance_matrix(state, wireless, diffs),
        "diagnostics": build_extraction_diagnostics(state),
        "topology_insights": build_topology_insights(state),
        "rule_assessment": build_validation_rule_assessment(state),
        "evidence_quality_matrix": build_evidence_quality_matrix(state),
        "analyst_signoff": build_analyst_signoff(state),
    }
    if report_type == "executive":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "risk", "summary", "executive_summary"]}
    if report_type == "technical":
        base["objects"] = objects
        base["topology"] = build_topology(state)
        base["snapshot_diff"] = build_snapshot_diff(state)
        return base
    if report_type == "security":
        base["security_findings"] = [d for d in diffs if d["severity"] in {"Critical", "High"}]
        base["playbooks"] = build_playbooks(state)
        return base
    if report_type == "audit":
        base["evidence_manifest"] = state.get("active_extraction", {}).get("manifest", {})
        base["line_level_evidence"] = objects.get("raw_evidence", [])
        base["source_hash"] = state.get("active_extraction", {}).get("source_hash")
        return base
    if report_type == "compliance":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "risk", "summary", "compliance", "policy_diff"]}
    if report_type == "packet_tracer":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "summary", "packet_tracer_conversion", "diagnostics", "evidence_quality_matrix", "analyst_signoff"]}
    if report_type == "quality":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "summary", "diagnostics", "topology_insights", "rule_assessment", "evidence_quality_matrix", "analyst_signoff"]}
    if report_type == "wireless_risk":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "risk", "summary", "wireless", "root_causes"]}
    if report_type == "evidence_appendix":
        base["evidence_manifest"] = state.get("active_extraction", {}).get("manifest", {})
        base["line_level_evidence"] = objects.get("raw_evidence", [])
        base["source_hash"] = state.get("active_extraction", {}).get("source_hash")
        base["artifacts"] = state.get("active_extraction", {}).get("artifacts", {})
        return base
    if report_type == "wireless":
        return {k: base[k] for k in ["report_type", "generated_at", "project", "risk", "summary", "wireless", "policy_diff", "root_causes"]}
    base["objects"] = objects
    base["topology"] = build_topology(state)
    base["timeline"] = build_timeline(state)
    base["playbooks"] = build_playbooks(state)
    base["rules"] = state.get("rules", [])
    base["compliance"] = build_compliance_matrix(state, wireless, diffs)
    base["snapshot_diff"] = build_snapshot_diff(state)
    return base


def build_executive_summary(score, diffs):
    failed = [d for d in diffs if d["status"] == "Fail"]
    review = [d for d in diffs if d["status"] == "Review"]
    critical = [d for d in failed if d["severity"] == "Critical"]
    if critical:
        concern = critical[0]["id"]
    elif failed:
        concern = failed[0]["id"]
    elif review:
        concern = review[0]["id"]
    else:
        concern = "No critical policy drift confirmed."
    return {
        "headline": f"Wireless policy health is {score['score']}/100 ({score['grade']}).",
        "primary_concern": concern,
        "business_impact": "Potential segmentation drift may expose internal services or cause users to receive the wrong network policy." if failed else "Current evidence does not show critical segmentation failure.",
        "recommended_priority": "Immediate remediation for Critical/High failed checks; review Medium items within SLA.",
    }
