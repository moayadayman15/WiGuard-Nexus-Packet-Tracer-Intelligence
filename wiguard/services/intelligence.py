from .util import now_iso, network_cidr
from .wireless import wireless_dashboard, wireless_risk_score
from .compliance import build_compliance_matrix


def wireless_ssids(state):
    return state.get("wireless_policy", {}).get("ssids", [])


def get_objects(state):
    return state.get("active_extraction", {}).get("objects", {}) or {}


def object_counts(objects):
    return {
        "devices": len(objects.get("devices", [])),
        "interfaces": len(objects.get("interfaces", [])),
        "vlans": len(objects.get("vlans", [])),
        "dhcp_scopes": len(objects.get("dhcp_scopes", [])),
        "acl_rules": len(objects.get("acl_rules", [])),
        "routing": len(objects.get("routing", {}).get("static_routes", [])) + len(objects.get("routing", {}).get("protocols", [])),
        "nat_rules": len(objects.get("nat_rules", [])),
        "cdp_links": len(objects.get("cdp_links", [])),
        "raw_evidence": len(objects.get("raw_evidence", [])),
    }


def vlan_ids(objects):
    ids = set()
    for v in objects.get("vlans", []):
        if v.get("id"):
            ids.add(str(v.get("id")))
    for i in objects.get("interfaces", []):
        for key in ["access_vlan", "dot1q_vlan", "native_vlan"]:
            if i.get(key):
                ids.add(str(i[key]))
        for v in i.get("trunk_allowed_vlans", []) or []:
            if str(v).isdigit():
                ids.add(str(v))
    return ids


def dhcp_cidrs(objects):
    return {p["cidr"] for p in objects.get("dhcp_scopes", []) if p.get("cidr")}


def interfaces_for_vlan(objects, vlan_id):
    vlan_id = str(vlan_id)
    result = []
    for i in objects.get("interfaces", []):
        if str(i.get("access_vlan")) == vlan_id or str(i.get("dot1q_vlan")) == vlan_id or str(i.get("native_vlan")) == vlan_id:
            result.append(i)
    return result


def trunk_interfaces(objects):
    return [i for i in objects.get("interfaces", []) if i.get("mode") == "trunk" or i.get("trunk_allowed_vlans")]


def trunk_carries_vlan(interface, vlan_id):
    allowed = [str(x) for x in interface.get("trunk_allowed_vlans", [])]
    return "all" in allowed or str(vlan_id) in allowed


def find_vlan_line(objects, vlan_id):
    for v in objects.get("vlans", []):
        if str(v.get("id")) == str(vlan_id):
            return v.get("evidence", {}).get("source_line")
    for i in objects.get("interfaces", []):
        if str(i.get("access_vlan")) == str(vlan_id) or str(i.get("dot1q_vlan")) == str(vlan_id) or str(i.get("native_vlan")) == str(vlan_id):
            return i.get("evidence", {}).get("source_line")
        if str(vlan_id) in [str(x) for x in i.get("trunk_allowed_vlans", [])]:
            return i.get("evidence", {}).get("source_line")
    return None


def find_dhcp_line(objects, cidr):
    for p in objects.get("dhcp_scopes", []):
        if p.get("cidr") == cidr:
            return p.get("evidence", {}).get("source_line")
    return None


def find_dhcp_pool(objects, cidr):
    for p in objects.get("dhcp_scopes", []):
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
    return [r for r in objects.get("acl_rules", []) if str(r.get("acl_name")) == str(acl_name)]


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
    for rule in objects.get("acl_rules", []):
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
            for m in objects.get("dhcp_gateway_matches", []):
                if m.get("pool") == pool.get("name"):
                    matched_gateway = m
                    break
            gw_status = "Pass" if matched_gateway and matched_gateway.get("matched_vlan") == expected_vlan else "Review"
            diffs.append(_diff_item(
                f"DHCP-GW-{asset}", asset, "Gateway/DHCP Matching", f"DHCP gateway on VLAN {expected_vlan}",
                f"Gateway {pool.get('default_gateway')} matched {matched_gateway.get('matched_interface') if matched_gateway else 'no interface'}",
                gw_status, "Medium" if gw_status != "Pass" else "Info", pool.get("evidence", {}).get("source_line"),
                0.90 if gw_status == "Pass" else 0.55,
                "Check default-router vs routed subinterface/SVI IP." if gw_status != "Pass" else "No action required.",
                "DHCP default-router compared with extracted interface IP/VLAN."
            ))

        if trunks:
            carrying = [t for t in trunks if trunk_carries_vlan(t, expected_vlan)]
            trunk_status = "Pass" if carrying else "Fail"
            evidence = carrying[0].get("evidence", {}).get("source_line") if carrying else trunks[0].get("evidence", {}).get("source_line")
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
                isolation.get("rule", {}).get("evidence", {}).get("source_line") if isolation.get("rule") else None,
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
                applied[0][2].get("evidence", {}).get("source_line") if applied else None,
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

    for d in objects.get("devices", []):
        add_node(d.get("id") or d.get("hostname"), d.get("hostname"), d.get("type"), d.get("evidence", {}).get("confidence", 0.5))

    for ssid in wireless_ssids(state):
        ssid_id = f"SSID:{ssid['ssid']}"
        vlan_id = f"VLAN:{ssid.get('expected_vlan')}"
        add_node(ssid_id, ssid["ssid"], "ssid", 1.0, {"role": ssid.get("role")})
        add_node(vlan_id, f"VLAN {ssid.get('expected_vlan')}", "vlan", 0.9)
        add_edge(ssid_id, vlan_id, "policy-map", "expected", 1.0, ssid.get("role", ""))

    for i in objects.get("interfaces", []):
        iface_id = f"IF:{i.get('name')}"
        add_node(iface_id, i.get("name"), "interface", i.get("evidence", {}).get("confidence", 0.75), {"mode": i.get("mode")})
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

    for p in objects.get("dhcp_scopes", []):
        pool_id = f"DHCP:{p.get('name')}"
        add_node(pool_id, p.get("name"), "dhcp", p.get("evidence", {}).get("confidence", 0.8), {"cidr": p.get("cidr")})
        for m in objects.get("dhcp_gateway_matches", []):
            if m.get("pool") == p.get("name") and m.get("matched_vlan"):
                add_edge(pool_id, f"VLAN:{m.get('matched_vlan')}", "serves", m.get("status", "review"), m.get("confidence", 0.6), p.get("cidr", ""))

    for link in objects.get("cdp_links", []):
        if link.get("neighbor"):
            add_node(link["neighbor"], link["neighbor"], "neighbor", link.get("evidence", {}).get("confidence", 0.7))
            if link.get("local_interface"):
                add_edge(f"IF:{link.get('local_interface')}", link["neighbor"], "cdp", "confirmed", link.get("evidence", {}).get("confidence", 0.7), link.get("remote_interface", ""))

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
        },
        "executive_summary": build_executive_summary(score, diffs),
        "policy_diff": diffs,
        "root_causes": causes,
        "wireless": wireless,
        "compliance": build_compliance_matrix(state, wireless, diffs),
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
