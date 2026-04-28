import csv
import io
import ipaddress
import json
from collections import Counter, defaultdict
from typing import Dict, Any, List, Tuple
from .util import now_iso


DEFAULT_APS = [
    {"id": "AP-01", "name": "AP-01", "location": "Admin Floor", "switch": "SW1", "uplink_interface": "GigabitEthernet0/1", "supported_vlans": ["10", "20", "30"], "max_clients": 30, "status": "online"},
    {"id": "AP-02", "name": "AP-02", "location": "Lecture Hall", "switch": "SW1", "uplink_interface": "GigabitEthernet0/2", "supported_vlans": ["10", "20", "30"], "max_clients": 30, "status": "online"},
    {"id": "AP-03", "name": "AP-03", "location": "Guest Lobby", "switch": "SW2", "uplink_interface": "GigabitEthernet0/3", "supported_vlans": ["30"], "max_clients": 25, "status": "online"},
]

DEFAULT_POLICY_SETTINGS = {
    "auth_failure_threshold": 3,
    "roaming_threshold": 4,
    "ap_load_warning": 75,
    "ap_load_critical": 90,
    "unknown_ap_severity": "High",
    "enforce_role_ssid_match": True,
    "enforce_ap_vlan_support": True,
}


SSID_SERVICE_MATRIX = {
    "Staff": ["Internet", "DNS", "ERP", "File Server", "Internal Portal"],
    "Student": ["Internet", "DNS", "Internal Portal"],
    "Guest": ["Internet"],
}


def _event_id(state) -> int:
    return max([int(e.get("id", 0)) for e in state.get("events", []) if str(e.get("id", "")).isdigit()] + [0]) + 1


def _client_id(name: str) -> str:
    return "client-" + "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")[:48]


def _ap_id(name: str) -> str:
    return "".join(ch.upper() if ch.isalnum() else "-" for ch in name).strip("-")[:48] or "AP-NEW"


def _ssid_for_role(state, role: str) -> Dict[str, Any]:
    for ssid in state.get("wireless_policy", {}).get("ssids", []):
        if str(ssid.get("role", "")).lower() == str(role or "").lower():
            return ssid
    return {}


def _ssid_by_name(state, name: str) -> Dict[str, Any]:
    for ssid in state.get("wireless_policy", {}).get("ssids", []):
        if str(ssid.get("ssid", "")).lower() == str(name or "").lower():
            return ssid
    return {}


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _first_usable(cidr: str, offset: int = 40) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(list(net.hosts())[min(offset, max(0, net.num_addresses - 3))])
    except Exception:
        return ""


def normalize_wireless_state(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("wireless_policy", {}).setdefault("ssids", [])
    state.setdefault("ap_inventory", [])
    state.setdefault("clients", [])
    state.setdefault("client_sessions", [])
    state.setdefault("events", [])
    state.setdefault("policy_settings", {}).setdefault("wireless", DEFAULT_POLICY_SETTINGS.copy())
    for key, value in DEFAULT_POLICY_SETTINGS.items():
        state["policy_settings"].setdefault("wireless", {}).setdefault(key, value)
    state.setdefault("policy_studio", {}).setdefault("rules", [dict(r) for r in DEFAULT_POLICY_STUDIO_RULES])

    if not state["ap_inventory"]:
        state["ap_inventory"] = [dict(ap) for ap in DEFAULT_APS]

    # Upgrade old client records into durable session-aware records.
    for c in state["clients"]:
        c.setdefault("id", _client_id(c.get("name", "client")))
        c.setdefault("mac", "00:00:00:00:00:00")
        c.setdefault("status", "associated")
        c.setdefault("last_seen", now_iso())
        ssid = _ssid_by_name(state, c.get("ssid")) or _ssid_for_role(state, c.get("role"))
        if ssid:
            c.setdefault("vlan", str(ssid.get("expected_vlan", "")))
            c.setdefault("services", ssid.get("allowed_services", []))
            c.setdefault("expected_subnet", ssid.get("expected_subnet", ""))

    existing_sessions = {s.get("client") for s in state["client_sessions"]}
    for c in state["clients"]:
        if c.get("name") not in existing_sessions:
            state["client_sessions"].append({
                "id": f"session-{len(state['client_sessions']) + 1}",
                "client": c.get("name"),
                "role": c.get("role"),
                "ssid": c.get("ssid"),
                "ap": c.get("ap"),
                "vlan": str(c.get("vlan", "")),
                "ip": c.get("ip", ""),
                "status": c.get("status", "associated"),
                "started_at": c.get("last_seen", now_iso()),
                "last_event": "association",
            })
    return state


def add_event(state: Dict[str, Any], event_type: str, client: str = "", severity: str = "Info", detail: str = "", **extra):
    event = {
        "id": _event_id(state),
        "type": event_type,
        "client": client,
        "severity": severity,
        "detail": detail,
        "created_at": extra.pop("created_at", now_iso()),
    }
    event.update({k: v for k, v in extra.items() if v not in (None, "")})
    state.setdefault("events", []).insert(0, event)
    return event


def ap_load_analytics(state: Dict[str, Any]) -> Dict[str, Any]:
    normalize_wireless_state(state)
    counts = Counter(c.get("ap") for c in state.get("clients", []) if c.get("status") != "disassociated")
    rows = []
    for ap in state.get("ap_inventory", []):
        current = counts.get(ap.get("name") or ap.get("id"), 0)
        max_clients = int(ap.get("max_clients") or 1)
        pct = round((current / max_clients) * 100, 1) if max_clients else 0
        status = "Critical" if pct >= state["policy_settings"]["wireless"].get("ap_load_critical", 90) else "Warning" if pct >= state["policy_settings"]["wireless"].get("ap_load_warning", 75) else "Healthy"
        rows.append({**ap, "current_clients": current, "load_percent": pct, "health": status})
    distribution = {
        "by_ap": dict(counts),
        "by_ssid": dict(Counter(c.get("ssid") for c in state.get("clients", []) if c.get("status") != "disassociated")),
        "by_role": dict(Counter(c.get("role") for c in state.get("clients", []) if c.get("status") != "disassociated")),
    }
    return {"aps": rows, "distribution": distribution}


def validation_matrix(state: Dict[str, Any], policy_diffs: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    normalize_wireless_state(state)
    rows = []
    ap_by_name = {ap.get("name"): ap for ap in state.get("ap_inventory", [])}
    for c in state.get("clients", []):
        ssid = _ssid_by_name(state, c.get("ssid")) or _ssid_for_role(state, c.get("role"))
        expected_vlan = str(ssid.get("expected_vlan", ""))
        expected_subnet = ssid.get("expected_subnet", "")
        ap = ap_by_name.get(c.get("ap"), {})
        ap_support = expected_vlan in [str(v) for v in ap.get("supported_vlans", [])]
        vlan_ok = str(c.get("vlan", "")) == expected_vlan
        dhcp_ok = _ip_in_cidr(c.get("ip", ""), expected_subnet)
        ssid_role_ok = str(c.get("role", "")).lower() == str(ssid.get("role", "")).lower()
        result = "Pass" if all([vlan_ok, dhcp_ok, ap_support, ssid_role_ok]) else "Fail" if not vlan_ok or not ssid_role_ok else "Review"
        rows.append({
            "client": c.get("name"),
            "role": c.get("role"),
            "ssid": c.get("ssid"),
            "ap": c.get("ap"),
            "expected_vlan": expected_vlan,
            "actual_vlan": str(c.get("vlan", "")),
            "vlan_status": "Pass" if vlan_ok else "Fail",
            "ip": c.get("ip"),
            "dhcp_scope": expected_subnet,
            "dhcp_status": "Pass" if dhcp_ok else "Review",
            "ap_trunk_status": "Pass" if ap_support else "Fail",
            "role_status": "Pass" if ssid_role_ok else "Fail",
            "result": result,
            "confidence": 95 if result == "Pass" else 75 if result == "Review" else 88,
            "confidence_reason": "Matched SSID/VLAN/DHCP/AP support" if result == "Pass" else "Requires extra wired or DHCP evidence" if result == "Review" else "Contradiction between session and policy evidence",
        })
    return rows


def event_to_wired_correlation(state: Dict[str, Any], objects: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    normalize_wireless_state(state)
    correlations = []
    ap_by_name = {ap.get("name"): ap for ap in state.get("ap_inventory", [])}
    for event in state.get("events", [])[:80]:
        client = next((c for c in state.get("clients", []) if c.get("name") == event.get("client")), {})
        ssid = _ssid_by_name(state, event.get("ssid") or client.get("ssid")) or _ssid_for_role(state, client.get("role"))
        ap_name = event.get("to_ap") or event.get("ap") or client.get("ap")
        ap = ap_by_name.get(ap_name, {})
        expected_vlan = str(ssid.get("expected_vlan", client.get("vlan", "")))
        supported = expected_vlan in [str(v) for v in ap.get("supported_vlans", [])] if ap else False
        status = "Pass" if supported else "Review" if event.get("type") in {"import", "simulation", "acl_check"} else "Fail"
        correlations.append({
            "time": event.get("created_at"),
            "event_type": event.get("type"),
            "client": event.get("client"),
            "ssid": ssid.get("ssid", event.get("ssid", "")),
            "expected_vlan": expected_vlan,
            "ap": ap_name or "unknown",
            "wired_path": f"{ap_name or 'Unknown AP'} → {ap.get('switch', 'Unknown switch')} {ap.get('uplink_interface', 'Unknown uplink')} → VLAN {expected_vlan}",
            "status": status,
            "reason": "AP inventory says this AP/uplink supports the expected WLAN VLAN." if supported else "AP inventory does not prove that the expected VLAN is supported on this AP/uplink.",
        })
    return correlations


def anomaly_engine(state: Dict[str, Any], policy_diffs: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    normalize_wireless_state(state)
    settings = state.get("policy_settings", {}).get("wireless", DEFAULT_POLICY_SETTINGS)
    anomalies = []
    matrix = validation_matrix(state, policy_diffs)
    for row in matrix:
        if row["role_status"] == "Fail":
            anomalies.append({"id": f"ROLE-SSID-{row['client']}", "severity": "High", "category": "Role/SSID mismatch", "asset": row["client"], "detail": f"{row['client']} role {row['role']} does not match SSID {row['ssid']} policy.", "recommendation": "Reassign the client to the correct SSID or update the identity group mapping."})
        if row["vlan_status"] == "Fail":
            anomalies.append({"id": f"VLAN-MISMATCH-{row['client']}", "severity": "Critical", "category": "VLAN mismatch", "asset": row["client"], "detail": f"Expected VLAN {row['expected_vlan']} but client is on VLAN {row['actual_vlan']}.", "recommendation": "Fix WLAN role/VLAN mapping and re-authenticate the client."})
        if row["dhcp_status"] != "Pass":
            anomalies.append({"id": f"DHCP-MISMATCH-{row['client']}", "severity": "Medium", "category": "DHCP scope mismatch", "asset": row["client"], "detail": f"Client IP {row['ip']} is not proven inside {row['dhcp_scope']}.", "recommendation": "Check DHCP scope, default-router, and relay helper for the WLAN VLAN."})
        if row["ap_trunk_status"] == "Fail":
            anomalies.append({"id": f"AP-VLAN-{row['client']}", "severity": "High", "category": "AP VLAN support", "asset": row["ap"], "detail": f"{row['ap']} does not support expected VLAN {row['expected_vlan']} for {row['ssid']}.", "recommendation": "Add the WLAN VLAN to the AP uplink trunk or move the client to a compliant AP."})

    analytics = ap_load_analytics(state)
    for ap in analytics["aps"]:
        if ap["health"] in {"Warning", "Critical"}:
            anomalies.append({"id": f"AP-LOAD-{ap['name']}", "severity": "High" if ap["health"] == "Critical" else "Medium", "category": "AP load", "asset": ap["name"], "detail": f"AP load is {ap['load_percent']}% ({ap['current_clients']}/{ap['max_clients']} clients).", "recommendation": "Balance clients, add AP capacity, or tune roaming thresholds."})

    failures = Counter(e.get("client") or e.get("ssid") or "unknown" for e in state.get("events", []) if e.get("type") == "authentication_failure")
    for key, count in failures.items():
        if count >= int(settings.get("auth_failure_threshold", 3)):
            anomalies.append({"id": f"AUTH-FAIL-{key}", "severity": "High", "category": "Authentication failures", "asset": key, "detail": f"{count} authentication failures detected.", "recommendation": "Review credentials, 802.1X/RADIUS, account lockouts, or possible attack attempts."})

    roams = Counter(e.get("client") or "unknown" for e in state.get("events", []) if e.get("type") == "roaming")
    for key, count in roams.items():
        if count >= int(settings.get("roaming_threshold", 4)):
            anomalies.append({"id": f"ROAMING-{key}", "severity": "Medium", "category": "Roaming instability", "asset": key, "detail": f"{count} roaming events detected for one client.", "recommendation": "Check AP overlap, signal quality, sticky client behavior, and band steering."})

    for diff in policy_diffs or []:
        if diff.get("status") != "Pass":
            anomalies.append({"id": f"WIRED-{diff.get('id')}", "severity": diff.get("severity", "Medium"), "category": "Wired policy drift", "asset": diff.get("asset"), "detail": diff.get("actual"), "recommendation": diff.get("recommendation")})

    known_aps = {a.get("name") for a in state.get("ap_inventory", [])}
    for c in state.get("clients", []):
        if c.get("ap") and c.get("ap") not in known_aps:
            anomalies.append({"id": f"UNKNOWN-AP-{c.get('name')}", "severity": settings.get("unknown_ap_severity", "High"), "category": "Unknown AP", "asset": c.get("ap"), "detail": f"Client {c.get('name')} is associated to AP {c.get('ap')} which is not in inventory.", "recommendation": "Add the AP to inventory or investigate rogue/incorrect AP naming."})
        if c.get("status") == "associated" and not c.get("ip"):
            anomalies.append({"id": f"NO-IP-{c.get('name')}", "severity": "Medium", "category": "DHCP missing", "asset": c.get("name"), "detail": f"Associated client {c.get('name')} has no recorded IP lease.", "recommendation": "Import DHCP leases or validate DHCP relay/scope."})

    for rule in ensure_policy_studio(state):
        if not rule.get("enabled", True):
            continue
        cond = rule.get("condition")
        if cond == "guest_internal_blocked":
            for c in state.get("clients", []):
                if c.get("role") == "Guest" and any(s for s in c.get("services", []) if s not in {"Internet", "DNS"}):
                    anomalies.append({"id": f"{rule.get('id')}-{c.get('name')}", "severity": rule.get("severity", "High"), "category": "Policy Studio", "asset": c.get("name"), "detail": f"Policy Studio rule failed: {rule.get('name')}.", "recommendation": rule.get("remediation")})

    for a in anomalies:
        a.setdefault("confidence", 90 if a.get("severity") in {"Critical", "High"} else 75)
        a.setdefault("evidence", f"Wireless matrix/event correlation for {a.get('asset', 'asset')}")
    return anomalies


def wireless_risk_score(state: Dict[str, Any], policy_diffs: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    anomalies = anomaly_engine(state, policy_diffs)
    score = 100
    for a in anomalies:
        sev = a.get("severity")
        score -= 18 if sev == "Critical" else 10 if sev == "High" else 5 if sev == "Medium" else 2
    score = max(0, score)
    return {
        "score": score,
        "grade": "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs Improvement" if score >= 60 else "Critical",
        "risk_level": "Low" if score >= 90 else "Medium" if score >= 60 else "High",
        "anomaly_count": len(anomalies),
        "critical": sum(1 for a in anomalies if a.get("severity") == "Critical"),
        "high": sum(1 for a in anomalies if a.get("severity") == "High"),
    }


def wireless_dashboard(state: Dict[str, Any], policy_diffs: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    normalize_wireless_state(state)
    anomalies = anomaly_engine(state, policy_diffs)
    analytics = ap_load_analytics(state)
    return {
        "analytics": analytics,
        "matrix": validation_matrix(state, policy_diffs),
        "correlations": event_to_wired_correlation(state),
        "anomalies": anomalies,
        "risk": wireless_risk_score(state, policy_diffs),
        "confidence": evidence_confidence_meter(state, policy_diffs),
        "playbooks": wireless_remediation_playbooks(state, anomalies),
        "policy_rules": ensure_policy_studio(state),
    }


def apply_role_change(state: Dict[str, Any], client_name: str, new_role: str) -> Tuple[bool, str]:
    normalize_wireless_state(state)
    client = next((c for c in state.get("clients", []) if c.get("name") == client_name), None)
    if not client:
        return False, "Client not found."
    ssid = _ssid_for_role(state, new_role)
    if not ssid:
        return False, "No SSID profile exists for the selected role."
    old = {"role": client.get("role"), "ssid": client.get("ssid"), "vlan": client.get("vlan"), "ip": client.get("ip")}
    client["role"] = ssid.get("role")
    client["ssid"] = ssid.get("ssid")
    client["vlan"] = str(ssid.get("expected_vlan"))
    client["expected_subnet"] = ssid.get("expected_subnet")
    client["ip"] = _first_usable(ssid.get("expected_subnet", ""), 40 + len(state.get("clients", []))) or client.get("ip", "")
    client["services"] = ssid.get("allowed_services", SSID_SERVICE_MATRIX.get(new_role, []))
    client["last_seen"] = now_iso()
    add_event(
        state,
        "role_change",
        client_name,
        "Info",
        f"Role changed {old['role']} → {client['role']}; SSID {old['ssid']} → {client['ssid']}; VLAN {old['vlan']} → {client['vlan']}; DHCP scope {ssid.get('expected_subnet')}.",
        old_role=old["role"],
        new_role=client["role"],
        old_vlan=old["vlan"],
        new_vlan=client["vlan"],
        ssid=client["ssid"],
        ap=client.get("ap"),
    )
    state.setdefault("client_sessions", []).insert(0, {
        "id": f"session-{len(state.get('client_sessions', [])) + 1}",
        "client": client_name,
        "role": client.get("role"),
        "ssid": client.get("ssid"),
        "ap": client.get("ap"),
        "vlan": client.get("vlan"),
        "ip": client.get("ip"),
        "status": "reauthenticated",
        "started_at": now_iso(),
        "last_event": "role_change",
    })
    return True, "Role change demo completed and validation data refreshed."


def simulate_wireless_event(state: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, str]:
    normalize_wireless_state(state)
    event_type = payload.get("event_type") or payload.get("type") or "association"
    client_name = payload.get("client", "").strip()
    client = next((c for c in state.get("clients", []) if c.get("name") == client_name), None)
    ssid_name = payload.get("ssid") or (client or {}).get("ssid")
    ssid = _ssid_by_name(state, ssid_name)
    severity = "Info"
    detail = ""
    if not client and client_name:
        client = {"id": _client_id(client_name), "name": client_name, "mac": payload.get("mac", "00:00:00:00:00:00"), "role": ssid.get("role", payload.get("role", "Guest")), "ssid": ssid_name, "vlan": str(payload.get("vlan") or ssid.get("expected_vlan", "")), "ip": payload.get("ip") or _first_usable(ssid.get("expected_subnet", "10.10.30.0/24")), "ap": payload.get("to_ap") or payload.get("ap") or "AP-01", "services": ssid.get("allowed_services", [])}
        state.setdefault("clients", []).append(client)
    if not client:
        return False, "Client is required."

    if event_type == "roaming":
        old_ap = payload.get("from_ap") or client.get("ap")
        new_ap = payload.get("to_ap") or payload.get("ap") or client.get("ap")
        client["ap"] = new_ap
        detail = f"{client_name} roamed from {old_ap} to {new_ap} on {client.get('ssid')}."
        add_event(state, "roaming", client_name, severity, detail, from_ap=old_ap, to_ap=new_ap, ssid=client.get("ssid"), vlan=client.get("vlan"))
    elif event_type == "authentication_failure":
        severity = "Medium"
        detail = f"Authentication failure for {client_name} on {ssid_name or client.get('ssid')}."
        add_event(state, "authentication_failure", client_name, severity, detail, ssid=ssid_name or client.get("ssid"), ap=payload.get("ap") or client.get("ap"), result="failed")
    elif event_type == "disassociation":
        client["status"] = "disassociated"
        detail = f"{client_name} disassociated from {client.get('ssid')} on {client.get('ap')}."
        add_event(state, "disassociation", client_name, severity, detail, ssid=client.get("ssid"), ap=client.get("ap"))
    elif event_type == "dhcp_assignment":
        client["ip"] = payload.get("ip") or client.get("ip")
        if payload.get("vlan"):
            client["vlan"] = str(payload.get("vlan"))
        detail = f"DHCP assigned {client.get('ip')} to {client_name} on VLAN {client.get('vlan')}."
        add_event(state, "dhcp_assignment", client_name, severity, detail, ip=client.get("ip"), vlan=client.get("vlan"), ssid=client.get("ssid"))
    elif event_type == "policy_violation":
        severity = "High"
        detail = payload.get("detail") or f"Policy violation recorded for {client_name}."
        add_event(state, "policy_violation", client_name, severity, detail, ssid=client.get("ssid"), ap=client.get("ap"), vlan=client.get("vlan"))
    else:
        # association/default
        client["status"] = "associated"
        if ssid:
            client["ssid"] = ssid.get("ssid")
            client["role"] = ssid.get("role")
            client["vlan"] = str(payload.get("vlan") or ssid.get("expected_vlan"))
            client["services"] = ssid.get("allowed_services", [])
        if payload.get("to_ap") or payload.get("ap"):
            client["ap"] = payload.get("to_ap") or payload.get("ap")
        if payload.get("ip"):
            client["ip"] = payload.get("ip")
        detail = f"{client_name} associated to {client.get('ssid')} on {client.get('ap')} with VLAN {client.get('vlan')}."
        add_event(state, "association", client_name, severity, detail, ssid=client.get("ssid"), ap=client.get("ap"), vlan=client.get("vlan"), ip=client.get("ip"))

    client["last_seen"] = now_iso()
    state.setdefault("client_sessions", []).insert(0, {
        "id": f"session-{len(state.get('client_sessions', [])) + 1}",
        "client": client_name,
        "role": client.get("role"),
        "ssid": client.get("ssid"),
        "ap": client.get("ap"),
        "vlan": client.get("vlan"),
        "ip": client.get("ip"),
        "status": client.get("status", "associated"),
        "started_at": now_iso(),
        "last_event": event_type,
    })
    return True, detail


def import_events_payload(state: Dict[str, Any], filename: str, raw: bytes) -> Tuple[int, List[str]]:
    normalize_wireless_state(state)
    errors = []
    text = raw.decode("utf-8", errors="replace")
    events = []
    if filename.lower().endswith(".json"):
        data = json.loads(text)
        events = data if isinstance(data, list) else data.get("events", [])
    else:
        reader = csv.DictReader(io.StringIO(text))
        events = list(reader)
    count = 0
    for item in events:
        try:
            ok, msg = simulate_wireless_event(state, item)
            if ok:
                count += 1
            else:
                errors.append(msg)
        except Exception as exc:
            errors.append(str(exc))
    return count, errors[:10]


def add_or_update_ap(state: Dict[str, Any], form: Dict[str, Any]) -> str:
    normalize_wireless_state(state)
    name = (form.get("name") or form.get("id") or "").strip()
    if not name:
        raise ValueError("AP name is required.")
    supported = [v.strip() for v in str(form.get("supported_vlans", "")).replace(",", " ").split() if v.strip()]
    ap = next((a for a in state["ap_inventory"] if a.get("name") == name or a.get("id") == name), None)
    if not ap:
        ap = {"id": _ap_id(name), "name": name}
        state["ap_inventory"].append(ap)
    ap.update({
        "location": form.get("location", ap.get("location", "")),
        "switch": form.get("switch", ap.get("switch", "")),
        "uplink_interface": form.get("uplink_interface", ap.get("uplink_interface", "")),
        "supported_vlans": supported or ap.get("supported_vlans", []),
        "max_clients": int(form.get("max_clients") or ap.get("max_clients") or 25),
        "status": form.get("status", ap.get("status", "online")),
        "vendor": form.get("vendor", ap.get("vendor", "manual")),
        "serial": form.get("serial", ap.get("serial", "")),
        "model": form.get("model", ap.get("model", "")),
    })
    add_event(state, "ap_inventory", name, "Info", f"AP inventory updated for {name}.", ap=name)
    return name


def add_or_update_ssid(state: Dict[str, Any], form: Dict[str, Any]) -> str:
    normalize_wireless_state(state)
    name = (form.get("ssid") or "").strip()
    if not name:
        raise ValueError("SSID name is required.")
    item = next((s for s in state["wireless_policy"]["ssids"] if s.get("ssid") == name), None)
    if not item:
        item = {"ssid": name}
        state["wireless_policy"]["ssids"].append(item)
    allowed = [s.strip() for s in str(form.get("allowed_services", "")).split(",") if s.strip()]
    item.update({
        "role": form.get("role", item.get("role", "Guest")),
        "expected_vlan": str(form.get("expected_vlan") or item.get("expected_vlan", "")),
        "expected_subnet": form.get("expected_subnet", item.get("expected_subnet", "")),
        "dhcp_scope": form.get("dhcp_scope", item.get("dhcp_scope", "")),
        "security": form.get("security", item.get("security", "WPA2")),
        "internet": form.get("internet", "true") in {"true", "on", "1", True},
        "internal_access": form.get("internal_access", item.get("internal_access", "limited")),
        "client_isolation": form.get("client_isolation", "false") in {"true", "on", "1", True},
        "allowed_services": allowed or item.get("allowed_services", []),
        "business_purpose": form.get("business_purpose", item.get("business_purpose", "")),
    })
    if item["internal_access"] == "true":
        item["internal_access"] = True
    elif item["internal_access"] == "false":
        item["internal_access"] = False
    add_event(state, "ssid_policy", name, "Info", f"SSID policy updated for {name}.", ssid=name, vlan=item.get("expected_vlan"))
    return name

DEFAULT_POLICY_STUDIO_RULES = [
    {
        "id": "PS-GUEST-DENY-INTERNAL", "enabled": True, "name": "Guest must be isolated from internal services", "scope": "Guest", "condition": "guest_internal_blocked", "condition_left": "ssid.internal_access", "operator": "equals", "condition_value": "false", "condition_expression": "ssid.internal_access equals false AND applied ACL deny exists",
        "severity": "Critical", "severity_score": 95, "owner": "Security", "control_mapping": "ISO27001-A.8.22 / NIST-AC-4", "evidence_required": "VLAN gateway + applied ACL + show access-lists", "false_positive_guard": "Do not pass on ACL text alone; require ip access-group binding on the guest gateway.", "acceptance_criteria": "Guest VLAN has an inbound/outbound deny to internal subnets and Internet/DNS still allowed.", "action_type": "block_report_pass", "remediation": "Apply guest isolation ACL inbound on the guest VLAN gateway and verify with show access-lists + show running-config interface.", "version": 1,
    },
    {
        "id": "PS-ROLE-SSID-MATCH", "enabled": True, "name": "Client role must match SSID role", "scope": "All", "condition": "role_ssid_match", "condition_left": "client.role", "operator": "equals", "condition_value": "ssid.role", "condition_expression": "client.role equals ssid.role",
        "severity": "High", "severity_score": 78, "owner": "Wireless", "control_mapping": "Identity-to-network authorization", "evidence_required": "Client session + SSID policy matrix", "false_positive_guard": "Ignore stale client rows older than the active import unless a live event confirms association.", "acceptance_criteria": "Client role, SSID role, VLAN and DHCP subnet align.", "action_type": "create_anomaly", "remediation": "Fix identity group mapping or move the user to the correct SSID.", "version": 1,
    },
    {
        "id": "PS-AP-VLAN-SUPPORT", "enabled": True, "name": "AP uplink must support expected VLAN", "scope": "All APs", "condition": "ap_vlan_support", "condition_left": "ap.supported_vlans", "operator": "contains", "condition_value": "ssid.expected_vlan", "condition_expression": "ap.supported_vlans contains ssid.expected_vlan",
        "severity": "High", "severity_score": 74, "owner": "Network", "control_mapping": "Wireless-to-wired trunk consistency", "evidence_required": "AP inventory + show interfaces trunk", "false_positive_guard": "Prefer operational trunk evidence over planned AP inventory only.", "acceptance_criteria": "Every AP serving the SSID has the expected VLAN on its uplink trunk.", "action_type": "raise_risk", "remediation": "Add missing WLAN VLANs to AP uplink trunks and regenerate validation.", "version": 1,
    },
    {
        "id": "PS-MGMT-PLANE-HARDENING", "enabled": True, "name": "Management plane must avoid weak services", "scope": "Network devices", "condition": "security_hardening", "condition_left": "device.security_hardening", "operator": "not_contains", "condition_value": "weak", "condition_expression": "no telnet, enable password, insecure HTTP, or exposed SNMP community indicators",
        "severity": "High", "severity_score": 81, "owner": "Security", "control_mapping": "CIS Cisco IOS / NIST-CM-7", "evidence_required": "running-config hardening lines", "false_positive_guard": "Flag only when direct config line evidence exists.", "acceptance_criteria": "SSH-only VTY, enable secret, AAA/local auth, and no insecure HTTP/Telnet evidence.", "action_type": "require_manual_review", "remediation": "Disable Telnet/HTTP, replace enable password with enable secret, restrict SNMP and enforce SSH.", "version": 1,
    },

    {
        "id": "PS-ACL-RUNTIME-HITS", "enabled": True, "name": "Segmentation ACLs should have runtime counters", "scope": "Segmentation", "condition": "acl_hit_counts", "condition_left": "acl.matches", "operator": "greater_than", "condition_value": "0", "condition_expression": "show access-lists counter evidence exists for enforced segmentation ACLs",
        "severity": "Medium", "severity_score": 58, "owner": "Security", "control_mapping": "Evidence-based enforcement validation", "evidence_required": "show access-lists output with match counters", "false_positive_guard": "Treat zero counters as Review unless traffic simulation was executed.", "acceptance_criteria": "At least one active deny/permit ACL line has runtime counter evidence or a documented test result.", "action_type": "raise_risk", "remediation": "Run a controlled access test, capture show access-lists counters, and attach the evidence.", "version": 1,
    },
    {
        "id": "PS-VLAN-TRUNK-CROSSCHECK", "enabled": True, "name": "Configured VLANs must be present on operational trunks", "scope": "Switching", "condition": "vlan_crosscheck", "condition_left": "vlan.missing_from_trunks", "operator": "equals", "condition_value": "0", "condition_expression": "configured/access/DHCP VLANs are included in trunk allowed or forwarding evidence",
        "severity": "High", "severity_score": 82, "owner": "Network", "control_mapping": "L2 path assurance", "evidence_required": "show vlan brief + show interfaces trunk + running-config", "false_positive_guard": "Do not fail if operational trunk output was not imported; mark Needs Evidence instead.", "acceptance_criteria": "Every production policy VLAN appears in trunk allowed/forwarding evidence.", "action_type": "block_report_pass", "remediation": "Add missing VLANs to the trunk or update policy inventory, then re-import operational trunk output.", "version": 1,
    },
    {
        "id": "PS-INTERFACE-ERROR-HEALTH", "enabled": True, "name": "Critical uplinks should not show physical error counters", "scope": "Operations", "condition": "interface_counters", "condition_left": "interface.errors", "operator": "equals", "condition_value": "0", "condition_expression": "input/output/CRC errors are zero on uplinks and AP trunks",
        "severity": "Medium", "severity_score": 54, "owner": "Network Operations", "control_mapping": "Availability / network health", "evidence_required": "show interfaces counters or show interfaces detail", "false_positive_guard": "Only escalate when direct counter evidence maps to an uplink/trunk or repeated live events corroborate it.", "acceptance_criteria": "No CRC/input/output error evidence on critical wireless path interfaces.", "action_type": "create_anomaly", "remediation": "Inspect cable/SFP/duplex, clear counters, monitor again, and document the before/after state.", "version": 1,
    },
    {
        "id": "PS-EVIDENCE-COMPLETENESS", "enabled": True, "name": "Reports must disclose missing evidence before claiming pass", "scope": "Reporting", "condition": "evidence_profile", "condition_left": "evidence.confidence", "operator": "greater_than", "condition_value": "0.70", "condition_expression": "line-level evidence confidence >= 70% OR missing commands are explicitly listed",
        "severity": "Medium", "severity_score": 62, "owner": "Assurance", "control_mapping": "Audit defensibility", "evidence_required": "conversion readiness score + missing command checklist + evidence profile", "false_positive_guard": "Do not punish native .pkt uploads; disclose reduced confidence and ask for exported show commands.", "acceptance_criteria": "Technical report includes readiness score, missing commands, and traceability stats.", "action_type": "require_manual_review", "remediation": "Import the missing show-command bundle or keep the finding in Needs More Evidence.", "version": 1,
    },
]


def ensure_policy_studio(state: Dict[str, Any]):
    studio = state.setdefault("policy_studio", {})
    rules = studio.setdefault("rules", [dict(r) for r in DEFAULT_POLICY_STUDIO_RULES])
    existing = {r.get("id") for r in rules}
    for default in DEFAULT_POLICY_STUDIO_RULES:
        if default.get("id") not in existing:
            rules.append(dict(default))
    severity_map = {"Critical": 95, "High": 75, "Medium": 50, "Low": 25, "Info": 10}
    for rule in rules:
        sev = rule.get("severity", "Medium")
        rule.setdefault("severity_score", severity_map.get(sev, 50))
        rule.setdefault("condition_left", "client.role")
        rule.setdefault("operator", "equals")
        rule.setdefault("condition_value", "")
        rule.setdefault("condition_expression", f"{rule.get('condition_left')} {rule.get('operator')} {rule.get('condition_value')}")
        rule.setdefault("control_mapping", "Wireless Segmentation")
        rule.setdefault("evidence_required", "current imported evidence")
        rule.setdefault("false_positive_guard", "Require line-level evidence or a correlated live event before marking a finding as confirmed.")
        rule.setdefault("acceptance_criteria", "Finding is considered fixed only after re-imported evidence changes the check to Pass.")
        rule.setdefault("action_type", "create_anomaly")
        rule.setdefault("version", 1)
    return rules


def add_or_update_policy_rule(state: Dict[str, Any], form: Dict[str, Any]) -> str:
    normalize_wireless_state(state)
    rules = ensure_policy_studio(state)
    rid = (form.get("id") or form.get("rule_id") or "").strip().upper().replace(" ", "-")
    if not rid:
        rid = f"PS-CUSTOM-{len(rules)+1:03d}"
    rule = next((r for r in rules if r.get("id") == rid), None)
    if not rule:
        rule = {"id": rid}
        rules.append(rule)
    current_version = int(rule.get("version", 0) or 0)
    condition = form.get("condition", rule.get("condition", "role_ssid_match"))
    left = form.get("condition_left", rule.get("condition_left", "client.role"))
    operator = form.get("operator", rule.get("operator", "equals"))
    value = form.get("condition_value", rule.get("condition_value", ""))
    rule.update({
        "enabled": form.get("enabled", "on") in {"on", "true", "1", True},
        "name": form.get("name", rule.get("name", "Custom wireless policy rule")),
        "scope": form.get("scope", rule.get("scope", "All")),
        "condition": condition,
        "condition_left": left,
        "operator": operator,
        "condition_value": value,
        "condition_expression": f"{left} {operator} {value}".strip(),
        "severity": form.get("severity", rule.get("severity", "Medium")),
        "severity_score": {"Critical": 95, "High": 75, "Medium": 50, "Low": 25, "Info": 10}.get(form.get("severity", rule.get("severity", "Medium")), 50),
        "owner": form.get("owner", rule.get("owner", "Wireless Team")),
        "control_mapping": form.get("control_mapping", rule.get("control_mapping", "Wireless Segmentation")),
        "action_type": form.get("action_type", rule.get("action_type", "create_anomaly")),
        "evidence_required": form.get("evidence_required", rule.get("evidence_required", "current imported evidence")),
        "false_positive_guard": form.get("false_positive_guard", rule.get("false_positive_guard", "Require corroborated evidence before confirming.")),
        "acceptance_criteria": form.get("acceptance_criteria", rule.get("acceptance_criteria", "Re-import evidence and confirm Pass state.")),
        "remediation": form.get("remediation", rule.get("remediation", "Review the affected SSID/VLAN/client mapping and revalidate.")),
        "version": current_version + 1,
        "updated_at": now_iso(),
    })
    add_event(state, "policy_rule", rid, "Info", f"Policy Studio rule saved: {rule['name']}.")
    return rid


def delete_policy_rule(state: Dict[str, Any], rule_id: str) -> bool:
    rules = ensure_policy_studio(state)
    before = len(rules)
    state["policy_studio"]["rules"] = [r for r in rules if r.get("id") != rule_id]
    if len(state["policy_studio"]["rules"]) != before:
        add_event(state, "policy_rule_delete", rule_id, "Info", f"Policy Studio rule deleted: {rule_id}.")
        return True
    return False


def add_or_update_client(state: Dict[str, Any], form: Dict[str, Any]) -> str:
    normalize_wireless_state(state)
    name = (form.get("name") or form.get("client") or "").strip()
    if not name:
        raise ValueError("Client name is required.")
    ssid = _ssid_by_name(state, form.get("ssid")) or _ssid_for_role(state, form.get("role"))
    client = next((c for c in state.get("clients", []) if c.get("name") == name), None)
    if not client:
        client = {"id": _client_id(name), "name": name}
        state.setdefault("clients", []).append(client)
    client.update({
        "mac": form.get("mac", client.get("mac", "00:00:00:00:00:00")),
        "role": form.get("role") or ssid.get("role") or client.get("role", "Guest"),
        "ssid": form.get("ssid") or ssid.get("ssid") or client.get("ssid", "GuestWiFi"),
        "vlan": str(form.get("vlan") or ssid.get("expected_vlan") or client.get("vlan", "")),
        "expected_subnet": ssid.get("expected_subnet", client.get("expected_subnet", "")),
        "ip": form.get("ip") or client.get("ip") or _first_usable(ssid.get("expected_subnet", "10.10.30.0/24")),
        "ap": form.get("ap") or client.get("ap", "AP-01"),
        "status": form.get("status", client.get("status", "associated")),
        "services": ssid.get("allowed_services", client.get("services", [])),
        "last_seen": now_iso(),
    })
    add_event(state, "client_save", name, "Info", f"Client session profile saved for {name}.", ssid=client.get("ssid"), ap=client.get("ap"), vlan=client.get("vlan"))
    return name


def delete_client(state: Dict[str, Any], name: str) -> bool:
    normalize_wireless_state(state)
    before = len(state.get("clients", []))
    state["clients"] = [c for c in state.get("clients", []) if c.get("name") != name]
    state["client_sessions"] = [s for s in state.get("client_sessions", []) if s.get("client") != name]
    if len(state["clients"]) != before:
        add_event(state, "client_delete", name, "Medium", f"Client deleted: {name}.")
        return True
    return False


def delete_ap(state: Dict[str, Any], name: str) -> bool:
    normalize_wireless_state(state)
    before = len(state.get("ap_inventory", []))
    state["ap_inventory"] = [a for a in state.get("ap_inventory", []) if a.get("name") != name and a.get("id") != name]
    if len(state["ap_inventory"]) != before:
        add_event(state, "ap_delete", name, "Medium", f"AP removed from inventory: {name}.")
        return True
    return False


def delete_ssid(state: Dict[str, Any], name: str) -> bool:
    normalize_wireless_state(state)
    before = len(state.get("wireless_policy", {}).get("ssids", []))
    state["wireless_policy"]["ssids"] = [s for s in state["wireless_policy"].get("ssids", []) if s.get("ssid") != name]
    if len(state["wireless_policy"]["ssids"]) != before:
        add_event(state, "ssid_delete", name, "Medium", f"SSID removed from policy: {name}.")
        return True
    return False


def evidence_confidence_meter(state: Dict[str, Any], policy_diffs: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    normalize_wireless_state(state)
    sources = 0
    reasons = []
    if state.get("active_extraction", {}).get("objects"):
        sources += 35
        reasons.append("wired config evidence")
    if state.get("events"):
        sources += 20
        reasons.append("wireless event log")
    if state.get("ap_inventory"):
        sources += 15
        reasons.append("AP inventory")
    if state.get("client_sessions"):
        sources += 15
        reasons.append("client sessions")
    if state.get("wireless_policy", {}).get("ssids"):
        sources += 15
        reasons.append("SSID policy database")
    fail_count = sum(1 for d in policy_diffs or [] if d.get("status") != "Pass")
    score = max(20, min(100, sources - min(20, fail_count * 2)))
    return {"score": score, "level": "High" if score >= 80 else "Medium" if score >= 55 else "Low", "reasons": reasons, "wired_drift_penalty": min(20, fail_count * 2)}


def wireless_remediation_playbooks(state: Dict[str, Any], anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    playbooks = []
    for a in anomalies[:30]:
        cat = a.get("category", "Wireless anomaly")
        commands = ["show wlan summary", "show wireless client summary", "show interfaces trunk"]
        if cat == "AP VLAN support":
            commands = ["show interfaces trunk", "show running-config interface <ap-uplink>", "switchport trunk allowed vlan add <missing-vlan>"]
        elif cat == "VLAN mismatch":
            commands = ["show wlan id <id>", "show client detail <mac>", "clear wireless client mac <mac>"]
        elif cat == "DHCP scope mismatch":
            commands = ["show ip dhcp binding", "show ip dhcp pool", "show running-config | section dhcp"]
        elif cat == "Authentication failures":
            commands = ["show logging | include RADIUS", "show aaa servers", "test aaa group radius <user> <pass> legacy"]
        elif cat == "Roaming instability":
            commands = ["show wireless client mac <mac> detail", "show ap auto-rf", "show wireless stats client detail"]
        playbooks.append({
            "id": f"PB-{a.get('id', cat)}",
            "finding": a.get("id", cat),
            "severity": a.get("severity", "Medium"),
            "title": f"Remediate {cat}",
            "why": a.get("detail", "Review wireless policy evidence."),
            "fix": a.get("recommendation", "Correct the affected wireless policy object and revalidate."),
            "verify": commands,
            "rollback": "Revert the changed WLAN/VLAN/ACL setting and restore the previous validated backup if impact is observed.",
        })
    return playbooks
