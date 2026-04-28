from typing import Dict, Any, List


def build_compliance_matrix(state: Dict[str, Any], wireless: Dict[str, Any], diffs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalies = wireless.get("anomalies", []) if wireless else []
    matrix = wireless.get("matrix", []) if wireless else []
    failed_clients = [r for r in matrix if r.get("result") != "Pass"]
    failed_diffs = [d for d in diffs if d.get("status") != "Pass"]

    def evidence_id(prefix, count):
        return f"{prefix}-{count:03d}"

    controls = [
        {
            "id": "CTRL-GUEST-ISOLATION",
            "control": "Guest isolation",
            "status": "Fail" if any("Guest" in str(a.get("detail", "")) or "Guest" in str(a.get("asset", "")) for a in anomalies) else "Pass",
            "risk": "High",
            "evidence": evidence_id("WLAN", len(anomalies)),
            "requirement": "Guest users must not reach internal networks or trusted services.",
        },
        {
            "id": "CTRL-SSID-VLAN",
            "control": "SSID to VLAN mapping",
            "status": "Fail" if any(a.get("category") == "VLAN mismatch" for a in anomalies) else "Pass",
            "risk": "High",
            "evidence": evidence_id("MATRIX", len(matrix)),
            "requirement": "Each SSID must assign clients to the expected VLAN.",
        },
        {
            "id": "CTRL-DHCP-ACCURACY",
            "control": "DHCP scope accuracy",
            "status": "Review" if any(a.get("category") == "DHCP scope mismatch" for a in anomalies) else "Pass",
            "risk": "Medium",
            "evidence": evidence_id("DHCP", len(failed_clients)),
            "requirement": "Wireless clients must receive IPs from their assigned role subnet.",
        },
        {
            "id": "CTRL-AP-TRUNK",
            "control": "AP trunk coverage",
            "status": "Fail" if any(a.get("category") == "AP VLAN support" for a in anomalies) else "Pass",
            "risk": "High",
            "evidence": evidence_id("PATH", len(wireless.get("correlations", [])) if wireless else 0),
            "requirement": "AP uplinks must carry the VLANs required by hosted SSIDs.",
        },
        {
            "id": "CTRL-WIRED-POLICY",
            "control": "Wired policy alignment",
            "status": "Review" if failed_diffs else "Pass",
            "risk": "Medium",
            "evidence": evidence_id("DIFF", len(failed_diffs)),
            "requirement": "Wireless expectations must match extracted switch/router evidence.",
        },
        {
            "id": "CTRL-AUDIT-TRAIL",
            "control": "Administrative audit trail",
            "status": "Pass" if state.get("events") else "Review",
            "risk": "Low",
            "evidence": evidence_id("AUDIT", len(state.get("events", []))),
            "requirement": "Sensitive changes must create an event or audit trail entry.",
        },
    ]
    return controls
