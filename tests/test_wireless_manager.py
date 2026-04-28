from wiguard.services.seed import seed_state
from wiguard.services.wireless import (
    normalize_wireless_state, wireless_dashboard, apply_role_change,
    simulate_wireless_event, import_events_payload
)
from wiguard.services.intelligence import build_report


def test_wireless_dashboard_has_required_project4_outputs():
    state = seed_state()
    normalize_wireless_state(state)
    dashboard = wireless_dashboard(state, [])
    assert len(state["wireless_policy"]["ssids"]) >= 3
    assert len(state["ap_inventory"]) >= 3
    assert dashboard["matrix"]
    assert "score" in dashboard["risk"]


def test_role_change_demo_updates_vlan_dhcp_and_services():
    state = seed_state()
    ok, message = apply_role_change(state, "student_2044", "Staff")
    assert ok, message
    client = next(c for c in state["clients"] if c["name"] == "student_2044")
    assert client["role"] == "Staff"
    assert client["ssid"] == "StaffWiFi"
    assert client["vlan"] == "10"
    assert "ERP" in client["services"]


def test_event_import_accepts_csv():
    state = seed_state()
    payload = b"timestamp,event_type,client,ssid,to_ap,vlan,ip\n2026-04-27 12:00:00,authentication_failure,guest_01,GuestWiFi,AP-03,30,10.10.30.55\n"
    count, errors = import_events_payload(state, "events.csv", payload)
    assert count == 1
    assert not errors


def test_wireless_report_contains_matrix_and_anomalies():
    state = seed_state()
    simulate_wireless_event(state, {"event_type": "roaming", "client": "student_2044", "to_ap": "AP-03"})
    report = build_report(state, "wireless")
    assert report["wireless"]["matrix"]
    assert "risk" in report["wireless"]
