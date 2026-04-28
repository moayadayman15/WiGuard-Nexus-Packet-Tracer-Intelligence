from pathlib import Path
from wiguard.services.seed import seed_state
from wiguard.services.wireless import (
    normalize_wireless_state, add_or_update_client, add_or_update_policy_rule,
    wireless_dashboard, delete_client
)
from wiguard.services.compliance import build_compliance_matrix
from wiguard.services.connectors import import_connector_payload
from wiguard.services.database import AppDatabase


def test_password_policy_and_migrations(tmp_path):
    db = AppDatabase(tmp_path / "wiguard.sqlite3")
    assert db.migrations()
    assert db.validate_password_policy("weak")
    user = db.create_user("engineer1", "StrongPass!123", "engineer")
    assert user["role"] == "engineer"
    allowed, _ = db.login_allowed("engineer1", "127.0.0.1")
    assert allowed


def test_policy_studio_and_client_crud():
    state = seed_state()
    normalize_wireless_state(state)
    rid = add_or_update_policy_rule(state, {"id": "PS-TEST", "name": "Test rule", "condition": "role_ssid_match", "severity": "High"})
    assert rid == "PS-TEST"
    client = add_or_update_client(state, {"name": "new_client", "role": "Guest", "ssid": "GuestWiFi", "ap": "AP-03"})
    assert client == "new_client"
    dash = wireless_dashboard(state, [])
    assert "confidence" in dash
    assert dash["matrix"]
    assert delete_client(state, "new_client")


def test_connector_and_compliance():
    state = seed_state()
    raw = b"client,ssid,ap,vlan,ip\nclient_x,GuestWiFi,AP-03,30,10.10.30.77\n"
    count, errors = import_connector_payload(state, "generic_wlc_clients", "clients.csv", raw)
    assert count == 1
    assert not errors
    dash = wireless_dashboard(state, [])
    controls = build_compliance_matrix(state, dash, [])
    assert any(c["id"] == "CTRL-SSID-VLAN" for c in controls)
