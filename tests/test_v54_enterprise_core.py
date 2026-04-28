import io
import json
from wiguard.services.connectors import import_connector_payload, check_connector_credentials
from wiguard.services.database import AppDatabase


def test_vendor_connector_import_normalizes_meraki_ap_export(tmp_path):
    state = {"events": [], "ap_inventory": [], "clients": [], "wireless_policy": {"ssids": []}}
    raw = json.dumps([{"name": "MR-01", "model": "MR46", "serial": "Q2XX-123", "address": "HQ", "tags": ["corp"], "vlans": [10, 20, 30]}]).encode()
    count, errors = import_connector_payload(state, "meraki_api", "meraki.json", raw)
    assert count == 1
    assert not errors
    assert any(ap["name"] == "MR-01" and ap.get("vendor") == "meraki_api" for ap in state["ap_inventory"])


def test_syslog_ingestion_deduplicates_with_database(tmp_path):
    db = AppDatabase(tmp_path / "wiguard.sqlite3")
    state = {"events": [], "ap_inventory": [], "clients": [], "wireless_policy": {"ssids": []}}
    raw = json.dumps([{"timestamp": "2026-04-28T10:00:00Z", "client": "aa:bb", "message": "authentication fail on StaffWiFi"}]).encode()
    count1, errors1 = import_connector_payload(state, "syslog_events", "syslog.json", raw, db=db, live=True)
    count2, errors2 = import_connector_payload(state, "syslog_events", "syslog.json", raw, db=db, live=True)
    assert count1 == 1 and not errors1
    assert count2 == 0 and not errors2


def test_api_token_hash_and_verify(tmp_path):
    db = AppDatabase(tmp_path / "wiguard.sqlite3")
    created = db.create_api_token("ingest", ["read", "ingest"], "tenant-main", "admin")
    assert created["token"].startswith("wgn_")
    tokens = db.list_api_tokens()
    assert tokens and tokens[0]["token_prefix"] == created["prefix"]
    verified = db.verify_api_token(created["token"], "127.0.0.1")
    assert verified["tenant_id"] == "tenant-main"
    assert "ingest" in verified["scopes"]


def test_connector_import_only_credential_test():
    result = check_connector_credentials("radius_accounting")
    assert result["ok"] is True
    assert result["status"] == "import-only"
