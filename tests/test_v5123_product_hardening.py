from wiguard.services.intelligence import object_count_breakdown
from wiguard.services.reporting import sanitize_export_payload


def test_object_count_breakdown_separates_real_objects_from_evidence_rows():
    objects = {
        "devices": [{"hostname": "R1"}],
        "interfaces": [{"name": "Gig0/0"}],
        "source_key_value_index": [{"path": "$.devices[0].hostname", "value": "R1"} for _ in range(5)],
        "raw_evidence": [{"preview": "enable secret supersecret"}],
        "native_source_manifest": [{"filename": "lab.pkt"}],
    }

    breakdown = object_count_breakdown(objects)

    assert breakdown["real_object_count"] == 2
    assert breakdown["evidence_entry_count"] >= 7
    assert breakdown["total_extracted_entries"] >= 9


def test_export_sanitizer_redacts_sensitive_keys_and_values():
    payload = {
        "username": "admin",
        "password": "P@ssw0rd!",
        "headers": {"Authorization": "Bearer eyJhbGciOiJVeryLongTokenValue"},
        "config": "snmp-server community public RO\nenable secret 5 abcdefgh\nusername bob secret bobpass",
        "nested": [{"api_key": "abc123456789"}],
    }

    clean = sanitize_export_payload(payload)

    assert clean["password"] == "[REDACTED]"
    assert clean["headers"]["Authorization"] == "[REDACTED]"
    assert "public" not in clean["config"]
    assert "abcdefgh" not in clean["config"]
    assert clean["nested"][0]["api_key"] == "[REDACTED]"
