import json

from wiguard.services.structured_import import StructuredEvidenceNormalizer


def test_packet_tracer_lab_result_matrix_is_understood():
    payload = [
        {
            "client": "m.salem",
            "target": "203.0.113.10",
            "service": "Internet",
            "result": "Success",
            "event": "acl_check",
            "actual_ssid": "StaffWiFi",
            "actual_vlan": "10",
            "actual_ip": "10.10.10.21",
            "ap_name": "AP-STAFF",
            "details": "Internet is reachable for m.salem.",
        },
        {
            "client": "student_2044",
            "target": "10.10.50.10",
            "service": "ERP",
            "result": "Failed",
            "event": "acl_check",
            "actual_ssid": "StudentsWiFi",
            "actual_vlan": "20",
            "actual_ip": "10.10.20.21",
            "ap_name": "AP-STU-2",
            "details": "ERP is blocked / unavailable for student_2044.",
        },
        {
            "client": "student_2044",
            "target": "AP-STU-2",
            "event": "roaming",
            "ap_name": "AP-STU-2",
            "details": "Lab results updated from dashboard.",
        },
    ]

    objects, text, summary = StructuredEvidenceNormalizer().normalize_json(payload)

    assert summary["status"] == "understood"
    assert summary["normalizer"] == "structured_json_xml_v3_lab_matrix"
    assert len(objects["access_tests"]) == 2
    assert len(objects["client_access_matrix"]) == 2
    assert len(objects["roaming_events"]) == 1
    assert len(objects["wireless_hints"]) >= 2
    assert {v["id"] for v in objects["vlans"]} >= {"10", "20"}
    assert objects["lab_result_summary"][0]["success"] == 1
    assert objects["lab_result_summary"][0]["failed"] == 1
    assert any("expected policy baseline" in f["title"].lower() for f in objects["validation_findings"])
