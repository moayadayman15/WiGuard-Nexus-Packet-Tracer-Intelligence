from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService
from wiguard.services.intelligence import (
    build_extraction_diagnostics,
    build_topology_insights,
    build_validation_rule_assessment,
    build_report,
)


class FakeUpload:
    def __init__(self, filename, data):
        self.filename = filename
        self._data = data

    def read(self):
        return self._data


def _state_from_result(result):
    return {
        "active_extraction": {
            "filename": result["filename"],
            "source_mode": result["source_mode"],
            "objects": result["objects"],
            "conversion_profile": result.get("conversion_profile", {}),
            "pipeline": result.get("pipeline", []),
        },
        "projects": [{"id": "main", "name": "Main"}],
        "current_project": "main",
        "wireless_policy": {"ssids": []},
        "rules": [],
    }


def test_v591_diagnostics_are_truth_first_for_native_pkt(tmp_path):
    native = FakeUpload("lab.pkt", b"PKT\x00opaque native content hostname R1")
    result = PacketTracerImportService(tmp_path).extract(native)
    diag = build_extraction_diagnostics(_state_from_result(result))

    assert diag["native_packet_tracer"] is True
    assert diag["can_claim_full_fidelity"] is False
    assert any(b["id"] == "PT-COMPANION-EXPORT-MISSING" for b in diag["blockers"])
    assert diag["recommended_actions"]


def test_v591_diagnostics_topology_and_reports_with_companion_export(tmp_path):
    native = FakeUpload("campus.pkt", b"PKT\x00hostname R1 interface GigabitEthernet0/0 vlan 10")
    companion = FakeUpload(
        "campus_export.cfg",
        b"hostname R1\n"
        b"interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        b"interface GigabitEthernet0/1\n switchport mode access\n switchport access vlan 10\n"
        b"vlan 10\n name STAFF\n",
    )
    result = PacketTracerImportService(tmp_path).extract(native, companion_file=companion)
    state = _state_from_result(result)

    diag = build_extraction_diagnostics(state)
    topology = build_topology_insights(state)
    rules = build_validation_rule_assessment(state)
    report = build_report(state, "packet_tracer")

    assert diag["tier"] == "native_plus_companion_export"
    assert diag["evidence_summary"]["verified"] > 0
    assert topology["node_count"] > 0
    assert "confirmed_edges" in topology
    assert "gaps" in rules
    assert report["diagnostics"]["source_mode"] == "pkt_auto_xml_json_bridge"
