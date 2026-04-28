from pathlib import Path

from wiguard.services.pkt_native import inspect_native_pkt
from wiguard.services.extractor import PacketTracerImportService


class Upload:
    def __init__(self, name, data):
        self.filename = name
        self._data = data

    def read(self):
        return self._data


def test_native_pkt_inspector_reports_opaque_binary_without_fake_topology():
    raw = bytes((i * 37 + 19) % 256 for i in range(4096))
    profile, text = inspect_native_pkt(raw, "lab.pkt")
    assert profile["native_packet_tracer"] is True
    assert profile["bytes"] == 4096
    assert "recoverability" in profile
    assert "sha256" in profile
    assert "NATIVE_PACKET_TRACER_BINARY_INSPECTION" in text


def test_pkt_upload_uses_auto_xml_json_bridge_mode(tmp_path):
    raw = bytes((i * 91 + 7) % 256 for i in range(8192))
    service = PacketTracerImportService(tmp_path)
    result = service.extract(Upload("Project.pkt", raw))
    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert result["objects"].get("native_pkt_profile")
    assert result["objects"].get("devices") == []
    assert result["conversion_profile"]["metadata"]["native_inspector_used"] is True
    assert result["conversion_profile"]["metadata"]["auto_xml_json_bridge_used"] is True
    assert result["objects"].get("converted_xml_preview")
    assert result["objects"].get("normalized_json_preview")
    assert result["conversion_profile"]["readiness"] == "needs_more_evidence"
