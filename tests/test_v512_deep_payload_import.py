import json
from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService


class FakeUpload:
    def __init__(self, filename, data):
        self.filename = filename
        self._data = data
        self._used = False

    def read(self):
        if self._used:
            return b""
        self._used = True
        return self._data


def test_json_import_builds_universal_payload_indexes(tmp_path):
    payload = json.loads(Path("tests/fixtures/packet_tracer/deep_payload_lab.json").read_text(encoding="utf-8"))
    service = PacketTracerImportService(tmp_path)
    result = service.extract(FakeUpload("deep_payload_lab.json", json.dumps(payload).encode("utf-8")))
    objects = result["objects"]

    assert result["source_mode"] == "json_structured"
    assert len(objects["source_conversion_manifest"]) == 1
    assert len(objects["source_payload_tree"]) >= 5
    assert len(objects["source_key_value_index"]) >= 8
    assert len(objects["universal_network_facts"]) >= 4
    assert len(objects["payload_tables"]) >= 1
    assert objects["universal_xml_preview"][0]["content"].startswith("<?xml")
    assert "normalized" in objects["universal_json_preview"][0]["name"]


def test_native_pkt_bridge_runs_universal_payload_indexes(tmp_path):
    raw = (
        b"\x00Packet Tracer\x00"
        b"hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        b"{\"devices\":[{\"hostname\":\"R2\",\"type\":\"router\"}],"
        b"\"interfaces\":[{\"name\":\"GigabitEthernet0/1\",\"ipAddress\":\"10.0.1.1\"}]}"
        b"\x00"
    )
    service = PacketTracerImportService(tmp_path)
    result = service.extract(FakeUpload("bridge-test.pkt", raw))
    objects = result["objects"]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert len(objects["internal_xml_bridge"]) == 1
    assert len(objects["source_conversion_manifest"]) == 1
    assert len(objects["source_key_value_index"]) >= 1
    assert len(objects["universal_network_facts"]) >= 1
    assert len(objects["native_source_manifest"]) == 1
