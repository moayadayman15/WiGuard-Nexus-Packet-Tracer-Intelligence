from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService


class FakeUpload:
    def __init__(self, filename, data):
        self.filename = filename
        self._data = data

    def read(self):
        return self._data


def test_native_pkt_with_companion_export_builds_verified_contract(tmp_path):
    native = FakeUpload(
        "campus_lab.pkt",
        b"PKT\x00hostname R1 interface GigabitEthernet0/0 ip address 10.0.0.1 255.255.255.0 vlan 10",
    )
    companion = FakeUpload(
        "campus_export.cfg",
        b"hostname R1\n"
        b"interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        b"interface GigabitEthernet0/1\n switchport mode access\n switchport access vlan 10\n"
        b"vlan 10\n name STAFF\n",
    )

    result = PacketTracerImportService(tmp_path).extract(native, companion_file=companion)
    objects = result["objects"]
    contract = objects["verified_extraction_contract"][0]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert objects["companion_exports"][0]["status"] == "parsed"
    assert contract["tier"] == "native_plus_companion_export"
    assert contract["companion_export_present"] is True
    assert objects["evidence_registry"]
    assert any(row["status"] == "verified" for row in objects["evidence_registry"])
    assert len(objects["interfaces"]) >= 2
    assert len(objects["vlans"]) >= 1


def test_text_config_gets_verified_export_contract(tmp_path):
    upload = FakeUpload(
        "running.cfg",
        b"hostname SW1\ninterface FastEthernet0/1\n switchport mode access\n switchport access vlan 20\nvlan 20\n name USERS\n",
    )
    result = PacketTracerImportService(tmp_path).extract(upload)
    contract = result["objects"]["verified_extraction_contract"][0]

    assert result["source_mode"] == "text_config"
    assert contract["tier"] == "verified_export_parse"
    assert result["objects"]["evidence_registry"]
    assert contract["evidence_summary"]["verified"] > 0
