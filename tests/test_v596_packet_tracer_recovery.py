from wiguard.services.extractor import PacketTracerImportService


class Upload:
    def __init__(self, filename, data):
        self.filename = filename
        self._data = data

    def read(self):
        return self._data


def test_interface_ip_inventory_is_derived_from_config(tmp_path):
    cfg = (
        b"hostname R1\n"
        b"interface GigabitEthernet0/0\n"
        b" ip address 10.0.0.1 255.255.255.0\n"
        b"vlan 10\n name STAFF\n"
    )
    result = PacketTracerImportService(tmp_path).extract(Upload("running.cfg", cfg))
    objects = result["objects"]

    assert result["source_mode"] == "text_config"
    assert objects["interfaces"]
    assert any(row.get("ip_address") == "10.0.0.1" for row in objects["ip_inventory"])
    assert any(row.get("ip_address") == "10.0.0.1" for row in objects["endpoint_inventory"])


def test_native_packet_tracer_visible_config_recovers_inventory_and_reasonable_score(tmp_path):
    raw = (
        b"PKT\x00hostname SW1\n"
        b"interface FastEthernet0/1\n"
        b" switchport access vlan 10\n"
        b" ip address 10.10.10.2 255.255.255.0\n"
        b"vlan 10\n name STAFF\n"
    )
    result = PacketTracerImportService(tmp_path).extract(Upload("lab.pkt", raw))
    objects = result["objects"]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert objects["internal_xml_bridge"]
    assert objects["converted_xml_preview"]
    assert objects["normalized_json_preview"]
    assert any(row.get("ip_address") == "10.10.10.2" for row in objects["ip_inventory"])
    assert result["conversion_profile"]["readiness_score"] >= 0.5
