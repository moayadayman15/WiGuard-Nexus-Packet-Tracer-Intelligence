import zlib
from wiguard.services.extractor import PacketTracerImportService


class FakeUpload:
    def __init__(self, filename, data):
        self.filename = filename
        self._data = data

    def read(self):
        return self._data


def test_native_pkt_recovers_zlib_embedded_config(tmp_path):
    cfg = b"""hostname R1
interface GigabitEthernet0/0
 ip address 192.168.10.1 255.255.255.0
 no shutdown
vlan 10
 name STAFF
"""
    raw = b"PT-BINARY" + zlib.compress(cfg) + b"EOF"
    result = PacketTracerImportService(tmp_path).extract(FakeUpload("lab.pkt", raw))
    objects = result["objects"]
    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert objects["interfaces"]
    assert objects["vlans"]
    assert objects["ip_inventory"]


def test_operational_tables_promote_to_searchable_inventory(tmp_path):
    text = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.10.10.1      YES manual up                    up
VLAN Name                             Status    Ports
10   STAFF                            active    Fa0/1, Fa0/2
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW2              Fas 0/1           153        S I         2960      Fas 0/2
"""
    result = PacketTracerImportService(tmp_path).extract(FakeUpload("ops.txt", text.encode()))
    objects = result["objects"]
    assert any(i.get("ip_address") == "10.10.10.1" for i in objects["interfaces"])
    assert any(i.get("access_vlan") == "10" for i in objects["interfaces"])
    assert objects["cdp_links"]
