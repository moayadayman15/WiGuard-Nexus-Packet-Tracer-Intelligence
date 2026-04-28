from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService
from wiguard.services.pkt_native import reconstruct_cisco_config_text


class Upload:
    def __init__(self, name: str, data: bytes):
        self.filename = name
        self._data = data

    def read(self):
        return self._data


def test_flattened_native_pkt_config_is_reconstructed_before_parsing(tmp_path: Path):
    raw = (
        b"\x00PacketTracerBLOB "
        b"hostname R1 "
        b"interface GigabitEthernet0/0 ip address 192.168.1.1 255.255.255.0 "
        b"interface GigabitEthernet0/1 switchport mode trunk switchport trunk allowed vlan 10,20 "
        b"vlan 10 name STAFF "
        b"ip dhcp pool STAFF network 192.168.1.0 255.255.255.0 default-router 192.168.1.1 "
        b"access-list 101 deny ip any any \x00"
    ) + bytes((i * 17) % 256 for i in range(1024))

    result = PacketTracerImportService(tmp_path).extract(Upload("flattened.pkt", raw))
    objects = result["objects"]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert any(d.get("hostname") == "R1" for d in objects["devices"])
    assert any(i.get("name") == "GigabitEthernet0/0" and i.get("ip_address") == "192.168.1.1" for i in objects["interfaces"])
    assert any(i.get("name") == "GigabitEthernet0/1" and i.get("mode") == "trunk" and "10" in (i.get("trunk_allowed_vlans") or []) for i in objects["interfaces"])
    assert any(v.get("id") == "10" for v in objects["vlans"])
    assert any(d.get("name") == "STAFF" and d.get("default_gateway") == "192.168.1.1" for d in objects["dhcp_scopes"])
    assert any(a.get("acl_name") == "101" and a.get("expression") == "ip any any" for a in objects["acl_rules"])
    assert objects["reconstructed_config_preview"]
    assert objects["printable_segments_preview"]
    assert objects["extraction_fidelity"][0]["tier"] in {"strong_visible_recovery", "partial_visible_recovery"}


def test_reconstruction_does_not_invent_commands():
    source = "junk hostname SW1 interface FastEthernet0/1 switchport access vlan 30 end"
    reconstructed = reconstruct_cisco_config_text(source)
    assert "hostname SW1" in reconstructed
    assert "interface FastEthernet0/1" in reconstructed
    assert "switchport access vlan 30" in reconstructed
    assert "secret" not in reconstructed.lower()
