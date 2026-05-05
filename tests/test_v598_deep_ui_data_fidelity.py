from wiguard.services.extractor import ConfigExtractor
from wiguard.services.pkt_native import _extract_utf16_text_payloads, run_native_pkt_auto_pipeline


def test_v598_deep_command_and_feature_indexes():
    sample = """
hostname R1
ip default-gateway 192.168.1.1
ip name-server 8.8.8.8
logging host 10.0.0.10
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 ip helper-address 192.168.10.5
 standby 1 ip 192.168.1.254
 no shutdown
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 storm-control broadcast level 5.00
 channel-group 1 mode active
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
 passive-interface default
"""
    objects = ConfigExtractor().parse(sample)
    assert len(objects["all_config_commands"]) >= 15
    assert any(x["feature"] == "voice_vlan" for x in objects["interface_features"])
    assert any(x["service"] == "default_gateway" for x in objects["management_services"])
    assert any(x["protocol"] == "hsrp" for x in objects["gateway_redundancy"])
    assert any(x["type"] == "network" for x in objects["routing_protocol_details"])
    assert len(objects["extraction_completeness"]) >= 6


def test_v598_utf16_native_pkt_payload_promotion():
    raw = ("hostname R2\ninterface Fa0/1\n switchport access vlan 30\n switchport voice vlan 40\n standby 1 ip 10.0.0.254\n").encode("utf-16le")
    payloads = _extract_utf16_text_payloads(raw)
    assert payloads
    assert "switchport voice vlan" in payloads[0]["content"]
    profile, text, bridge_xml, bridge_json = run_native_pkt_auto_pipeline(raw, "lab.pkt")
    assert profile["decoded_payload_count"] >= 1
    assert "switchport voice vlan" in text
    assert bridge_json["counts"]["decoded_payloads"] >= 1
