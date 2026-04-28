from wiguard.services.extractor import ConfigExtractor
from wiguard.services.packet_tracer import build_conversion_profile, normalize_interface_name


def test_v55_extracts_l2_packet_tracer_evidence():
    sample = """
    hostname SW1
    vlan 10
     name Staff
    interface FastEthernet0/1
     switchport mode access
     switchport access vlan 10
     switchport port-security
     switchport port-security maximum 2
     switchport port-security violation restrict
    interface GigabitEthernet0/1
     switchport mode trunk
     switchport trunk allowed vlan 10,20,30
    ip dhcp pool STAFF
     network 10.10.10.0 255.255.255.0
     default-router 10.10.10.1
    access-list 101 deny ip any 10.10.0.0 0.0.255.255
    VLAN0010
    Fa0/1 Desg FWD 19 128.1 P2p
    1      Po1(SU)         LACP      Gi0/1(P) Gi0/2(P)
    """
    objects = ConfigExtractor().parse(sample)
    assert objects["port_security"][0]["maximum"] == "2"
    assert objects["spanning_tree"][0]["interface"] == "Fa0/1"
    assert objects["etherchannels"][0]["port_channel"] == "Po1"


def test_v55_conversion_profile_flags_native_pkt_recovery():
    objects = ConfigExtractor().parse("hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n")
    profile = build_conversion_profile("lab.pkt", b"Packet Tracer binary Cisco hostname R1", "hostname R1", "pkt_binary_recovery", objects)
    assert profile["metadata"]["native_packet_tracer"] is True
    assert profile["readiness_score"] <= 0.68
    assert any(row["command"].startswith("Export Packet Tracer") for row in profile["command_checklist"])


def test_v55_interface_normalization():
    assert normalize_interface_name("Fa0/1") == "FastEthernet0/1"
    assert normalize_interface_name("Gi0/2") == "GigabitEthernet0/2"
    assert normalize_interface_name("VLAN10") == "Vlan10"
