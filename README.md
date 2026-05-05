from wiguard.services.extractor import ConfigExtractor

DEEP_SAMPLE = """
hostname SW-CORE
service password-encryption
aaa new-model
username netadmin privilege 15 secret 5 $1$hash
ip http server
line vty 0 4
 transport input telnet ssh
 login local
!
interface GigabitEthernet0/1
 description Uplink to SW-ACCESS
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,30,99
!
Port        Name               Status       Vlan       Duplex  Speed Type
Gi0/1       Uplink             connected    trunk      a-full  a-1000 1000BaseSX

Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      99
Port        Vlans allowed on trunk
Gi0/1       10,20,30,99
Port        Vlans allowed and active in management domain
Gi0/1       10,20,30,99
Port        Vlans in spanning tree forwarding state and not pruned
Gi0/1       10,20,30

Local Intf: Gi0/1
System Name: SW-ACCESS
Port id: Gi0/24

O    10.10.30.0/24 [110/2] via 10.10.99.2, 00:00:12, GigabitEthernet0/1
"""


def test_deep_packet_tracer_extracts_operational_and_security_layers():
    objects = ConfigExtractor().parse(DEEP_SAMPLE)
    assert objects["interface_status"]
    assert objects["trunk_operational"]
    assert objects["lldp_links"]
    assert objects["route_table"]
    assert any(x["posture"] == "weak" for x in objects["security_hardening"])
    assert objects["policy_controls"]
    assert objects["deep_evidence_index"]
