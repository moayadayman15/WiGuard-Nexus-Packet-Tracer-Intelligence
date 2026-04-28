from wiguard.services.extractor import ConfigExtractor
from wiguard.services.packet_tracer import build_conversion_profile
from wiguard.services.wireless import normalize_wireless_state


SAMPLE = """
hostname SW-DIST
service password-encryption
enable password cisco
line vty 0 4
 transport input telnet ssh
!
vlan 10
 name Staff
vlan 30
 name Guest
!
VLAN Name                             Status    Ports
10   Staff                            active    Gi0/2, Gi0/3
30   Guest                            active    Gi0/4
!
interface GigabitEthernet0/1
 description Uplink
 switchport mode trunk
 switchport trunk allowed vlan 10
!
Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       on           802.1q         trunking      1
Port        Vlans allowed on trunk
Gi0/1       10
!
Extended IP access list GUEST_ISOLATION
 10 deny ip 10.10.30.0 0.0.0.255 10.10.0.0 0.0.255.255 (24 matches)
 20 permit ip 10.10.30.0 0.0.0.255 any (100 matches)
!
GigabitEthernet0/1 is up, line protocol is up
  7 input errors, 3 CRC, 0 frame, 0 overrun, 0 ignored
  2 output errors, 0 collisions, 1 interface resets
!
VLAN0030
  Root ID    Priority    32768
             Address     0011.2233.4455
             Cost        19
             Port        Gi0/1
router ospf 1
 network 10.10.30.0 0.0.0.255 area 0
"""


def test_v58_extracts_runtime_counters_crosscheck_and_risk_atoms():
    objects = ConfigExtractor().parse(SAMPLE)
    assert objects["vlan_brief"]
    assert objects["acl_hit_counts"][0]["matches"] == 24
    assert objects["interface_counters"][0]["input_errors"] == 7
    assert objects["stp_root"]
    assert objects["protocol_summary"]
    assert "30" in objects["vlan_crosscheck"]["missing_from_trunks"]
    assert any(atom["key"] == "vlan-not-on-trunk" for atom in objects["risk_atoms"])
    assert any(atom["key"] == "weak-management-plane" for atom in objects["risk_atoms"])
    assert objects["coverage_domains"]


def test_v58_conversion_profile_exposes_new_quality_layers():
    objects = ConfigExtractor().parse(SAMPLE)
    profile = build_conversion_profile("bundle.zip", b"", SAMPLE, "zip_bundle", objects)
    assert profile["coverage_domains"]
    assert profile["vlan_crosscheck"]["missing_from_trunks"]
    assert any("Runtime validation" in gate["name"] for gate in profile["quality_gates"])
    assert any(row["command"] == "show access-lists with counters" for row in profile["command_checklist"])


def test_v58_default_policy_rules_are_upgraded():
    state = {}
    normalize_wireless_state(state)
    ids = {rule["id"] for rule in state["policy_studio"]["rules"]}
    assert "PS-VLAN-TRUNK-CROSSCHECK" in ids
    assert "PS-ACL-RUNTIME-HITS" in ids
    assert "PS-EVIDENCE-COMPLETENESS" in ids
