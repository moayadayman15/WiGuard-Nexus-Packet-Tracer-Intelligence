from wiguard.services.extractor import ConfigExtractor
from wiguard.services.seed import seed_state
from wiguard.services.intelligence import build_policy_diff, guest_isolation_status, run_access_simulation

SAMPLE = """
hostname R1-Core
ip dhcp pool GUEST_POOL
 network 10.10.30.0 255.255.255.0
 default-router 10.10.30.1
!
interface GigabitEthernet0/0.30
 encapsulation dot1Q 30
 ip address 10.10.30.1 255.255.255.0
 ip access-group GUEST_ISOLATION in
!
interface GigabitEthernet0/2
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
!
ip access-list extended GUEST_ISOLATION
 10 deny ip 10.10.30.0 0.0.0.255 10.10.0.0 0.0.255.255
 20 permit ip 10.10.30.0 0.0.0.255 any
"""


def parsed_state():
    state = seed_state()
    state["active_extraction"] = {"objects": ConfigExtractor().parse(SAMPLE)}
    return state


def test_acl_rules_are_bound_to_interfaces():
    objects = ConfigExtractor().parse(SAMPLE)
    guest_rules = [r for r in objects["acl_rules"] if r["acl_name"] == "GUEST_ISOLATION"]
    assert guest_rules
    assert all(r["is_applied"] for r in guest_rules)
    assert guest_rules[0]["applied_to"][0]["interface"] == "GigabitEthernet0/0.30"


def test_guest_isolation_requires_applied_deny_acl():
    state = parsed_state()
    guest = next(s for s in state["wireless_policy"]["ssids"] if s["role"] == "Guest")
    status = guest_isolation_status(state["active_extraction"]["objects"], guest)
    assert status["status"] == "Pass"
    assert "applied" in status["reason"].lower()


def test_policy_diff_contains_trunk_and_gateway_checks():
    diffs = build_policy_diff(parsed_state())
    categories = {d["category"] for d in diffs}
    assert "Trunk Coverage" in categories
    assert "Gateway/DHCP Matching" in categories
    assert any(d["id"] == "GUEST-ISOLATION-GuestWiFi" and d["status"] == "Pass" for d in diffs)


def test_simulation_uses_acl_path_for_guest_internal_access():
    result = run_access_simulation(parsed_state(), "guest_01 - Guest", "Access Internal Network")
    assert result["status"] == "Pass"
    assert any("ACL" in step for step in result["path"])
