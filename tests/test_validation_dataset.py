from pathlib import Path
from wiguard.services.extractor import ConfigExtractor
from wiguard.services.seed import seed_state
from wiguard.services.intelligence import build_policy_diff, object_counts

FIXTURES = Path(__file__).parent / "fixtures" / "packet_tracer"


def parse_fixture(name):
    return ConfigExtractor().parse((FIXTURES / name).read_text())


def test_validation_dataset_simple_vlan_expected_objects():
    objects = parse_fixture("simple_vlan.cfg")
    counts = object_counts(objects)
    assert counts["devices"] == 1
    assert {v["id"] for v in objects["vlans"]} >= {"10", "30"}
    assert any(i["mode"] == "trunk" and "30" in i["trunk_allowed_vlans"] for i in objects["interfaces"])


def test_validation_dataset_router_on_a_stick_acl_bindings_and_confidence():
    objects = parse_fixture("router_on_a_stick.cfg")
    assert any(i["dot1q_vlan"] == "30" for i in objects["interfaces"])
    assert any(p["cidr"] == "10.10.30.0/24" for p in objects["dhcp_scopes"])
    assert all(r["is_applied"] for r in objects["acl_rules"] if r["acl_name"] == "GUEST_ISOLATION")
    assert objects["evidence_profile"]["confidence"] >= 0.65


def test_validation_dataset_detects_trunk_failure_for_guest_vlan():
    state = seed_state()
    state["active_extraction"] = {"objects": parse_fixture("trunk_failure.cfg")}
    diffs = build_policy_diff(state)
    assert any(d["id"] == "TRUNK-GuestWiFi" and d["status"] == "Fail" for d in diffs)


def test_validation_dataset_port_security_and_etherchannel():
    ps = parse_fixture("port_security_violation.cfg")
    assert any(i["port_security_enabled"] and i["port_security_violation"] == "restrict" for i in ps["interfaces"])
    ec = parse_fixture("etherchannel_lab.cfg")
    assert ec["etherchannels"]
