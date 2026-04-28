from wiguard.services.intelligence import build_policy_diff, build_topology, object_counts, sanitize_objects


def test_partial_import_objects_do_not_crash_topology_or_policy_diff():
    state = {
        "wireless_policy": {
            "ssids": [
                {
                    "ssid": "GuestWiFi",
                    "role": "Guest",
                    "expected_vlan": 20,
                    "expected_subnet": "10.20.0.0/24",
                    "internal_access": False,
                    "allowed_services": ["Internet"],
                    "internet": True,
                }
            ]
        },
        "active_extraction": {
            "objects": {
                "devices": [{"hostname": "SW1", "evidence": None}, None],
                "vlans": None,
                "interfaces": [
                    {"name": "Gi0/1", "mode": "trunk", "trunk_allowed_vlans": ["20"], "evidence": None}
                ],
                "dhcp_scopes": [
                    {"name": "GUEST_POOL", "cidr": "10.20.0.0/24", "default_gateway": "10.20.0.1", "evidence": None}
                ],
                "policy_controls": [{"control": "Guest isolation", "evidence": None, "confidence": 0.7}, None],
                "coverage_domains": [{"domain": "ACL", "count": 1, "status": "partial", "keys": ["acl_rules"]}],
            }
        },
    }

    clean = sanitize_objects(state["active_extraction"]["objects"])
    assert clean["vlans"] == []
    assert clean["devices"][0]["evidence"] == {}
    assert object_counts(clean)["interfaces"] == 1
    assert build_topology(state)["nodes"]
    assert build_policy_diff(state)
