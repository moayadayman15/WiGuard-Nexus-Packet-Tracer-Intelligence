from wiguard.services.structured_import import StructuredEvidenceNormalizer


class Upload:
    def __init__(self, filename, raw):
        self.filename = filename
        self._raw = raw

    def read(self):
        return self._raw


def test_object_map_json_devices_interfaces_and_links_are_named():
    payload = {
        "topology": {
            "devices": {
                "R1": {
                    "type": "router",
                    "interfaces": {
                        "GigabitEthernet0/0": {
                            "ipAddress": "10.0.0.1",
                            "subnetMask": "255.255.255.0",
                        }
                    },
                },
                "SW1": {
                    "type": "switch",
                    "ports": {
                        "FastEthernet0/1": {"vlanId": 10, "mode": "access"}
                    },
                },
            },
            "links": [
                {
                    "sourceId": "R1",
                    "targetId": "SW1",
                    "sourcePort": "GigabitEthernet0/0",
                    "targetPort": "FastEthernet0/1",
                    "cableType": "copper",
                }
            ],
        }
    }

    objects, _, summary = StructuredEvidenceNormalizer().normalize_json(payload)

    assert summary["status"] == "understood"
    assert any(d.get("hostname") == "R1" and d.get("type") == "router" for d in objects["devices"])
    assert any(d.get("hostname") == "SW1" and d.get("type") == "switch" for d in objects["devices"])
    assert any(i.get("device") == "R1" and i.get("name") == "GigabitEthernet0/0" and i.get("ip_address") == "10.0.0.1" for i in objects["interfaces"])
    assert any(i.get("device") == "SW1" and i.get("name") == "FastEthernet0/1" and i.get("access_vlan") == "10" for i in objects["interfaces"])
    assert any(l.get("device") == "R1" and l.get("neighbor") == "SW1" for l in objects["cdp_links"])
