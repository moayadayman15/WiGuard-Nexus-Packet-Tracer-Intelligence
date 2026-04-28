import json
from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService


class Upload:
    def __init__(self, name, data):
        self.filename = name
        self._data = data

    def read(self):
        return self._data


def test_native_pkt_generates_internal_xml_and_normalized_json_bridge(tmp_path: Path):
    raw = (
        b"\x00Packet Tracer\x00hostname SW1\n"
        b"interface FastEthernet0/1\n"
        b" switchport access vlan 10\n"
        b" ip address 10.10.10.2 255.255.255.0\n"
        b"ssid CampusWiFi\n"
    ) + bytes((i * 37 + 13) % 256 for i in range(2048))

    result = PacketTracerImportService(tmp_path).extract(Upload("campus.pkt", raw))
    objects = result["objects"]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert result["conversion_profile"]["metadata"]["internal_xml_bridge_used"] is True
    assert result["conversion_profile"]["metadata"]["auto_xml_json_bridge_used"] is True
    assert objects["auto_conversion_pipeline"]
    assert objects["internal_xml_bridge"]
    assert objects["converted_xml_preview"][0]["content"].startswith("<?xml")
    assert "packetTracerInternalBridge" in objects["converted_xml_preview"][0]["content"]
    assert "native_pkt_auto_xml_json_bridge" in objects["normalized_json_preview"][0]["content"]
    assert result["pipeline"][2]["status"] == "understood"


def test_packet_tracer_json_wrappers_are_flattened_not_displayed_as_raw_objects(tmp_path: Path):
    payload = {
        "logicalTopology": {
            "nodes": [
                {"attributes": {"id": "r1", "displayName": "R1", "deviceType": "Router"}},
                {"attributes": {"id": "sw1", "displayName": "SW1", "deviceType": "Switch"}},
            ],
            "connections": [
                {"properties": {
                    "sourceDevice": "r1",
                    "targetDevice": "sw1",
                    "sourcePort": "Gi0/0",
                    "targetPort": "Gi0/1",
                    "cableType": "Copper",
                }}
            ],
        },
        "devices": [
            {"attributes": {"hostname": "SW1", "deviceType": "Switch"}, "ports": [
                {"properties": {"portId": "Fa0/1", "mode": "access", "vlanId": "10", "ipAddress": "10.10.10.2", "subnetMask": "255.255.255.0"}},
                {"properties": {"portId": "Gi0/1", "mode": "trunk", "allowedVlans": "10,20"}},
            ]}
        ],
    }

    result = PacketTracerImportService(tmp_path).extract(Upload("pt_export.json", json.dumps(payload).encode()))
    objects = result["objects"]

    assert result["source_mode"] == "json_structured"
    assert any(d.get("hostname") == "R1" for d in objects["devices"])
    assert any(d.get("hostname") == "SW1" for d in objects["devices"])
    assert any(l.get("device") == "R1" and l.get("neighbor") == "SW1" for l in objects["cdp_links"])
    assert any(i.get("name") == "Fa0/1" and i.get("ip_address") == "10.10.10.2" for i in objects["interfaces"])
    assert any(i.get("name") == "Gi0/1" and i.get("mode") == "trunk" for i in objects["interfaces"])
    assert not any(isinstance(d, dict) and "attributes" in d and "ports" in d for d in objects["devices"])
