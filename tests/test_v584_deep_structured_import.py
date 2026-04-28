import json
from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService
from wiguard.services.structured_import import StructuredEvidenceNormalizer


class Upload:
    filename = "deep_lab.json"

    def read(self):
        return json.dumps({
            "topology": {
                "nodes": [
                    {"id": "n1", "label": "R1", "deviceType": "Router", "model": "2911"},
                    {"id": "n2", "label": "SW1", "deviceType": "Switch", "model": "2960"},
                ],
                "links": [
                    {"endpoints": [
                        {"nodeId": "n1", "port": "GigabitEthernet0/0"},
                        {"nodeId": "n2", "port": "GigabitEthernet0/1"},
                    ], "cableType": "copper"}
                ],
            },
            "devices": [
                {"hostname": "SW1", "type": "switch", "interfaces": [
                    {"name": "GigabitEthernet0/1", "mode": "trunk", "allowedVlans": "10,20", "status": "up"},
                    {"name": "FastEthernet0/2", "vlanId": 10, "ipAddress": "10.10.10.2", "subnetMask": "255.255.255.0"},
                ]}
            ],
            "vlans": [{"vlanId": 10, "name": "STAFF"}],
            "dhcpPools": [{"poolName": "STAFF", "network": "10.10.10.0", "subnetMask": "255.255.255.0", "defaultGateway": "10.10.10.1"}],
            "aclRules": [{"aclName": "GUEST_ISOLATION", "action": "deny", "protocol": "ip", "source": "10.10.30.0/24", "destination": "10.10.10.0/24"}],
        }).encode()


def test_v584_deep_json_schema_extracts_topology_and_validation_layers(tmp_path: Path):
    result = PacketTracerImportService(tmp_path).extract(Upload())
    objects = result["objects"]
    assert result["source_mode"] == "json_structured"
    assert objects["structured_summary"]["normalizer"] == "structured_json_xml_v3_lab_matrix"
    assert len(objects["devices"]) >= 2
    assert any(link["device"] == "R1" and link["neighbor"] == "SW1" for link in objects["cdp_links"])
    assert any(iface.get("mode") == "trunk" for iface in objects["interfaces"])
    assert objects["dhcp_scopes"]
    assert objects["acl_rules"]
    assert objects["schema_map"]
    assert "validation_findings" in objects


def test_v584_xml_child_tags_are_flattened_into_records():
    xml = """
    <packetTracerExport>
      <devices>
        <device id="r1">
          <name>R1</name>
          <deviceType>Router</deviceType>
          <interface><name>GigabitEthernet0/0</name><ipAddress>192.168.1.1</ipAddress><subnetMask>255.255.255.0</subnetMask></interface>
        </device>
      </devices>
      <links><link source="R1" target="SW1" sourceInterface="GigabitEthernet0/0" targetInterface="GigabitEthernet0/1" /></links>
    </packetTracerExport>
    """
    objects, text, summary = StructuredEvidenceNormalizer().normalize_xml(xml)
    assert summary["status"] == "understood"
    assert any(d["hostname"] == "R1" for d in objects["devices"])
    assert any(i["name"] == "GigabitEthernet0/0" for i in objects["interfaces"])
    assert objects["cdp_links"]
    assert objects["schema_map"]
