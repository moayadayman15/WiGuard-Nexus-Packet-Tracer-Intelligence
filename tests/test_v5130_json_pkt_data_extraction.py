import json
import os
import textwrap
from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService
from wiguard.services.structured_import import StructuredEvidenceNormalizer


class Upload:
    def __init__(self, filename, raw):
        self.filename = filename
        self._raw = raw

    def read(self):
        return self._raw


def test_nested_packet_tracer_json_nodes_links_are_real_objects(tmp_path):
    payload = {
        "network": {
            "nodes": [
                {
                    "id": "n1",
                    "displayName": "R1",
                    "deviceType": "Router",
                    "interfaces": [
                        {
                            "id": "i1",
                            "name": "GigabitEthernet0/0",
                            "ipv4": {"address": "192.168.1.1", "mask": "255.255.255.0"},
                            "switchport": {"mode": "access", "vlan": 10},
                        }
                    ],
                },
                {
                    "id": "n2",
                    "displayName": "SW1",
                    "deviceType": "Switch",
                    "ports": [{"portName": "FastEthernet0/1", "access_vlan": "20"}],
                },
            ],
            "links": [
                {
                    "source": {"nodeId": "n1", "port": "GigabitEthernet0/0"},
                    "target": {"nodeId": "n2", "port": "FastEthernet0/1"},
                    "cableType": "copper",
                }
            ],
            "vlans": [{"vlanId": 10, "vlanName": "Users"}],
        }
    }

    objects, _, summary = StructuredEvidenceNormalizer().normalize_json(payload)

    assert summary["status"] == "understood"
    assert {(d["hostname"], d["type"]) for d in objects["devices"]} >= {("R1", "router"), ("SW1", "switch")}
    assert not any(i.get("name") in {"n1", "n2"} for i in objects["interfaces"])
    assert any(i.get("device") == "R1" and i.get("ip_address") == "192.168.1.1" and i.get("subnet_mask") == "255.255.255.0" for i in objects["interfaces"])
    assert any(i.get("device") == "SW1" and i.get("name") == "FastEthernet0/1" and i.get("access_vlan") == "20" for i in objects["interfaces"])
    assert objects["cdp_links"] == [{
        "device": "R1",
        "neighbor": "SW1",
        "local_interface": "GigabitEthernet0/0",
        "remote_interface": "FastEthernet0/1",
        "platform": "copper",
        "source": "structured_topology",
        "evidence": objects["cdp_links"][0]["evidence"],
    }]


def test_pkt_external_converter_xml_uses_real_names_not_raw_node_ids(tmp_path, monkeypatch):
    converter = tmp_path / "ptexplorer.py"
    converter.write_text(textwrap.dedent('''
        import sys
        from pathlib import Path
        args = sys.argv[1:]
        out = Path(args[2] if args and args[0] == '-d' else args[1])
        out.write_text("""<?xml version='1.0'?>
        <packetTracerExport>
          <devices>
            <device id='n1' name='R1' type='router'>
              <interfaces><interface name='GigabitEthernet0/0' ipAddress='10.10.10.1' subnetMask='255.255.255.0' mode='access' vlanId='10'/></interfaces>
            </device>
            <device id='n2' name='SW1' type='switch'>
              <ports><port name='FastEthernet0/1' vlanId='10'/></ports>
            </device>
          </devices>
          <links><link sourceNode='n1' sourcePort='GigabitEthernet0/0' targetNode='n2' targetPort='FastEthernet0/1' cableType='copper'/></links>
          <vlans><vlan id='10' name='Users'/></vlans>
        </packetTracerExport>""", encoding='utf-8')
    '''), encoding="utf-8")
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_PATH", str(converter))
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_TIMEOUT", "3")

    result = PacketTracerImportService(tmp_path).extract(Upload("lab.pkt", b"opaque native Packet Tracer bytes"))
    objects = result["objects"]

    assert any(d.get("hostname") == "R1" for d in objects["devices"])
    assert any(d.get("hostname") == "SW1" for d in objects["devices"])
    assert any(i.get("device") == "R1" and i.get("name") == "GigabitEthernet0/0" for i in objects["interfaces"])
    assert any(l.get("device") == "R1" and l.get("neighbor") == "SW1" for l in objects["cdp_links"])
    assert not any(i.get("name") in {"R1", "SW1", "Users"} for i in objects["interfaces"])
    assert objects["external_converter_outputs"]
