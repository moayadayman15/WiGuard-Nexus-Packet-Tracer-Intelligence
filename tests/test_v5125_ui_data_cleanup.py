from pathlib import Path

from wiguard.services.pkt_xml_profile import extract_packet_tracer_xml_objects
from wiguard.services.extractor import PacketTracerImportService

SAMPLE_XML = """<?xml version="1.0"?>
<packetTracerLab>
  <devices>
    <device id="R1" name="R1-Core" type="Router" model="2911">
      <interfaces>
        <interface name="GigabitEthernet0/0" ipAddress="10.10.10.1" subnetMask="255.255.255.0" vlan="10" status="up" />
      </interfaces>
      <runningConfig>hostname R1-Core
interface GigabitEthernet0/0
 ip address 10.10.10.1 255.255.255.0
</runningConfig>
    </device>
    <device id="SW1" name="SW-Access" type="Switch" />
  </devices>
  <vlans><vlan id="10" name="Users" status="active" /></vlans>
  <links><link source="R1-Core" target="SW-Access" sourcePort="GigabitEthernet0/0" targetPort="FastEthernet0/1" cableType="copper" /></links>
</packetTracerLab>
"""


def test_packet_tracer_converter_xml_profile_extracts_real_objects():
    objects, text, summary = extract_packet_tracer_xml_objects(SAMPLE_XML, "sample.xml")
    assert summary["status"] == "understood"
    assert any(d["hostname"] == "R1-Core" for d in objects["devices"])
    assert any(i["normalized_name"] == "GigabitEthernet0/0" for i in objects["interfaces"])
    assert any(v["id"] == "10" for v in objects["vlans"])
    assert any(l["neighbor"] == "SW-Access" for l in objects["cdp_links"])
    assert "hostname R1-Core" in text


def test_xml_upload_uses_profile_without_synthetic_device(tmp_path):
    service = PacketTracerImportService(tmp_path / "uploads")
    upload = type("Upload", (), {"filename": "converted.xml", "read": lambda self: SAMPLE_XML.encode()})()
    result = service.extract(upload)
    objects = result["objects"]
    assert result["source_mode"] == "xml_structured"
    assert any(d["hostname"] == "R1-Core" for d in objects["devices"])
    assert not any(d.get("role") == "synthetic_context" for d in objects["devices"])


def test_import_template_has_density_toolbar_and_unique_pipeline_id():
    template = Path("wiguard/templates/import.html").read_text(encoding="utf-8")
    assert "data-import-view-toolbar" in template
    assert template.count('id="conversion-pipeline-rail"') == 1
    assert 'id="conversion-pipeline-empty"' in template
