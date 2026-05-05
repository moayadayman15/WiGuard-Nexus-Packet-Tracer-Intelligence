import os
from pathlib import Path

from wiguard.services.extractor import PacketTracerImportService
from wiguard.services.pkt_converter import run_external_pkt_converters


class Upload:
    filename = "converted_lab.pkt"

    def __init__(self, raw=b"Packet Tracer opaque native binary"):
        self._raw = raw

    def read(self):
        return self._raw


def _make_fake_converter(tmp_path: Path) -> Path:
    converter = tmp_path / "fake_pkt_to_xml.sh"
    converter.write_text(
        "#!/bin/sh\n"
        "cat > \"$2\" <<'XML'\n"
        "<?xml version=\"1.0\"?>\n"
        "<packetTracerExport>\n"
        "  <devices>\n"
        "    <device name=\"R1\" type=\"router\" x=\"120\" y=\"80\">\n"
        "      <interfaces>\n"
        "        <interface name=\"GigabitEthernet0/0\" ipAddress=\"10.10.10.1\" subnetMask=\"255.255.255.0\" mode=\"access\" vlanId=\"10\"/>\n"
        "      </interfaces>\n"
        "    </device>\n"
        "  </devices>\n"
        "  <vlans><vlan id=\"10\" name=\"Users\"/></vlans>\n"
        "</packetTracerExport>\n"
        "XML\n",
        encoding="utf-8",
    )
    converter.chmod(0o755)
    return converter


def test_external_pkt_converter_adapter_collects_xml_payload(tmp_path, monkeypatch):
    converter = _make_fake_converter(tmp_path)
    pkt = tmp_path / "lab.pkt"
    pkt.write_bytes(b"opaque pkt bytes")
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_PATH", str(converter))

    attempts, payloads = run_external_pkt_converters(pkt, tmp_path)

    assert any(a.get("status") == "success" for a in attempts)
    assert payloads
    assert payloads[0]["kind"] == "xml"
    assert "packetTracerExport" in payloads[0]["content"]


def test_pkt_import_merges_external_xml_converter_output(tmp_path, monkeypatch):
    converter = _make_fake_converter(tmp_path)
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_PATH", str(converter))

    result = PacketTracerImportService(tmp_path).extract(Upload())
    objects = result["objects"]

    assert result["source_mode"] == "pkt_auto_xml_json_bridge"
    assert objects["external_converter_outputs"]
    assert any(d.get("hostname") == "R1" for d in objects["devices"])
    assert any(i.get("name") == "GigabitEthernet0/0" for i in objects["interfaces"])
    assert any(v.get("id") == "10" for v in objects["vlans"])
    assert result["confidence_summary"]["source_confidence"] >= 0.95
