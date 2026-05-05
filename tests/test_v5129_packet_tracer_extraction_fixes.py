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


def _write_ptexplorer_style_converter(path: Path) -> Path:
    converter = path / "ptexplorer.py"
    converter.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "out = Path(args[2] if args and args[0] == '-d' else args[1])\n"
        "out.write_text('''<?xml version=\"1.0\"?>\n"
        "<packetTracerExport>\n"
        "  <devices>\n"
        "    <device name=\"R1\" type=\"router\" x=\"120\" y=\"80\">\n"
        "      <interfaces>\n"
        "        <interface name=\"GigabitEthernet0/0\" ipAddress=\"10.10.10.1\" subnetMask=\"255.255.255.0\" mode=\"access\" vlanId=\"10\"/>\n"
        "      </interfaces>\n"
        "    </device>\n"
        "  </devices>\n"
        "  <vlans><vlan id=\"10\" name=\"Users\"/></vlans>\n"
        "</packetTracerExport>''', encoding='utf-8')\n",
        encoding="utf-8",
    )
    return converter


def test_ptexplorer_style_decode_adapter_is_supported(tmp_path, monkeypatch):
    converter = _write_ptexplorer_style_converter(tmp_path)
    pkt = tmp_path / "lab.pkt"
    pkt.write_bytes(b"opaque pkt bytes")
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_PATH", str(converter))
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_TIMEOUT", "5")

    attempts, payloads = run_external_pkt_converters(pkt, tmp_path)

    assert any(a.get("status") == "success" for a in attempts)
    assert payloads and payloads[0]["kind"] == "xml"
    assert "packetTracerExport" in payloads[0]["content"]


def test_packet_tracer_export_does_not_treat_export_as_port_context(tmp_path, monkeypatch):
    converter = _write_ptexplorer_style_converter(tmp_path)
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_PATH", str(converter))
    monkeypatch.setenv("WIGUARD_PKT_CONVERTER_TIMEOUT", "5")

    result = PacketTracerImportService(tmp_path).extract(Upload())
    objects = result["objects"]

    assert any(d.get("hostname") == "R1" for d in objects["devices"])
    assert any(i.get("name") == "GigabitEthernet0/0" for i in objects["interfaces"])
    assert not any(i.get("name") == "R1" for i in objects["interfaces"])
    assert not any(i.get("name") == "Users" for i in objects["interfaces"])
    assert any(v.get("id") == "10" and v.get("name") == "Users" for v in objects["vlans"])
    assert objects["external_converter_outputs"]
