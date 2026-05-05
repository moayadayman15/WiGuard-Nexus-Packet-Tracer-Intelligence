import json
from pathlib import Path

import pytest

from wiguard.services.professional_pipeline import (
    DataImportValidator,
    ImportValidationError,
    ParserRegistry,
    ProfessionalReportBuilder,
    SchemaNormalizer,
    build_professional_analysis,
    health_report,
)


def test_parser_registry_selects_json_xml_csv_text_and_pkt(tmp_path: Path):
    registry = ParserRegistry()
    cases = {
        "lab.json": '{"devices":[{"hostname":"R1","device_type":"router"}]}',
        "lab.xml": "<network><device><hostname>SW1</hostname></device></network>",
        "lab.csv": "hostname,ip\nSW1,10.0.0.2\n",
        "lab.cfg": "hostname Core\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n",
        "lab.pkt": "PKT\x00binary-placeholder",
        "bundle.zip": None,
    }
    import zipfile
    for name, content in cases.items():
        p = tmp_path / name
        if name.endswith(".zip"):
            with zipfile.ZipFile(p, "w") as archive:
                archive.writestr("network.json", '{"devices":[{"hostname":"ZIP-R1"}]}')
        else:
            p.write_text(content, encoding="utf-8", errors="ignore")
        assert registry.select(p).name in {"json", "xml", "csv", "text_config", "zip_bundle", "packet_tracer_native_hook"}


def test_json_parser_and_normalizer_produce_stable_entities(tmp_path: Path):
    p = tmp_path / "network.json"
    p.write_text(json.dumps({"devices": [{"hostname": "R1", "device_type": "router", "ip": "10.0.0.1"}], "vlans": [{"vlan_id": 10, "name": "STAFF"}]}), encoding="utf-8")
    result = ParserRegistry().parse(p)
    assert result["parser"] == "json"
    types = {row["type"] for row in result["entities"]}
    assert "device" in types or "ip_address" in types


def test_invalid_xml_returns_friendly_error(tmp_path: Path):
    p = tmp_path / "broken.xml"
    p.write_text("<network><device></network>", encoding="utf-8")
    with pytest.raises(Exception) as exc:
        ParserRegistry().parse(p)
    assert "XML" in str(exc.value) or "xml" in str(exc.value)


def test_empty_file_validation_is_friendly(tmp_path: Path):
    p = tmp_path / "empty.cfg"
    p.write_text("", encoding="utf-8")
    with pytest.raises(ImportValidationError):
        DataImportValidator().validate_path(p)


def test_build_professional_analysis_flags_secret_duplicate_ip_and_flat_network():
    objects = {
        "devices": [{"hostname": "R1"}, {"hostname": "SW1"}, {"hostname": "SW2"}],
        "ip_inventory": [
            {"name": "R1-G0/0", "ip": "10.0.0.1", "device": "R1"},
            {"name": "SW1-Vlan1", "ip": "10.0.0.1", "device": "SW1"},
        ],
        "credentials": [{"name": "enable secret", "secret": "supersecret"}],
    }
    result = build_professional_analysis(objects, {"filename": "fixture.cfg", "source_mode": "unit"})
    titles = {f["title"] for f in result.findings}
    assert any("credential" in title.lower() for title in titles)
    assert any("duplicate ip" in title.lower() for title in titles)
    assert result.risk_score["finding_count"] >= 2



def test_zip_bundle_parser_extracts_supported_members(tmp_path: Path):
    import zipfile

    p = tmp_path / "evidence_bundle.zip"
    with zipfile.ZipFile(p, "w") as archive:
        archive.writestr("exports/core.cfg", "hostname ZIP-Core\ninterface GigabitEthernet0/1\n ip address 10.55.0.1 255.255.255.0\n")
        archive.writestr("../unsafe.cfg", "hostname should-not-load\n")
    result = ParserRegistry().parse(p)
    assert result["parser"] == "zip_bundle"
    assert any(row["name"] == "ZIP-Core" for row in result["entities"])
    assert any("unsafe" in warning.lower() for warning in result["warnings"])

def test_report_builder_outputs_json_and_html():
    result = build_professional_analysis({"devices": [{"hostname": "R1"}]}, {"filename": "fixture.cfg"})
    builder = ProfessionalReportBuilder()
    raw_json = builder.build_json(result)
    raw_html = builder.build_html(result)
    assert b"risk_score" in raw_json
    assert b"WiGuard Nexus Professional Analysis Report" in raw_html


def test_html_report_escapes_imported_evidence():
    result = build_professional_analysis({"credentials": [{"name": "<script>alert(1)</script>", "secret": "supersecret"}]}, {"filename": "xss.cfg"})
    raw_html = ProfessionalReportBuilder().build_html(result)
    assert b"<script>alert(1)</script>" not in raw_html
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in raw_html


def test_system_health_checker_runs():
    report = health_report(Path.cwd())
    assert "required_dependencies" in report
    assert any(dep["name"] == "flask" for dep in report["required_dependencies"])


def test_friendly_error_redacts_paths_and_sensitive_markers():
    from wiguard.services.util import friendly_error

    assert friendly_error("C:\\Users\\PC\\project\\secret.py failed") == "The request could not be completed. Please check the input and try again."
    assert friendly_error("Invalid CSV header") == "Invalid CSV header"
