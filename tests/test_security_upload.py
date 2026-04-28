from pathlib import Path
from wiguard.services.extractor import PacketTracerImportService


def test_upload_filename_is_sanitized_and_not_path_traversal(tmp_path):
    service = PacketTracerImportService(tmp_path / "uploads")
    upload = type("Upload", (), {"filename": "../evil.cfg", "read": lambda self: b"hostname R1\n"})()
    result = service.extract(upload)
    assert result["filename"] == "evil.cfg"
    assert result["stored_filename"].endswith(".cfg")
    assert not (tmp_path / "evil.cfg").exists()
    stored = (tmp_path / "uploads" / result["stored_filename"]).resolve()
    assert stored.exists()
    assert stored.is_relative_to((tmp_path / "uploads").resolve())


def test_rejects_unsupported_extension(tmp_path):
    service = PacketTracerImportService(tmp_path / "uploads")
    upload = type("Upload", (), {"filename": "payload.exe", "read": lambda self: b"hostname R1\n"})()
    try:
        service.extract(upload)
    except ValueError as exc:
        assert "Unsupported file extension" in str(exc)
    else:
        raise AssertionError("unsupported upload extension was accepted")
