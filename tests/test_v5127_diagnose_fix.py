from pathlib import Path

from wiguard.services.code_quality import scan_project


def test_code_quality_ignores_virtualenv_generated_caches(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")

    venv_cache = root / ".venv" / "Lib" / "site-packages" / "flask" / "__pycache__"
    venv_cache.mkdir(parents=True)
    (venv_cache / "app.cpython-314.pyc").write_bytes(b"fake")

    report = scan_project(root)
    assert report["status"] == "pass"
    assert report["summary"]["forbidden_artifact_count"] == 0


def test_code_quality_reports_project_cache_as_warning_not_startup_failure(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")

    project_cache = root / "wiguard" / "__pycache__"
    project_cache.mkdir(parents=True)
    (project_cache / "routes.cpython-314.pyc").write_bytes(b"fake")

    report = scan_project(root)
    assert report["status"] == "warn"
    assert report["fatal"] is False
    assert report["summary"]["forbidden_artifact_count"] == 1
