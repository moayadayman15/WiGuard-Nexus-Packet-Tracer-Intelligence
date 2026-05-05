"""Test fixtures and release hygiene helpers."""
from __future__ import annotations

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Minimal Flask app fixture with isolated temp storage.

    Older tests were written expecting pytest-flask style app/client fixtures, but
    the project intentionally avoids adding pytest-flask as a dependency.  This
    local fixture keeps the suite lightweight and Windows-friendly.
    """
    monkeypatch.setenv("WIGUARD_AUTH_REQUIRED", "0")
    monkeypatch.setenv("WIGUARD_DATA_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("WIGUARD_DB_PATH", str(tmp_path / "wiguard.sqlite3"))
    monkeypatch.setenv("WIGUARD_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("WIGUARD_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("WIGUARD_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("WIGUARD_SAMPLE_DIR", str(tmp_path / "samples"))
    (tmp_path / "samples").mkdir(parents=True, exist_ok=True)
    from wiguard import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()

