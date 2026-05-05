import re
import pytest

pytest.importorskip("flask")
pytest.importorskip("werkzeug")
from wiguard import create_app


def test_post_requires_csrf_token(tmp_path, monkeypatch):
    monkeypatch.setenv("WIGUARD_AUTH_REQUIRED", "0")
    monkeypatch.setenv("WIGUARD_DATA_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("WIGUARD_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("WIGUARD_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("WIGUARD_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("WIGUARD_SAMPLE_DIR", str(tmp_path / "samples"))
    (tmp_path / "samples").mkdir()
    app = create_app()
    client = app.test_client()
    assert client.post("/actions/reset").status_code == 400
    html = client.get("/").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    assert client.post("/actions/reset", data={"csrf_token": token}).status_code in {302, 303}
