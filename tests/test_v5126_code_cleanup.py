from pathlib import Path
from wiguard.services.code_quality import scan_project
from wiguard.services.state_schema import ensure_state_shape, tenant_scoped_copy



def test_state_schema_creates_required_ui_sections():
    state = ensure_state_shape({"projects": None, "imports": None}, tenant_id="tenant-a", version="x")
    assert state["tenant_id"] == "tenant-a"
    assert state["version"] == "x"
    assert state["projects"]
    assert state["imports"] == []
    assert state["active_extraction"]["objects"] == {}
    assert state["meta"]["workflow"]


def test_tenant_scoped_copy_filters_cross_tenant_lists():
    state = {
        "tenant_id": "tenant-a",
        "projects": [
            {"id": "a", "tenant_id": "tenant-a"},
            {"id": "b", "tenant_id": "tenant-b"},
        ],
        "imports": [
            {"id": "i1", "tenant_id": "tenant-a"},
            {"id": "i2", "tenant_id": "tenant-b"},
        ],
    }
    scoped = tenant_scoped_copy(state, "tenant-a")
    assert [p["id"] for p in scoped["projects"]] == ["a"]
    assert [i["id"] for i in scoped["imports"]] == ["i1"]


def test_release_hygiene_scanner_keeps_runtime_bytecode_nonfatal():
    root = Path(__file__).resolve().parents[1]
    report = scan_project(root)
    assert report["fatal"] is False
    assert report["summary"]["syntax_error_count"] == 0


def test_code_quality_scanner_passes_release_basics():
    root = Path(__file__).resolve().parents[1]
    report = scan_project(root)
    assert report["summary"]["syntax_error_count"] == 0
    assert report["fatal"] is False
    assert report["python_files"] > 0
