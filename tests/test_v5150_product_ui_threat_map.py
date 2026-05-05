from pathlib import Path


def test_v515_threat_map_template_and_route_exist():
    root = Path(__file__).resolve().parents[1]
    pages = (root / "wiguard" / "routes" / "pages.py").read_text()
    template = root / "wiguard" / "templates" / "threat_map.html"
    assert '@bp.route("/threat-map")' in pages
    assert template.exists()
    assert "Attack-path" in template.read_text() or "attack-path" in template.read_text()


def test_v515_command_palette_assets_are_present():
    root = Path(__file__).resolve().parents[1]
    base = (root / "wiguard" / "templates" / "base.html").read_text()
    js = (root / "wiguard" / "static" / "app.js").read_text()
    css = (root / "wiguard" / "static" / "style.css").read_text()
    assert "command-palette" in base
    assert "data-command-palette-open" in base
    assert "Ctrl+K" in base
    assert "global command palette" in js
    assert ".command-palette" in css


def test_v515_product_intelligence_contract_mentions_new_sections():
    root = Path(__file__).resolve().parents[1]
    service = (root / "wiguard" / "services" / "product_intelligence.py").read_text()
    assert "def attack_path_brain" in service
    assert "def evidence_search_pack" in service
    assert "def release_gate_pack" in service
    assert "requirements-product" in (root / "requirements-full.txt").read_text()
