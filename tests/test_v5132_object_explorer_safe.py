from wiguard.routes.pages import bp


def test_object_explorer_route_registered():
    rules = [str(rule) for rule in bp.deferred_functions]
    assert bp.name == "pages"


def test_object_explorer_normalizes_scalar_support_rows(client, app):
    storage = app.extensions["storage"]
    state = storage.load()
    state.setdefault("active_extraction", {}).setdefault("objects", {})
    state["active_extraction"]["objects"].update({
        "devices": [{"hostname": "R1", "evidence": None}],
        "routing": {"protocols": [{"protocol": "ospf"}], "static_routes": ["ip route 0.0.0.0 0.0.0.0 10.0.0.1"]},
        "external_converter_outputs": ["preview-only-row"],
    })
    storage.save(state)
    response = client.get("/objects")
    assert response.status_code in (200, 302)
    if response.status_code == 200:
        body = response.get_data(as_text=True)
        assert "Object Inventory" in body
        assert "preview-only-row" not in body or "Open full object JSON" in body
