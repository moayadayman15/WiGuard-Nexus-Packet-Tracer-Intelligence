from wiguard import create_app
from wiguard.services.product_intelligence import build_product_intelligence, dependency_health


def test_dependency_health_catalog_is_safe():
    health = dependency_health()
    assert health["total_count"] >= 10
    assert "pip install" in health["commands"]["p0"] or "already installed" in health["commands"]["p0"]


def test_product_intelligence_model_has_core_sections():
    model = build_product_intelligence({"active_extraction": {"objects": {}}, "wireless_policy": {"ssids": []}, "events": [], "imports": []})
    assert "dependency_health" in model
    assert "topology_brain" in model
    assert "ai_copilot" in model
    assert 0 <= model["maturity_score"] <= 100


def test_intelligence_page_loads(client):
    response = client.get("/intelligence")
    assert response.status_code in (200, 302)
