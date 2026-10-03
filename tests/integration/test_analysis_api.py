from __future__ import annotations

import pytest

from src.api.app import create_app


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "healthy"
    assert payload["version"] == "0.1.0"


def test_valid_url_analysis(client) -> None:
    response = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["url"] == "https://example.com"
    assert payload["normalized_url"] == "https://example.com/"
    assert payload["classification"] in {"low_risk", "moderate_risk", "high_risk", "critical_risk"}
    assert "analysis_id" in payload
    assert payload["risk_score"] >= 0


def test_invalid_url_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/url", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_url"


def test_missing_url_field_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/url", json={})
    assert response.status_code == 400


def test_analysis_retrieval_by_id(client) -> None:
    create_response = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    analysis_id = create_response.get_json()["analysis_id"]

    fetch_response = client.get(f"/api/v1/analysis/{analysis_id}")
    assert fetch_response.status_code == 200
    payload = fetch_response.get_json()
    assert payload["analysis_id"] == analysis_id
    assert payload["url"] == "https://example.com"


def test_nonexistent_analysis_returns_404(client) -> None:
    response = client.get("/api/v1/analysis/999999")
    assert response.status_code == 404
    payload = response.get_json()
    assert payload["error"] == "not_found"
