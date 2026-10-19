from __future__ import annotations

import pytest

from src.api.app import create_app


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with app.test_client() as test_client:
        yield test_client


def test_email_analysis_and_retrieval(client) -> None:
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "from": "Alice <alice@example.com>",
            "subject": "Hello",
            "body_text": "See you soon.",
        },
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["classification"] == "low_risk"
    assert "analysis_id" in payload
    assert payload["from"] == "Alice <alice@example.com>"

    fetch = client.get(f"/api/v1/email-analysis/{payload['analysis_id']}")
    assert fetch.status_code == 200
    assert fetch.get_json()["analysis_id"] == payload["analysis_id"]


def test_empty_email_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/email", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_email"


def test_missing_email_analysis_returns_404(client) -> None:
    response = client.get("/api/v1/email-analysis/999999")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"
