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
    assert payload["confidence"] is None
    assert "analysis_id" in payload
    assert payload["from"] == "Alice <alice@example.com>"

    fetch = client.get(f"/api/v1/email-analysis/{payload['analysis_id']}")
    assert fetch.status_code == 200
    fetch_payload = fetch.get_json()
    assert fetch_payload["analysis_id"] == payload["analysis_id"]
    assert fetch_payload["confidence"] is None


def test_email_analysis_with_sensitive_embedded_url_is_sanitized(client) -> None:
    raw_url = "https://user:secret@evil.example/login?token=abc123&safe=1&api_key=xyz"
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "from": "Alice <alice@example.com>",
            "subject": "Urgent action required",
            "body_html": f'<a href="{raw_url}">Confirm account</a>',
        },
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["confidence"] is None
    assert payload["urls"]
    url_result = payload["urls"][0]["url"]
    assert "user:secret" not in url_result
    assert "abc123" not in url_result
    assert "xyz" not in url_result
    assert "safe=1" in url_result
    assert "token=%5BREDACTED%5D" in url_result
    assert "api_key=%5BREDACTED%5D" in url_result
    assert "user:secret" not in str(payload["evidence"])

    fetch = client.get(f"/api/v1/email-analysis/{payload['analysis_id']}")
    assert fetch.status_code == 200
    fetch_payload = fetch.get_json()
    assert fetch_payload["urls"]
    assert "user:secret" not in str(fetch_payload["urls"])
    assert "abc123" not in str(fetch_payload["urls"])
    assert "token=%5BREDACTED%5D" in str(fetch_payload["urls"]) 
    assert fetch_payload["confidence"] is None


def test_empty_email_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/email", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_email"


def test_missing_email_analysis_returns_404(client) -> None:
    response = client.get("/api/v1/email-analysis/999999")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"
