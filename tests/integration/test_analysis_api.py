from __future__ import annotations

import pytest

from src.api.app import create_app
from src.database.connection import db
from src.database.models.url import AnalysisRecord


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


def test_extension_origin_receives_safe_cors_headers(client) -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://example.com"},
        headers={"Origin": "chrome-extension://audit-extension-id"},
    )
    assert response.status_code == 201
    assert response.headers["Access-Control-Allow-Origin"] == "chrome-extension://audit-extension-id"
    assert "Content-Type" in response.headers["Access-Control-Allow-Headers"]


def test_valid_url_analysis(client) -> None:
    response = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["url"] == "https://example.com"
    assert payload["normalized_url"] == "https://example.com/"
    assert payload["classification"] in {"low_risk", "moderate_risk", "high_risk", "critical_risk"}
    assert payload["confidence"] is None
    assert "analysis_id" in payload
    assert payload["risk_score"] >= 0


@pytest.mark.parametrize(
    ("matches", "threat_status"),
    [
        (
            [],
            {
                "status": "disabled",
                "match_found": None,
                "message": "Google Safe Browsing is disabled.",
            },
        ),
        (
            [],
            {
                "status": "enabled",
                "match_found": False,
                "message": "Google Safe Browsing found no matches.",
            },
        ),
        (
            [{"threatType": "SOCIAL_ENGINEERING"}],
            {
                "status": "enabled",
                "match_found": True,
                "message": "Google Safe Browsing found a match.",
            },
        ),
        (
            [],
            {
                "status": "unavailable",
                "match_found": None,
                "message": "Google Safe Browsing lookup is currently unavailable.",
            },
        ),
    ],
)
def test_safe_browsing_status_is_preserved_on_retrieval(
    client,
    monkeypatch,
    matches,
    threat_status,
) -> None:
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.lookup_url_with_status",
        lambda _url: (matches, threat_status),
    )

    created = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert created.status_code == 201
    initial = created.get_json()
    assert initial["threat_intelligence"] == threat_status
    assert "_phishguard_threat_intelligence" not in initial["features"]

    retrieved = client.get(f"/api/v1/analysis/{initial['analysis_id']}")
    assert retrieved.status_code == 200
    saved = retrieved.get_json()
    assert saved["threat_intelligence"] == threat_status
    assert saved["features"] == initial["features"]
    assert ("google_safe_browsing" in str(saved["evidence"])) is bool(threat_status["match_found"])


@pytest.mark.parametrize(
    ("saved_features", "expected_features"),
    [
        ({"at_symbol_count": 0}, {"at_symbol_count": 0}),
        (
            {"at_symbol_count": 0, "_phishguard_threat_intelligence": "malformed"},
            {"at_symbol_count": 0},
        ),
        (
            {
                "at_symbol_count": 0,
                "_phishguard_threat_intelligence": {
                    "status": "not-a-status",
                    "match_found": False,
                    "message": "Malformed status.",
                },
            },
            {"at_symbol_count": 0},
        ),
        (["malformed feature data"], {}),
    ],
)
def test_url_retrieval_handles_missing_or_malformed_threat_metadata(
    client,
    saved_features,
    expected_features,
) -> None:
    created = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    assert created.status_code == 201
    analysis_id = created.get_json()["analysis_id"]

    with client.application.app_context():
        record = db.session.get(AnalysisRecord, analysis_id)
        record.features = saved_features
        db.session.commit()

    retrieved = client.get(f"/api/v1/analysis/{analysis_id}")

    assert retrieved.status_code == 200
    payload = retrieved.get_json()
    assert payload["features"] == expected_features
    assert payload["threat_intelligence"]["status"] == "unknown"
    assert payload["threat_intelligence"]["match_found"] is None


def test_sensitive_url_analysis_retrieval_is_sanitized(client) -> None:
    raw_url = "https://user:secret@trusted.example/login?token=abc123&safe=1&api_key=xyz"
    create_response = client.post("/api/v1/analyze/url", json={"url": raw_url})
    assert create_response.status_code == 201
    analysis_id = create_response.get_json()["analysis_id"]

    fetch_response = client.get(f"/api/v1/analysis/{analysis_id}")
    assert fetch_response.status_code == 200
    payload = fetch_response.get_json()
    assert payload["url"] == "https://trusted.example/login?token=%5BREDACTED%5D&safe=1&api_key=%5BREDACTED%5D"
    assert payload["normalized_url"] == "https://trusted.example/login?token=%5BREDACTED%5D&safe=1&api_key=%5BREDACTED%5D"
    assert "user:secret" not in payload["url"]
    assert "abc123" not in payload["url"]
    assert "xyz" not in payload["url"]
    assert "safe=1" in payload["url"]
    assert payload["features"]["at_symbol_count"] == 1
    assert any(item["indicator"] == "url.at_symbol" for item in payload["evidence"])
    assert payload["confidence"] is None


def test_sensitive_url_payload_is_sanitized_in_api_response(client) -> None:
    response = client.post(
        "/api/v1/analyze/url",
        json={"url": "https://trusted.example@malicious.example/login?token=abc123&safe=1&api_key=secret"},
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert "trusted.example@malicious.example" not in payload["url"]
    assert "abc123" not in payload["url"]
    assert "secret" not in payload["url"]
    assert "token=%5BREDACTED%5D" in payload["url"]
    assert "api_key=%5BREDACTED%5D" in payload["url"]
    assert "safe=1" in payload["url"]
    assert payload["features"]["at_symbol_count"] == 1


def test_invalid_url_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/url", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_url"


def test_missing_url_field_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/url", json={"other": "value"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_url"


def test_empty_url_object_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/url", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_url"


def test_json_null_url_payload_returns_400(client) -> None:
    response = client.post(
        "/api/v1/analyze/url",
        data="null",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_url"


def test_malformed_json_url_payload_returns_400(client) -> None:
    response = client.post(
        "/api/v1/analyze/url",
        data='{"url":',
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_url"


@pytest.mark.parametrize("payload", [1, "url", ["url"]])
def test_non_object_url_payload_returns_400(client, payload) -> None:
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_url"


def test_analysis_retrieval_by_id(client) -> None:
    create_response = client.post("/api/v1/analyze/url", json={"url": "https://example.com"})
    analysis_id = create_response.get_json()["analysis_id"]

    fetch_response = client.get(f"/api/v1/analysis/{analysis_id}")
    assert fetch_response.status_code == 200
    payload = fetch_response.get_json()
    assert payload["analysis_id"] == analysis_id
    assert payload["url"] == "https://example.com"
    assert payload["confidence"] is None


def test_nonexistent_analysis_returns_404(client) -> None:
    response = client.get("/api/v1/analysis/999999")
    assert response.status_code == 404
    payload = response.get_json()
    assert payload["error"] == "not_found"


def test_url_history_pagination_filtering_and_deletion(client) -> None:
    first = client.post("/api/v1/analyze/url", json={"url": "https://example.com"}).get_json()["analysis_id"]
    client.post("/api/v1/analyze/url", json={"url": "https://suspicious-example.com/login"})

    listing = client.get("/api/v1/analyses/url?page=1&page_size=10&search=example&risk_level=low_risk")
    assert listing.status_code == 200
    payload = listing.get_json()
    assert payload["page"] == 1
    assert payload["page_size"] == 10
    assert payload["total"] >= 1
    assert "items" in payload
    assert "abc123" not in str(payload)

    deleted = client.delete(f"/api/v1/analysis/{first}")
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/analysis/{first}").status_code == 404


def test_url_history_rejects_invalid_pagination(client) -> None:
    assert client.get("/api/v1/analyses/url?page=0").status_code == 400
    assert client.get("/api/v1/analyses/url?page_size=101").status_code == 400
    assert client.get("/api/v1/analyses/url?risk_level=unknown").status_code == 400
