from __future__ import annotations

from src.engines.email.analyzer import analyze_email
from src.engines.ml.feature_schema import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from src.engines.ml.predictor import predict_url_features
from src.engines.tls.inspector import inspect_tls_url


def test_feature_schema_version_is_stable() -> None:
    assert FEATURE_SCHEMA_VERSION == "url-feature-schema-v1"
    assert "url_length" in FEATURE_COLUMNS
    assert "uses_https" in FEATURE_COLUMNS


def test_predictor_reports_unavailable_when_no_model_artifact_exists() -> None:
    result = predict_url_features({"url_length": 100, "hostname_length": 12, "path_length": 8, "query_length": 0,
        "fragment_length": 0, "dot_count": 2, "hyphen_count": 0, "underscore_count": 0, "slash_count": 2,
        "question_mark_count": 0, "equals_count": 0, "ampersand_count": 0, "at_symbol_count": 0, "digit_count": 0,
        "special_character_count": 0, "subdomain_count": 0, "has_ip_address": False, "has_punycode": False,
        "has_port": False, "is_nonstandard_port": False, "hostname_contains_digits": False, "uses_https": True,
        "suspicious_keyword_count": 0, "port": None})
    assert result.status == "unavailable"
    assert result.available is False
    assert result.probability is None


def test_tls_inspector_blocks_private_hosts() -> None:
    result = inspect_tls_url("https://127.0.0.1")
    assert result.status == "skipped"
    assert "blocked" in result.explanation.lower()


def test_tls_inspector_marks_http_urls_not_applicable() -> None:
    result = inspect_tls_url("http://example.com")
    assert result.status == "not_applicable"
    assert result.hostname == "example.com"


def test_tls_inspector_blocks_localhost_hostname() -> None:
    result = inspect_tls_url("https://localhost")
    assert result.status == "skipped"
    assert "blocked" in result.explanation.lower()


def test_email_analysis_does_not_trigger_tls_for_embedded_urls(monkeypatch) -> None:
    def _fail(*args, **kwargs):
        raise AssertionError("embedded email URLs should not trigger TLS inspection")

    monkeypatch.setattr("src.engines.url.analyzer.inspect_tls_url", _fail)
    result = analyze_email({
        "from": "alice@example.com",
        "subject": "Test",
        "body_html": '<a href="https://example.com/login?token=abc123">Click here</a>',
    })
    assert result["urls"]
    assert result["confidence"] is None
