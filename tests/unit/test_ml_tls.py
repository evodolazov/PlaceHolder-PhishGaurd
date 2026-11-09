from __future__ import annotations

from src.engines.email.analyzer import analyze_email
from src.engines.ml.feature_schema import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from src.engines.ml.predictor import predict_url_features
from src.engines.ml.training import load_training_dataset, train_default_model
from src.engines.tls.inspector import inspect_tls_url
from src.fusion.risk_engine import apply_ml_fusion, score_url
from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url


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


def test_training_dataset_loads_and_has_expected_labels() -> None:
    features, labels, summary = load_training_dataset()
    assert len(features) == len(labels) > 0
    assert summary.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert summary.label_distribution["phishing"] > 0
    assert summary.label_distribution["benign"] > 0


def test_ml_fusion_preserves_deterministic_scoring() -> None:
    normalized = normalize_url("https://example.com/login")
    assessment = score_url(extract_features(normalized), normalized, ml_probability=0.92)
    assert assessment.ml_probability == 0.92
    assert "ml_fusion" in assessment.evidence[-1]["type"]
    assert assessment.risk_score >= 0


def test_train_default_model_generates_model_metadata() -> None:
    result = train_default_model()
    assert result["metrics"]["accuracy"] >= 0.55
    assert result["version"] == "url-logreg-v1"


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
    assert "ml_probability" in result or result["urls"][0].get("ml_probability") is not None
