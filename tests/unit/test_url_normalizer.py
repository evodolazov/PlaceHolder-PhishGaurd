from __future__ import annotations

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url, validate_url
from src.fusion.risk_engine import score_url


def test_normal_https_url() -> None:
    normalized = normalize_url("https://example.com")
    assert normalized.scheme == "https"
    assert normalized.hostname == "example.com"
    assert normalized.normalized_url == "https://example.com/"


def test_http_url_with_uppercase_hostname_and_query_fragment() -> None:
    normalized = normalize_url("http://Example.com/path?x=1#frag")
    assert normalized.scheme == "http"
    assert normalized.hostname == "example.com"
    assert normalized.path == "/path"
    assert normalized.query == "x=1"
    assert normalized.fragment == "frag"


def test_missing_path_is_normalized_to_root() -> None:
    normalized = normalize_url("https://example.com")
    assert normalized.path == "/"


def test_port_is_preserved() -> None:
    normalized = normalize_url("https://example.com:8443/path")
    assert normalized.port == 8443
    assert normalized.normalized_url == "https://example.com:8443/path"


def test_url_credentials_and_sensitive_query_values_are_redacted() -> None:
    normalized = normalize_url("https://user:pass@example.com/path?token=abc123&password=supersecret&safe=1")
    assert normalized.username == "user"
    assert normalized.password == "pass"
    assert "user:pass" not in normalized.raw_url
    assert "https://example.com/path" in normalized.raw_url
    assert "token=%5BREDACTED%5D" in normalized.raw_url
    assert "password=%5BREDACTED%5D" in normalized.raw_url
    assert "abc123" not in normalized.raw_url
    assert "supersecret" not in normalized.normalized_url
    assert "safe=1" in normalized.normalized_url


def test_confidence_does_not_just_equal_risk_score() -> None:
    normalized = normalize_url("https://example.com/login")
    assessment = score_url(extract_features(normalized), normalized)
    assert 0.0 <= assessment.confidence <= 0.99
    assert assessment.confidence != assessment.risk_score / 100.0


def test_malformed_url_is_rejected() -> None:
    assert validate_url("not a url") is False
    try:
        normalize_url("not a url")
    except ValueError:
        pass
    else:
        raise AssertionError("normalize_url should reject malformed input")


def test_unsupported_protocol_is_rejected() -> None:
    assert validate_url("ftp://example.com") is False
    try:
        normalize_url("ftp://example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("Unsupported protocols should raise ValueError")
