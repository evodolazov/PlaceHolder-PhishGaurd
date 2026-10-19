from __future__ import annotations

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url
from src.fusion.risk_engine import score_url


def _score(url: str):
    data = normalize_url(url)
    return score_url(extract_features(data), data)


def test_low_risk_url() -> None:
    assessment = _score("https://example.com")
    assert assessment.classification == "low_risk"
    assert assessment.risk_score == 0
    assert assessment.evidence == []


def test_moderate_risk_url() -> None:
    assessment = _score("https://example.com/login")
    assert assessment.classification in {"low_risk", "moderate_risk"}
    assert any(item["indicator"] == "url.suspicious_keywords" for item in assessment.evidence)


def test_high_risk_url() -> None:
    assessment = _score("https://xn--example-9ua.com/login@evil.com")
    assert assessment.risk_score >= 25
    assert assessment.risk_score <= 100
    assert all(item["source"] == "url_rules" for item in assessment.evidence)


def test_score_caps_at_100() -> None:
    assessment = _score("https://192.168.0.1/login@evil.com/verify/security")
    assert assessment.risk_score <= 100


def test_http_and_keyword_signals_stack() -> None:
    assessment = _score("http://example.com/login")
    indicators = {item["indicator"] for item in assessment.evidence}
    assert "url.http_not_https" in indicators
    assert "url.suspicious_keywords" in indicators
    assert assessment.risk_score >= 10
