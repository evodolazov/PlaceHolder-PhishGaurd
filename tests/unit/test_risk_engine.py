from __future__ import annotations

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url
from src.fusion.risk_engine import score_url


def test_low_risk_url() -> None:
    data = normalize_url("https://example.com")
    assessment = score_url(extract_features(data), data)
    assert assessment.classification == "low_risk"
    assert assessment.risk_score >= 0


def test_moderate_risk_url() -> None:
    data = normalize_url("https://example.com/login")
    assessment = score_url(extract_features(data), data)
    assert assessment.classification in {"low_risk", "moderate_risk"}


def test_high_risk_url() -> None:
    data = normalize_url("https://xn--example-9ua.com/login@evil.com")
    assessment = score_url(extract_features(data), data)
    assert assessment.risk_score >= 25
    assert assessment.risk_score <= 100


def test_score_caps_at_100() -> None:
    data = normalize_url("https://192.168.0.1/login@evil.com/verify/security")
    assessment = score_url(extract_features(data), data)
    assert assessment.risk_score <= 100
