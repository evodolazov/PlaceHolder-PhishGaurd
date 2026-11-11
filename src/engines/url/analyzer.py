"""URL analysis orchestration for Milestone 0."""

from __future__ import annotations

from typing import Any

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url, validate_url
from src.engines.url.sanitizer import sanitize_url_for_storage
from src.fusion.risk_engine import RiskAssessment, score_url


def analyze_url(raw_url: str) -> dict[str, Any]:
    """Validate, normalize, extract features, score, and prepare evidence."""
    if not validate_url(raw_url):
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    normalized = normalize_url(raw_url)
    features = extract_features(normalized)

    risk_assessment: RiskAssessment = score_url(features, normalized)
    safe_url = sanitize_url_for_storage(raw_url)

    return {
        "url": safe_url,
        "normalized_url": normalized.normalized_url,
        "scheme": normalized.scheme,
        "hostname": normalized.hostname,
        "registrable_domain": normalized.registrable_domain,
        "classification": risk_assessment.classification,
        "risk_score": risk_assessment.risk_score,
        "confidence": risk_assessment.confidence,
        "features": features.as_dict(),
        "evidence": risk_assessment.evidence,
    }
