"""Email analysis orchestration for day 1."""

from __future__ import annotations

from typing import Any

from src.engines.email.features import extract_features
from src.engines.email.parser import http_links, parse_email
from src.engines.url.analyzer import analyze_url
from src.fusion.email_risk_engine import score_email


def _score_links(parsed) -> list[dict[str, Any]]:
    scored: list[dict[str, Any]] = []
    seen: set[str] = set()
    for link in http_links(parsed):
        if link.href in seen:
            continue
        seen.add(link.href)
        try:
            result = analyze_url(link.href, allow_tls=False)
        except ValueError:
            continue
        scored.append(
            {
                "url": result["url"],
                "normalized_url": result["normalized_url"],
                "classification": result["classification"],
                "risk_score": result["risk_score"],
                "confidence": result["confidence"],
                "ml_probability": result.get("ml_probability"),
                "ml_prediction": result.get("ml_prediction"),
                "ml_model_status": result.get("ml_model_status"),
                "ml_model_version": result.get("ml_model_version"),
                "feature_schema_version": result.get("feature_schema_version"),
                "evidence": result["evidence"],
            }
        )
    return scored


def analyze_email(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse an email, score embedded URLs, and apply email heuristics."""
    parsed = parse_email(payload)
    features = extract_features(parsed)
    url_results = _score_links(parsed)
    assessment = score_email(features, url_results)

    ml_probability = next((link.get("ml_probability") for link in url_results if link.get("ml_probability") is not None), None)
    ml_prediction = next((link.get("ml_prediction") for link in url_results if link.get("ml_prediction") is not None), None)
    ml_model_status = next((link.get("ml_model_status") for link in url_results if link.get("ml_model_status") is not None), None)
    ml_model_version = next((link.get("ml_model_version") for link in url_results if link.get("ml_model_version") is not None), None)
    feature_schema_version = next((link.get("feature_schema_version") for link in url_results if link.get("feature_schema_version") is not None), None)

    return {
        "from": payload.get("from") or parsed.from_address,
        "reply_to": payload.get("reply_to") or parsed.reply_to_address or None,
        "subject": parsed.subject,
        "classification": assessment.classification,
        "risk_score": assessment.risk_score,
        "confidence": assessment.confidence,
        "ml_probability": ml_probability,
        "ml_prediction": ml_prediction,
        "ml_model_status": ml_model_status,
        "ml_model_version": ml_model_version,
        "feature_schema_version": feature_schema_version,
        "features": features.as_dict(),
        "evidence": assessment.evidence,
        "urls": url_results,
    }
