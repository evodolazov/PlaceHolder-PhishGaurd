"""URL analysis orchestration for Milestone 0."""

from __future__ import annotations

from typing import Any

from src.engines.url.features import URLFeatures, extract_features
from src.engines.url.normalizer import NormalizedURL, normalize_url, validate_url
from src.fusion.risk_engine import RiskAssessment, score_url


def _build_raw_evidence(normalized_url: NormalizedURL, features: URLFeatures) -> list[dict[str, Any]]:
    """Create structured, low-level evidence without duplicate risk-engine indicators."""
    evidence: list[dict[str, Any]] = []

    if features.has_ip_address:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "ip_address",
            "severity": "high",
            "value": True,
            "description": "The hostname is an IP address instead of a domain name.",
        })
    if features.has_punycode:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "punycode",
            "severity": "high",
            "value": True,
            "description": "The hostname contains Punycode/IDN encoding.",
        })
    if features.at_symbol_count > 0:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "at_symbol",
            "severity": "high",
            "value": features.at_symbol_count,
            "description": "The URL contains an @ symbol in the authority section, which can hide the true hostname.",
        })
    if features.suspicious_keyword_count > 0:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "suspicious_keywords",
            "severity": "low",
            "value": features.suspicious_keyword_count,
            "description": "The URL contains credential-related or urgent-action keywords.",
        })
    if features.subdomain_count > 2:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "multiple_subdomains",
            "severity": "medium",
            "value": features.subdomain_count,
            "description": "The hostname contains several subdomains.",
        })
    if features.is_nonstandard_port:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "suspicious_port",
            "severity": "medium",
            "value": normalized_url.port,
            "description": "The URL uses a non-standard port that can be abused to disguise traffic.",
        })
    if not features.uses_https:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "http_not_https",
            "severity": "low",
            "value": False,
            "description": "The URL does not use the HTTPS scheme.",
        })
    if features.url_length > 75:
        evidence.append({
            "source": "url_analyzer",
            "indicator": "long_url",
            "severity": "medium",
            "value": features.url_length,
            "description": "The URL length is unusually long for a regular destination.",
        })
    return evidence


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in evidence:
        indicator = str(item.get("indicator", ""))
        if indicator in seen:
            continue
        seen.add(indicator)
        unique.append(item)
    return unique


def analyze_url(raw_url: str) -> dict[str, Any]:
    """Validate, normalize, extract features, score, and prepare evidence."""
    if not validate_url(raw_url):
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    normalized = normalize_url(raw_url)
    features = extract_features(normalized)

    risk_assessment: RiskAssessment = score_url(features, normalized)
    raw_evidence = _build_raw_evidence(normalized, features)
    evidence = _dedupe_evidence(raw_evidence + risk_assessment.evidence)

    return {
        "url": raw_url,
        "normalized_url": normalized.normalized_url,
        "scheme": normalized.scheme,
        "hostname": normalized.hostname,
        "registrable_domain": normalized.registrable_domain,
        "classification": risk_assessment.classification,
        "risk_score": risk_assessment.risk_score,
        "confidence": risk_assessment.confidence,
        "features": features.as_dict(),
        "evidence": evidence,
    }
