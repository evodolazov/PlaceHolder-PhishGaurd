"""Temporary deterministic risk-scoring engine for Milestone 0."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.engines.url.features import URLFeatures


@dataclass(frozen=True)
class RiskAssessment:
    """Heuristic risk result with transparent evidence and confidence."""

    classification: str
    risk_score: int
    confidence: float
    evidence: list[dict[str, Any]]


def score_url(features: URLFeatures, normalized_url: Any | None = None) -> RiskAssessment:
    """Compute a simple heuristic score. These weights are intentionally provisional."""
    score = 0
    evidence: list[dict[str, Any]] = []

    if features.has_ip_address:
        score += 30
        evidence.append({
            "source": "risk_engine",
            "indicator": "ip_address",
            "severity": "high",
            "value": True,
            "description": "IP-based hostnames are common in phishing infrastructure.",
        })
    if features.has_punycode:
        score += 25
        evidence.append({
            "source": "risk_engine",
            "indicator": "punycode",
            "severity": "high",
            "value": True,
            "description": "Punycode disguises lookalike domains.",
        })
    if features.at_symbol_count > 0:
        score += 25
        evidence.append({
            "source": "risk_engine",
            "indicator": "at_symbol",
            "severity": "high",
            "value": features.at_symbol_count,
            "description": "The URL authority contains an @ sign that can hide the true hostname.",
        })
    if features.suspicious_keyword_count > 0:
        score += features.suspicious_keyword_count * 5
        evidence.append({
            "source": "risk_engine",
            "indicator": "suspicious_keywords",
            "severity": "low",
            "value": features.suspicious_keyword_count,
            "description": "The URL contains credential-related or urgent-action keywords.",
        })
    if features.url_length > 75:
        score += 10
        evidence.append({
            "source": "risk_engine",
            "indicator": "long_url",
            "severity": "medium",
            "value": features.url_length,
            "description": "The URL is unusually long for a normal destination.",
        })
    if features.subdomain_count > 2:
        score += 10
        evidence.append({
            "source": "risk_engine",
            "indicator": "multiple_subdomains",
            "severity": "medium",
            "value": features.subdomain_count,
            "description": "Multiple subdomains may be used to disguise or impersonate trusted brands.",
        })
    if features.is_nonstandard_port:
        score += 10
        evidence.append({
            "source": "risk_engine",
            "indicator": "suspicious_port",
            "severity": "medium",
            "value": features.port,
            "description": "The URL specifies a non-standard port, which may be used to hide traffic intent.",
        })
    if not features.uses_https:
        score += 5
        evidence.append({
            "source": "risk_engine",
            "indicator": "http_not_https",
            "severity": "low",
            "value": False,
            "description": "The URL does not use HTTPS, which is a weak but meaningful signal.",
        })

    score = min(100, score)
    if score < 30:
        classification = "low_risk"
    elif score < 60:
        classification = "moderate_risk"
    elif score < 80:
        classification = "high_risk"
    else:
        classification = "critical_risk"

    confidence = max(0.05, min(0.99, score / 100.0))
    return RiskAssessment(
        classification=classification,
        risk_score=score,
        confidence=confidence,
        evidence=evidence,
    )
