"""Deterministic risk-scoring engine for URL analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.engines.url.features import URLFeatures
from src.engines.url.normalizer import NormalizedURL
from src.engines.url.rules import evaluate_rules


@dataclass(frozen=True)
class RiskAssessment:
    """Transparent risk result and supporting evidence."""

    classification: str
    risk_score: int
    confidence: float | None
    evidence: list[dict[str, Any]]
    ml_probability: float | None = None
    heuristic_strength: float | None = None


def _classify(score: int) -> str:
    if score < 30:
        return "low_risk"
    if score < 60:
        return "moderate_risk"
    if score < 80:
        return "high_risk"
    return "critical_risk"


def score_url(features: URLFeatures, normalized_url: NormalizedURL | None = None) -> RiskAssessment:
    """Sum fired rule weights. These weights are intentionally provisional."""
    if normalized_url is None:
        raise TypeError("normalized_url is required to evaluate URL rules.")

    results = evaluate_rules(features, normalized_url)
    fired = [result for result in results if result.fired]
    score = min(100, sum(result.weight for result in fired))
    evidence = [result.to_evidence() for result in fired]
    heuristic_strength = None if not evidence else round(min(1.0, len(evidence) / 6.0), 4)

    return RiskAssessment(
        classification=_classify(score),
        risk_score=score,
        confidence=None,
        evidence=evidence,
        ml_probability=None,
        heuristic_strength=heuristic_strength,
    )
