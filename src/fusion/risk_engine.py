"""Temporary deterministic risk-scoring engine for Milestone 0."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.engines.url.features import URLFeatures
from src.engines.url.normalizer import NormalizedURL
from src.engines.url.rules import evaluate_rules


def _heuristic_confidence(score: int, evidence: list[dict[str, Any]]) -> float:
    """Estimate certainty from evidence intensity without pretending this is a calibrated probability."""
    if not evidence and score <= 0:
        return 0.0
    signal_strength = min(1.0, len(evidence) / 6.0)
    classification_margin = min(1.0, abs(score - 50) / 50.0)
    confidence = 0.1 + (0.35 * signal_strength) + (0.55 * classification_margin)
    return round(min(0.99, max(0.0, confidence)), 4)


@dataclass(frozen=True)
class RiskAssessment:
    """Transparent risk result and supporting evidence."""

    classification: str
    risk_score: int
    confidence: float
    evidence: list[dict[str, Any]]
    ml_probability: float | None = None


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

    return RiskAssessment(
        classification=_classify(score),
        risk_score=score,
        confidence=_heuristic_confidence(score, evidence),
        evidence=evidence,
        ml_probability=None,
    )
