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
    ml_fusion_note: str | None = None
    ml_adjustment: int = 0


def _classify(score: int) -> str:
    if score < 30:
        return "low_risk"
    if score < 60:
        return "moderate_risk"
    if score < 80:
        return "high_risk"
    return "critical_risk"


def apply_ml_fusion(assessment: RiskAssessment, ml_probability: float | None) -> RiskAssessment:
    """Blend ML evidence conservatively without replacing deterministic scoring.

    ML is treated as a supporting signal only; it may adjust the final assessment
    at the extremes of the probability range but never replaces the deterministic
    evidence model. The original deterministic score remains available for audits.
    """
    if ml_probability is None:
        return assessment

    if not 0.0 <= ml_probability <= 1.0:
        return assessment

    if ml_probability >= 0.8:
        adjustment = 10
        note = "ML probability exceeded 0.8; the final score was elevated by 10 points as a secondary, explainable signal."
    elif ml_probability <= 0.2:
        adjustment = -10
        note = "ML probability was below 0.2; the final score was reduced by 10 points as a secondary, explainable signal."
    else:
        adjustment = 0
        note = "ML probability was within the non-extreme range; deterministic scoring remained authoritative."

    if adjustment:
        adjusted_score = max(0, min(100, assessment.risk_score + adjustment))
        evidence = list(assessment.evidence)
        evidence.append({
            "type": "ml_fusion",
            "detail": note,
            "ml_probability": round(float(ml_probability), 4),
            "risk_score_before": assessment.risk_score,
            "risk_score_after": adjusted_score,
        })
        return RiskAssessment(
            classification=_classify(adjusted_score),
            risk_score=adjusted_score,
            confidence=assessment.confidence,
            evidence=evidence,
            ml_probability=ml_probability,
            heuristic_strength=assessment.heuristic_strength,
            ml_fusion_note=note,
            ml_adjustment=adjustment,
        )

    evidence = list(assessment.evidence)
    evidence.append({
        "type": "ml_fusion",
        "detail": note,
        "ml_probability": round(float(ml_probability), 4),
    })
    return RiskAssessment(
        classification=assessment.classification,
        risk_score=assessment.risk_score,
        confidence=assessment.confidence,
        evidence=evidence,
        ml_probability=ml_probability,
        heuristic_strength=assessment.heuristic_strength,
        ml_fusion_note=note,
        ml_adjustment=0,
    )


def score_url(
    features: URLFeatures,
    normalized_url: NormalizedURL | None = None,
    *,
    ml_probability: float | None = None,
) -> RiskAssessment:
    """Sum fired rule weights while preserving a separate ML probability signal."""
    if normalized_url is None:
        raise TypeError("normalized_url is required to evaluate URL rules.")

    results = evaluate_rules(features, normalized_url)
    fired = [result for result in results if result.fired]
    score = min(100, sum(result.weight for result in fired))
    evidence = [result.to_evidence() for result in fired]
    heuristic_strength = None if not evidence else round(min(1.0, len(evidence) / 6.0), 4)

    assessment = RiskAssessment(
        classification=_classify(score),
        risk_score=score,
        confidence=None,
        evidence=evidence,
        ml_probability=ml_probability,
        heuristic_strength=heuristic_strength,
    )
    return apply_ml_fusion(assessment, ml_probability)
