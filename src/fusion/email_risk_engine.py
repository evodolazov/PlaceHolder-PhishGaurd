"""Combine email heuristics with extracted-URL scores."""

from __future__ import annotations

from typing import Any

from src.engines.email.features import EmailFeatures
from src.engines.email.rules import evaluate_rules
from src.fusion.risk_engine import RiskAssessment, _classify

EMAIL_RULE_CAP = 70
URL_SCORE_CAP = 40


def score_email(features: EmailFeatures, url_results: list[dict[str, Any]] | None = None) -> RiskAssessment:
    """Sum email-rule weights and the strongest URL score."""
    url_results = url_results or []
    results = evaluate_rules(features)
    fired = [result for result in results if result.fired]
    email_points = min(EMAIL_RULE_CAP, sum(result.weight for result in fired))
    url_points = min(URL_SCORE_CAP, max((int(item.get("risk_score") or 0) for item in url_results), default=0))
    score = min(100, email_points + url_points)
    evidence = [result.to_evidence() for result in fired]
    for item in url_results:
        for url_evidence in item.get("evidence") or []:
            enriched = dict(url_evidence)
            enriched["url"] = item.get("url")
            evidence.append(enriched)

    return RiskAssessment(
        classification=_classify(score),
        risk_score=score,
        confidence=0.0 if not evidence else round(min(0.99, 0.15 + (0.6 * min(1.0, len(evidence) / 6.0)) + (0.25 * min(1.0, abs(score - 50) / 50.0))), 4),
        evidence=evidence,
        ml_probability=None,
    )
