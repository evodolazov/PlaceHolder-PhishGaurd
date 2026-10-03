"""Service layer that coordinates analysis and persistence."""

from __future__ import annotations

from src.database.repositories.analysis_repository import AnalysisRepository
from src.engines.url.analyzer import analyze_url


class URLAnalysisService:
    """Coordinate URL validation, analysis, and persistence for the API."""

    def __init__(self, repository: AnalysisRepository | None = None) -> None:
        self.repository = repository or AnalysisRepository()

    def analyze(self, raw_url: str) -> dict[str, object]:
        payload = analyze_url(raw_url)
        analysis = self.repository.persist_analysis(
            raw_url=raw_url,
            normalized_url=payload["normalized_url"],
            scheme=payload["scheme"],
            hostname=payload["hostname"],
            registrable_domain=payload["registrable_domain"],
            classification=payload["classification"],
            risk_score=payload["risk_score"],
            confidence=payload["confidence"],
            features=payload["features"],
            evidence=payload["evidence"],
        )

        return {
            "analysis_id": analysis.id,
            "url": raw_url,
            "normalized_url": payload["normalized_url"],
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "features": analysis.features,
            "evidence": analysis.evidence,
            "created_at": analysis.created_at.isoformat(),
        }

    def get_analysis(self, analysis_id: int) -> dict[str, object] | None:
        record = self.repository.get_analysis(analysis_id)
        if record is None:
            return None

        return {
            "analysis_id": record.id,
            "url": record.url.raw_url,
            "normalized_url": record.url.normalized_url,
            "classification": record.classification,
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "features": record.features,
            "evidence": record.evidence,
            "created_at": record.created_at.isoformat(),
        }
