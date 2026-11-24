"""Service layer that coordinates analysis and persistence."""

from __future__ import annotations

from src.database.repositories.analysis_repository import AnalysisRepository
from src.engines.url.analyzer import analyze_url
from src.engines.url.sanitizer import sanitize_url_for_storage
from src.services.analysis_metadata import (
    features_with_threat_status,
    features_without_threat_status,
)


class URLAnalysisService:
    """Coordinate URL validation, analysis, and persistence for the API."""

    def __init__(self, repository: AnalysisRepository | None = None) -> None:
        self.repository = repository or AnalysisRepository()

    def analyze(self, raw_url: str) -> dict[str, object]:
        payload = analyze_url(raw_url)
        safe_url = sanitize_url_for_storage(raw_url)
        threat_status = payload["threat_intelligence"]
        analysis = self.repository.persist_analysis(
            raw_url=safe_url,
            normalized_url=payload["normalized_url"],
            scheme=payload["scheme"],
            hostname=payload["hostname"],
            registrable_domain=payload["registrable_domain"],
            classification=payload["classification"],
            risk_score=payload["risk_score"],
            confidence=payload["confidence"],
            features=features_with_threat_status(payload["features"], threat_status),
            evidence=payload["evidence"],
        )

        return {
            "analysis_id": analysis.id,
            "url": safe_url,
            "normalized_url": payload["normalized_url"],
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "features": payload["features"],
            "evidence": analysis.evidence,
            "threat_intelligence": threat_status,
            "created_at": analysis.created_at.isoformat(),
        }

    def get_analysis(self, analysis_id: int) -> dict[str, object] | None:
        record = self.repository.get_analysis(analysis_id)
        if record is None:
            return None

        features, threat_status = features_without_threat_status(record.features)
        return {
            "analysis_id": record.id,
            "url": record.url.raw_url,
            "normalized_url": record.url.normalized_url,
            "classification": record.classification,
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "features": features,
            "evidence": record.evidence,
            "threat_intelligence": threat_status,
            "created_at": record.created_at.isoformat(),
        }

    def list_analyses(self, page: int, page_size: int, risk_level: str = "", search: str = "") -> dict[str, object]:
        records, total = self.repository.list_analyses(page, page_size, risk_level, search)
        return {
            "items": [
                {
                    "analysis_id": record.id,
                    "url": record.url.raw_url,
                    "classification": record.classification,
                    "risk_score": record.risk_score,
                    "confidence": record.confidence,
                    "created_at": record.created_at.isoformat(),
                }
                for record in records
            ],
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": max(1, (total + page_size - 1) // page_size),
        }

    def delete_analysis(self, analysis_id: int) -> bool:
        return self.repository.delete_analysis(analysis_id)
