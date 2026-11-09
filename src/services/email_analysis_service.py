"""Service layer that coordinates email analysis and persistence."""

from __future__ import annotations

from typing import Any

from src.database.repositories.email_analysis_repository import EmailAnalysisRepository
from src.engines.email.analyzer import analyze_email


class EmailAnalysisService:
    """Coordinate email parsing, analysis, and persistence for the API."""

    def __init__(self, repository: EmailAnalysisRepository | None = None) -> None:
        self.repository = repository or EmailAnalysisRepository()

    def analyze(self, payload: dict[str, Any]) -> dict[str, object]:
        result = analyze_email(payload)
        analysis = self.repository.persist_analysis(
            from_address=str(payload.get("from") or ""),
            reply_to=str(payload.get("reply_to")).strip() if payload.get("reply_to") else None,
            subject=str(payload.get("subject") or ""),
            body_text=str(payload.get("body_text") or ""),
            body_html=str(payload.get("body_html") or ""),
            headers=payload.get("headers") if isinstance(payload.get("headers"), dict) else {},
            classification=str(result["classification"]),
            risk_score=int(result["risk_score"]),
            confidence=result["confidence"],
            features=result["features"],
            evidence=result["evidence"],
            urls=result["urls"],
            ml_probability=result.get("ml_probability"),
            ml_prediction=result.get("ml_prediction"),
            ml_model_status=result.get("ml_model_status"),
            ml_model_version=result.get("ml_model_version"),
            feature_schema_version=result.get("feature_schema_version"),
        )

        return {
            "analysis_id": analysis.id,
            "from": result["from"],
            "reply_to": result["reply_to"],
            "subject": result["subject"],
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "ml_probability": analysis.ml_probability,
            "ml_prediction": analysis.ml_prediction,
            "ml_model_status": analysis.ml_model_status,
            "ml_model_version": analysis.ml_model_version,
            "feature_schema_version": analysis.feature_schema_version,
            "features": analysis.features,
            "evidence": analysis.evidence,
            "urls": analysis.urls,
            "created_at": analysis.created_at.isoformat(),
        }

    def get_analysis(self, analysis_id: int) -> dict[str, object] | None:
        record = self.repository.get_analysis(analysis_id)
        if record is None:
            return None

        return {
            "analysis_id": record.id,
            "from": record.email.from_address,
            "reply_to": record.email.reply_to,
            "subject": record.email.subject,
            "classification": record.classification,
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "ml_probability": record.ml_probability,
            "ml_prediction": record.ml_prediction,
            "ml_model_status": record.ml_model_status,
            "ml_model_version": record.ml_model_version,
            "feature_schema_version": record.feature_schema_version,
            "features": record.features,
            "evidence": record.evidence,
            "urls": record.urls,
            "created_at": record.created_at.isoformat(),
        }
