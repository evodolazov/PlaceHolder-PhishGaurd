"""Repository layer for email analysis persistence."""

from __future__ import annotations

from typing import Any

from src.database.connection import db
from src.database.models.email import EmailAnalysisRecord, EmailRecord


class EmailAnalysisRepository:
    """Store email submissions and generated risk analyses."""

    def __init__(self, session=None) -> None:
        self.session = session or db.session

    def persist_analysis(
        self,
        *,
        from_address: str,
        reply_to: str | None,
        subject: str,
        body_text: str,
        body_html: str,
        headers: dict[str, Any],
        classification: str,
        risk_score: int,
        confidence: float | None,
        features: dict[str, Any],
        evidence: list[dict[str, Any]],
        urls: list[dict[str, Any]],
        ml_probability: float | None = None,
        ml_prediction: str | None = None,
        ml_model_status: str | None = None,
        ml_model_version: str | None = None,
        feature_schema_version: str | None = None,
    ) -> EmailAnalysisRecord:
        with self.session.begin():
            email_record = EmailRecord(
                from_address=from_address or "",
                reply_to=reply_to,
                subject=subject or "",
                body_text=body_text or "",
                body_html=body_html or "",
                headers=headers or {},
            )
            self.session.add(email_record)
            self.session.flush()
            analysis = EmailAnalysisRecord(
                email_id=email_record.id,
                classification=classification,
                risk_score=risk_score,
                confidence=confidence,
                ml_probability=ml_probability,
                ml_prediction=ml_prediction,
                ml_model_status=ml_model_status,
                ml_model_version=ml_model_version,
                feature_schema_version=feature_schema_version,
                features=features,
                evidence=evidence,
                urls=urls,
            )
            self.session.add(analysis)
            self.session.flush()
            return analysis

    def get_analysis(self, analysis_id: int) -> EmailAnalysisRecord | None:
        return self.session.get(EmailAnalysisRecord, analysis_id)
