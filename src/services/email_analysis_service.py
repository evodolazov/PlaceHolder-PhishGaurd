"""Service layer that coordinates email analysis and persistence."""

from __future__ import annotations

from typing import Any

from src.database.repositories.email_analysis_repository import EmailAnalysisRepository
from src.engines.email.analyzer import analyze_email
from src.engines.threat_intel.safe_browsing import get_status
from src.services.analysis_metadata import (
    features_with_threat_status,
    features_without_threat_status,
)


def _email_threat_status(url_results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [
        result["threat_intelligence"]
        for result in url_results
        if isinstance(result.get("threat_intelligence"), dict)
    ]
    if not statuses:
        return get_status()

    match_found = any(status.get("match_found") is True for status in statuses)
    if any(status.get("status") == "unavailable" for status in statuses):
        return {
            "status": "unavailable",
            "match_found": True if match_found else None,
            "message": "At least one embedded URL lookup was unavailable.",
        }
    if match_found:
        return {
            "status": "enabled",
            "match_found": True,
            "message": "Safe Browsing found a match for an embedded URL.",
        }
    if any(status.get("status") == "enabled" for status in statuses):
        return {
            "status": "enabled",
            "match_found": False,
            "message": "Safe Browsing found no matches for the analyzed embedded URLs.",
        }
    if all(status.get("status") == "disabled" for status in statuses):
        return {
            "status": "disabled",
            "match_found": None,
            "message": "Google Safe Browsing is disabled.",
        }
    return get_status()


class EmailAnalysisService:
    """Coordinate email parsing, analysis, and persistence for the API."""

    def __init__(self, repository: EmailAnalysisRepository | None = None) -> None:
        self.repository = repository or EmailAnalysisRepository()

    def analyze(
        self,
        payload: dict[str, Any],
        *,
        feature_body_html: str | None = None,
    ) -> dict[str, object]:
        result = analyze_email(payload, feature_body_html=feature_body_html)
        threat_status = _email_threat_status(result["urls"])
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
            features=features_with_threat_status(result["features"], threat_status),
            evidence=result["evidence"],
            urls=result["urls"],
        )

        return {
            "analysis_id": analysis.id,
            "from": result["from"],
            "reply_to": result["reply_to"],
            "subject": result["subject"],
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "features": result["features"],
            "evidence": analysis.evidence,
            "urls": analysis.urls,
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
            "from": record.email.from_address,
            "reply_to": record.email.reply_to,
            "subject": record.email.subject,
            "classification": record.classification,
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "features": features,
            "evidence": record.evidence,
            "urls": record.urls,
            "threat_intelligence": threat_status,
            "created_at": record.created_at.isoformat(),
        }

    def list_analyses(self, page: int, page_size: int, risk_level: str = "", search: str = "") -> dict[str, object]:
        records, total = self.repository.list_analyses(page, page_size, risk_level, search)
        return {
            "items": [
                {
                    "analysis_id": record.id,
                    "from": record.email.from_address,
                    "reply_to": record.email.reply_to,
                    "subject": record.email.subject,
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
