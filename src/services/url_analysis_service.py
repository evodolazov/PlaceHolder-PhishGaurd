"""Service layer that coordinates analysis and persistence."""

from __future__ import annotations

from datetime import datetime

from src.database.repositories.analysis_repository import AnalysisRepository
from src.engines.url.analyzer import analyze_url
from src.engines.url.sanitizer import sanitize_url_for_storage


class URLAnalysisService:
    """Coordinate URL validation, analysis, and persistence for the API."""

    def __init__(self, repository: AnalysisRepository | None = None) -> None:
        self.repository = repository or AnalysisRepository()

    def analyze(self, raw_url: str, *, allow_tls: bool | None = None) -> dict[str, object]:
        payload = analyze_url(raw_url, allow_tls=allow_tls)
        safe_url = sanitize_url_for_storage(raw_url)
        tls_timestamp = payload.get("tls_inspection_timestamp")
        parsed_tls_timestamp = None
        if isinstance(tls_timestamp, str):
            try:
                parsed_tls_timestamp = datetime.fromisoformat(tls_timestamp)
            except ValueError:
                parsed_tls_timestamp = None
        analysis = self.repository.persist_analysis(
            raw_url=safe_url,
            normalized_url=payload["normalized_url"],
            scheme=payload["scheme"],
            hostname=payload["hostname"],
            registrable_domain=payload["registrable_domain"],
            classification=payload["classification"],
            risk_score=payload["risk_score"],
            confidence=payload["confidence"],
            features=payload["features"],
            evidence=payload["evidence"],
            ml_probability=payload.get("ml_probability"),
            ml_prediction=payload.get("ml_prediction"),
            ml_model_status=payload.get("ml_model_status"),
            ml_model_version=payload.get("ml_model_version"),
            feature_schema_version=payload.get("feature_schema_version"),
            tls_status=payload.get("tls_status"),
            tls_version=payload.get("tls_version"),
            tls_cipher=payload.get("tls_cipher"),
            tls_subject=payload.get("tls_subject"),
            tls_issuer=payload.get("tls_issuer"),
            tls_expiration=payload.get("tls_expiration"),
            tls_hostname_match=payload.get("tls_hostname_match"),
            tls_fingerprint=payload.get("tls_fingerprint"),
            tls_inspection_timestamp=parsed_tls_timestamp,
        )

        return {
            "analysis_id": analysis.id,
            "url": safe_url,
            "normalized_url": payload["normalized_url"],
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "ml_probability": analysis.ml_probability,
            "ml_prediction": analysis.ml_prediction,
            "ml_model_status": analysis.ml_model_status,
            "ml_model_version": analysis.ml_model_version,
            "feature_schema_version": analysis.feature_schema_version,
            "tls_status": analysis.tls_status,
            "tls_version": analysis.tls_version,
            "tls_cipher": analysis.tls_cipher,
            "tls_subject": analysis.tls_subject,
            "tls_issuer": analysis.tls_issuer,
            "tls_expiration": analysis.tls_expiration,
            "tls_hostname_match": analysis.tls_hostname_match,
            "tls_fingerprint": analysis.tls_fingerprint,
            "tls_inspection_timestamp": analysis.tls_inspection_timestamp.isoformat() if analysis.tls_inspection_timestamp else None,
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
            "ml_probability": record.ml_probability,
            "ml_prediction": record.ml_prediction,
            "ml_model_status": record.ml_model_status,
            "ml_model_version": record.ml_model_version,
            "feature_schema_version": record.feature_schema_version,
            "tls_status": record.tls_status,
            "tls_version": record.tls_version,
            "tls_cipher": record.tls_cipher,
            "tls_subject": record.tls_subject,
            "tls_issuer": record.tls_issuer,
            "tls_expiration": record.tls_expiration,
            "tls_hostname_match": record.tls_hostname_match,
            "tls_fingerprint": record.tls_fingerprint,
            "tls_inspection_timestamp": record.tls_inspection_timestamp.isoformat() if record.tls_inspection_timestamp else None,
            "features": record.features,
            "evidence": record.evidence,
            "created_at": record.created_at.isoformat(),
        }
