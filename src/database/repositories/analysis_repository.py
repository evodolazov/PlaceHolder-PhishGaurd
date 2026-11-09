"""Repository layer for URL and analysis persistence."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from src.database.connection import db
from src.database.models.url import AnalysisRecord, URLRecord
from src.engines.url.sanitizer import sanitize_url_for_storage


class AnalysisRepository:
    """Store URL records and generated risk analyses in a transactional manner."""

    def __init__(self, session=None) -> None:
        self.session = session or db.session

    def create_or_get_url(
        self,
        *,
        raw_url: str,
        normalized_url: str,
        scheme: str,
        hostname: str,
        registrable_domain: str,
    ) -> URLRecord:
        safe_raw_url = sanitize_url_for_storage(raw_url)
        existing = self.session.execute(
            select(URLRecord).where(URLRecord.raw_url == safe_raw_url)
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        record = URLRecord(
            raw_url=safe_raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            registrable_domain=registrable_domain,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def create_analysis(
        self,
        *,
        url_record: URLRecord,
        classification: str,
        risk_score: int,
        confidence: float | None,
        features: dict[str, Any],
        evidence: list[dict[str, Any]],
        ml_probability: float | None = None,
        ml_prediction: str | None = None,
        ml_model_status: str | None = None,
        ml_model_version: str | None = None,
        feature_schema_version: str | None = None,
        tls_status: str | None = None,
        tls_version: str | None = None,
        tls_cipher: str | None = None,
        tls_subject: str | None = None,
        tls_issuer: str | None = None,
        tls_expiration: str | None = None,
        tls_hostname_match: bool | None = None,
        tls_fingerprint: str | None = None,
        tls_inspection_timestamp: Any | None = None,
    ) -> AnalysisRecord:
        record = AnalysisRecord(
            url_id=url_record.id,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            ml_probability=ml_probability,
            ml_prediction=ml_prediction,
            ml_model_status=ml_model_status,
            ml_model_version=ml_model_version,
            feature_schema_version=feature_schema_version,
            tls_status=tls_status,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            tls_subject=tls_subject,
            tls_issuer=tls_issuer,
            tls_expiration=tls_expiration,
            tls_hostname_match=tls_hostname_match,
            tls_fingerprint=tls_fingerprint,
            tls_inspection_timestamp=tls_inspection_timestamp,
            features=features,
            evidence=evidence,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def persist_analysis(
        self,
        *,
        raw_url: str,
        normalized_url: str,
        scheme: str,
        hostname: str,
        registrable_domain: str,
        classification: str,
        risk_score: int,
        confidence: float | None,
        features: dict[str, Any],
        evidence: list[dict[str, Any]],
        ml_probability: float | None = None,
        ml_prediction: str | None = None,
        ml_model_status: str | None = None,
        ml_model_version: str | None = None,
        feature_schema_version: str | None = None,
        tls_status: str | None = None,
        tls_version: str | None = None,
        tls_cipher: str | None = None,
        tls_subject: str | None = None,
        tls_issuer: str | None = None,
        tls_expiration: str | None = None,
        tls_hostname_match: bool | None = None,
        tls_fingerprint: str | None = None,
        tls_inspection_timestamp: Any | None = None,
    ) -> AnalysisRecord:
        """Persist both URL and analysis in a single transaction."""
        with self.session.begin():
            url_record = self.create_or_get_url(
                raw_url=raw_url,
                normalized_url=normalized_url,
                scheme=scheme,
                hostname=hostname,
                registrable_domain=registrable_domain,
            )
            analysis = self.create_analysis(
                url_record=url_record,
                classification=classification,
                risk_score=risk_score,
                confidence=confidence,
                features=features,
                evidence=evidence,
                ml_probability=ml_probability,
                ml_prediction=ml_prediction,
                ml_model_status=ml_model_status,
                ml_model_version=ml_model_version,
                feature_schema_version=feature_schema_version,
                tls_status=tls_status,
                tls_version=tls_version,
                tls_cipher=tls_cipher,
                tls_subject=tls_subject,
                tls_issuer=tls_issuer,
                tls_expiration=tls_expiration,
                tls_hostname_match=tls_hostname_match,
                tls_fingerprint=tls_fingerprint,
                tls_inspection_timestamp=tls_inspection_timestamp,
            )
            return analysis

    def get_analysis(self, analysis_id: int) -> AnalysisRecord | None:
        return self.session.get(AnalysisRecord, analysis_id)
