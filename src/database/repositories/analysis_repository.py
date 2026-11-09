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
        confidence: float,
        features: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> AnalysisRecord:
        record = AnalysisRecord(
            url_id=url_record.id,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
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
        confidence: float,
        features: dict[str, Any],
        evidence: list[dict[str, Any]],
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
            )
            return analysis

    def get_analysis(self, analysis_id: int) -> AnalysisRecord | None:
        return self.session.get(AnalysisRecord, analysis_id)
