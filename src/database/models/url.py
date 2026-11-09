"""Database models for URL records and analyses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.connection import db


class URLRecord(db.Model):
    """Persisted URL information for analysis history."""

    __tablename__ = "urls"

    id: Mapped[int] = mapped_column(primary_key=True)
    raw_url: Mapped[str] = mapped_column(unique=True, nullable=False, index=True)
    normalized_url: Mapped[str] = mapped_column(nullable=False)
    scheme: Mapped[str] = mapped_column(nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(nullable=False, index=True)
    registrable_domain: Mapped[str] = mapped_column(nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), nullable=False)

    analyses: Mapped[list["AnalysisRecord"]] = relationship(
        back_populates="url",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "raw_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "registrable_domain": self.registrable_domain,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AnalysisRecord(db.Model):
    """Persisted risk analysis results for a normalized URL."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("urls.id"), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(nullable=False)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    ml_probability: Mapped[float | None] = mapped_column(nullable=True)
    ml_prediction: Mapped[str | None] = mapped_column(nullable=True)
    ml_model_status: Mapped[str | None] = mapped_column(nullable=True)
    ml_model_version: Mapped[str | None] = mapped_column(nullable=True)
    feature_schema_version: Mapped[str | None] = mapped_column(nullable=True)
    tls_status: Mapped[str | None] = mapped_column(nullable=True)
    tls_version: Mapped[str | None] = mapped_column(nullable=True)
    tls_cipher: Mapped[str | None] = mapped_column(nullable=True)
    tls_subject: Mapped[str | None] = mapped_column(nullable=True)
    tls_issuer: Mapped[str | None] = mapped_column(nullable=True)
    tls_expiration: Mapped[str | None] = mapped_column(nullable=True)
    tls_hostname_match: Mapped[bool | None] = mapped_column(nullable=True)
    tls_fingerprint: Mapped[str | None] = mapped_column(nullable=True)
    tls_inspection_timestamp: Mapped[datetime | None] = mapped_column(nullable=True)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), nullable=False)

    url: Mapped[URLRecord] = relationship(back_populates="analyses")

    def to_dict(self) -> dict[str, object]:
        return {
            "analysis_id": self.id,
            "url_id": self.url_id,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "ml_probability": self.ml_probability,
            "ml_prediction": self.ml_prediction,
            "ml_model_status": self.ml_model_status,
            "ml_model_version": self.ml_model_version,
            "feature_schema_version": self.feature_schema_version,
            "tls_status": self.tls_status,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "tls_subject": self.tls_subject,
            "tls_issuer": self.tls_issuer,
            "tls_expiration": self.tls_expiration,
            "tls_hostname_match": self.tls_hostname_match,
            "tls_fingerprint": self.tls_fingerprint,
            "tls_inspection_timestamp": self.tls_inspection_timestamp.isoformat() if self.tls_inspection_timestamp else None,
            "features": self.features,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
