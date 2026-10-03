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
    confidence: Mapped[float] = mapped_column(nullable=False)
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
            "features": self.features,
            "evidence": self.evidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
