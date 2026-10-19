"""Database models for email records and analyses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.connection import db


class EmailRecord(db.Model):
    """Persisted email submission for analysis history."""

    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(primary_key=True)
    from_address: Mapped[str] = mapped_column(nullable=False, default="", index=True)
    reply_to: Mapped[str | None] = mapped_column(nullable=True)
    subject: Mapped[str] = mapped_column(nullable=False, default="")
    body_text: Mapped[str] = mapped_column(nullable=False, default="")
    body_html: Mapped[str] = mapped_column(nullable=False, default="")
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), nullable=False)

    analyses: Mapped[list["EmailAnalysisRecord"]] = relationship(
        back_populates="email",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )


class EmailAnalysisRecord(db.Model):
    """Persisted risk analysis results for an email submission."""

    __tablename__ = "email_analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id"), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    urls: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc), nullable=False)

    email: Mapped[EmailRecord] = relationship(back_populates="analyses")
