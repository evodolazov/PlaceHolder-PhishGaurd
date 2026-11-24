"""Repository layer for email analysis persistence."""

from __future__ import annotations

from typing import Any

from src.database.connection import db
from src.database.models.email import EmailAnalysisRecord, EmailRecord
from sqlalchemy import desc, select
import os


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
    ) -> EmailAnalysisRecord:
        with self.session.begin():
            retain_contents = os.getenv("RETAIN_EMAIL_CONTENTS", "true").strip().lower() in {"1", "true", "yes", "on"}
            email_record = EmailRecord(
                from_address=from_address or "",
                reply_to=reply_to,
                subject=subject or "",
                body_text=body_text or "" if retain_contents else "",
                body_html=body_html or "" if retain_contents else "",
                headers=headers or {} if retain_contents else {},
            )
            self.session.add(email_record)
            self.session.flush()
            analysis = EmailAnalysisRecord(
                email_id=email_record.id,
                classification=classification,
                risk_score=risk_score,
                confidence=confidence,
                features=features,
                evidence=evidence,
                urls=urls,
            )
            self.session.add(analysis)
            self.session.flush()
            return analysis

    def get_analysis(self, analysis_id: int) -> EmailAnalysisRecord | None:
        return self.session.get(EmailAnalysisRecord, analysis_id)

    def list_analyses(self, page: int, page_size: int, risk_level: str = "", search: str = "") -> tuple[list[EmailAnalysisRecord], int]:
        stmt = select(EmailAnalysisRecord).join(EmailRecord)
        if risk_level:
            stmt = stmt.where(EmailAnalysisRecord.classification == risk_level)
        if search:
            pattern = f"%{search}%"
            stmt = stmt.where(
                (EmailRecord.subject.ilike(pattern))
                | (EmailRecord.from_address.ilike(pattern))
                | (EmailRecord.reply_to.ilike(pattern))
            )
        count_stmt = stmt.with_only_columns(EmailAnalysisRecord.id)
        total = len(self.session.execute(count_stmt).all())
        records = self.session.execute(
            stmt.order_by(desc(EmailAnalysisRecord.created_at)).limit(page_size).offset((page - 1) * page_size)
        ).scalars().all()
        return list(records), total

    def delete_analysis(self, analysis_id: int) -> bool:
        record = self.session.get(EmailAnalysisRecord, analysis_id)
        if record is None:
            return False

        email_id = record.email_id
        try:
            self.session.delete(record)
            remaining_analysis = self.session.execute(
                select(EmailAnalysisRecord.id)
                .where(EmailAnalysisRecord.email_id == email_id)
                .limit(1)
            ).scalar_one_or_none()
            if remaining_analysis is None:
                email_record = self.session.get(EmailRecord, email_id)
                if email_record is not None:
                    self.session.delete(email_record)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return True
