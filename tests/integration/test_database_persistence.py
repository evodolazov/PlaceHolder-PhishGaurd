from __future__ import annotations

from src.api.app import create_app
from src.database.connection import db
from src.database.models.email import EmailAnalysisRecord, EmailRecord
from src.database.models.url import AnalysisRecord, URLRecord
from src.database.repositories.analysis_repository import AnalysisRepository
from src.database.repositories.email_analysis_repository import EmailAnalysisRepository


def test_url_and_analysis_persistence() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = AnalysisRepository()
        url_record = repo.create_or_get_url(
            raw_url="https://example.com",
            normalized_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            registrable_domain="example.com",
        )
        analysis = repo.create_analysis(
            url_record=url_record,
            classification="low_risk",
            risk_score=0,
            confidence=0.0,
            features={"uses_https": True},
            evidence=[],
        )

        assert URLRecord.query.filter_by(raw_url="https://example.com").count() == 1
        assert AnalysisRecord.query.filter_by(url_id=url_record.id).count() == 1
        assert analysis.url_id == url_record.id

        assert db.session.get(AnalysisRecord, analysis.id) is not None


def test_email_analysis_persistence() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = EmailAnalysisRepository()
        analysis = repo.persist_analysis(
            from_address="alice@example.com",
            reply_to=None,
            subject="Hello",
            body_text="Hi",
            body_html="",
            headers={},
            classification="low_risk",
            risk_score=0,
            confidence=0.05,
            features={"link_count": 0},
            evidence=[],
            urls=[],
        )

        assert EmailRecord.query.filter_by(from_address="alice@example.com").count() == 1
        assert EmailAnalysisRecord.query.filter_by(email_id=analysis.email_id).count() == 1
        assert db.session.get(EmailAnalysisRecord, analysis.id) is not None
