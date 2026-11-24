from __future__ import annotations

import pytest

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
            confidence=None,
            features={"uses_https": True},
            evidence=[],
        )

        assert URLRecord.query.filter_by(raw_url="https://example.com").count() == 1
        assert AnalysisRecord.query.filter_by(url_id=url_record.id).count() == 1
        assert analysis.url_id == url_record.id
        assert analysis.confidence is None

        assert db.session.get(AnalysisRecord, analysis.id) is not None


def test_sensitive_url_is_sanitized_in_database() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = AnalysisRepository()
        raw_url = "https://user:secret@trusted.example/login?token=abc123&safe=1&api_key=xyz"
        payload = {
            "url": raw_url,
            "normalized_url": "https://trusted.example/login?token=%5BREDACTED%5D&safe=1&api_key=%5BREDACTED%5D",
            "scheme": "https",
            "hostname": "trusted.example",
            "registrable_domain": "trusted.example",
            "classification": "moderate_risk",
            "risk_score": 30,
            "confidence": None,
            "features": {"at_symbol_count": 1, "uses_https": True, "suspicious_keyword_count": 1},
            "evidence": [{"source": "url_rules", "indicator": "url.at_symbol", "value": 1, "description": "Contains userinfo"}],
        }

        analysis = repo.persist_analysis(
            raw_url=raw_url,
            normalized_url=payload["normalized_url"],
            scheme=payload["scheme"],
            hostname=payload["hostname"],
            registrable_domain=payload["registrable_domain"],
            classification=payload["classification"],
            risk_score=payload["risk_score"],
            confidence=payload["confidence"],
            features=payload["features"],
            evidence=payload["evidence"],
        )

        stored_url = db.session.get(URLRecord, analysis.url_id)
        assert stored_url is not None
        assert stored_url.raw_url == "https://trusted.example/login?token=%5BREDACTED%5D&safe=1&api_key=%5BREDACTED%5D"
        assert "user:secret" not in stored_url.raw_url
        assert "abc123" not in stored_url.raw_url
        assert "xyz" not in stored_url.raw_url
        assert "safe=1" in stored_url.raw_url
        assert "token=%5BREDACTED%5D" in stored_url.normalized_url
        assert "api_key=%5BREDACTED%5D" in stored_url.normalized_url
        assert stored_url.hostname == "trusted.example"
        assert analysis.features["at_symbol_count"] == 1
        assert any(item["indicator"] == "url.at_symbol" for item in analysis.evidence)
        assert "user:secret" not in str(analysis.evidence)
        assert "abc123" not in str(analysis.evidence)


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
            confidence=None,
            features={"link_count": 0},
            evidence=[],
            urls=[],
        )

        assert EmailRecord.query.filter_by(from_address="alice@example.com").count() == 1
        assert EmailAnalysisRecord.query.filter_by(email_id=analysis.email_id).count() == 1
        assert analysis.confidence is None
        assert db.session.get(EmailAnalysisRecord, analysis.id) is not None


def _persist_email_analysis(repo: EmailAnalysisRepository):
    return repo.persist_analysis(
        from_address="alice@example.com",
        reply_to=None,
        subject="Hello",
        body_text="Hi",
        body_html="",
        headers={},
        classification="low_risk",
        risk_score=0,
        confidence=None,
        features={"link_count": 0},
        evidence=[],
        urls=[],
    )


def test_deleting_email_analysis_removes_unshared_email_record() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = EmailAnalysisRepository()
        analysis = _persist_email_analysis(repo)

        assert repo.delete_analysis(analysis.id) is True
        assert db.session.get(EmailAnalysisRecord, analysis.id) is None
        assert db.session.get(EmailRecord, analysis.email_id) is None


def test_deleting_email_analysis_preserves_unrelated_email_record() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = EmailAnalysisRepository()
        first = _persist_email_analysis(repo)
        second = repo.persist_analysis(
            from_address="bob@example.com",
            reply_to=None,
            subject="Other",
            body_text="Other message",
            body_html="",
            headers={},
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={},
            evidence=[],
            urls=[],
        )

        assert repo.delete_analysis(first.id) is True
        assert db.session.get(EmailRecord, first.email_id) is None
        assert db.session.get(EmailAnalysisRecord, second.id) is not None
        assert db.session.get(EmailRecord, second.email_id) is not None


def test_deleting_one_analysis_preserves_email_shared_by_another_analysis() -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        repo = EmailAnalysisRepository()
        first = _persist_email_analysis(repo)
        shared = EmailAnalysisRecord(
            email_id=first.email_id,
            classification="moderate_risk",
            risk_score=30,
            confidence=None,
            features={},
            evidence=[],
            urls=[],
        )
        db.session.add(shared)
        db.session.commit()

        assert repo.delete_analysis(first.id) is True
        assert db.session.get(EmailRecord, first.email_id) is not None
        assert db.session.get(EmailAnalysisRecord, shared.id) is not None


def test_failed_email_analysis_delete_rolls_back_analysis_and_email(monkeypatch) -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        analysis = _persist_email_analysis(EmailAnalysisRepository())
        session = db.session()
        repo = EmailAnalysisRepository(session=session)
        original_delete = session.delete

        def fail_email_delete(instance):
            if isinstance(instance, EmailRecord):
                raise RuntimeError("simulated email-row deletion failure")
            original_delete(instance)

        with monkeypatch.context() as patch:
            patch.setattr(session, "delete", fail_email_delete)
            with pytest.raises(RuntimeError, match="simulated email-row deletion failure"):
                repo.delete_analysis(analysis.id)

        assert db.session.get(EmailAnalysisRecord, analysis.id) is not None
        assert db.session.get(EmailRecord, analysis.email_id) is not None


def test_email_deletion_removes_record_when_content_retention_is_disabled(monkeypatch) -> None:
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})

    with app.app_context():
        monkeypatch.setenv("RETAIN_EMAIL_CONTENTS", "false")
        repo = EmailAnalysisRepository()
        analysis = _persist_email_analysis(repo)
        email_record = db.session.get(EmailRecord, analysis.email_id)
        assert email_record is not None
        assert email_record.body_text == ""

        assert repo.delete_analysis(analysis.id) is True
        assert db.session.get(EmailRecord, analysis.email_id) is None
