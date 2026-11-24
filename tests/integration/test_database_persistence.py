from __future__ import annotations

import os
import sqlite3
from pathlib import Path
import subprocess
import sys

import pytest
from flask_migrate import downgrade, upgrade
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from src.api.app import create_app
from src.database.connection import db
from src.database.models.email import EmailAnalysisRecord, EmailRecord
from src.database.models.url import AnalysisRecord, URLRecord
from src.database.repositories.analysis_repository import AnalysisRepository
from src.database.repositories.email_analysis_repository import EmailAnalysisRepository


def _upgrade_migrations():
    return upgrade(directory=str(Path(__file__).resolve().parents[2] / "migrations"))


def _assert_required_indexes(inspector) -> None:
    indexes = {
        (table_name, tuple(index["column_names"]), bool(index["unique"]))
        for table_name in ("urls", "analyses", "emails", "email_analyses")
        for index in inspector.get_indexes(table_name)
    }
    assert ("urls", ("raw_url",), True) in indexes
    assert ("urls", ("scheme",), False) in indexes
    assert ("urls", ("hostname",), False) in indexes
    assert ("urls", ("registrable_domain",), False) in indexes
    assert ("analyses", ("url_id",), False) in indexes
    assert ("analyses", ("classification",), False) in indexes
    assert ("emails", ("from_address",), False) in indexes
    assert ("email_analyses", ("email_id",), False) in indexes
    assert ("email_analyses", ("classification",), False) in indexes


def test_fresh_database_migration_creates_complete_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "fresh.db"
    app = create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        _upgrade_migrations()
        inspector = inspect(db.engine)
        assert {"urls", "analyses", "emails", "email_analyses"} <= set(inspector.get_table_names())
        _assert_required_indexes(inspector)
        assert inspector.get_pk_constraint("urls")["constrained_columns"] == ["id"]
        assert inspector.get_foreign_keys("analyses")[0]["referred_table"] == "urls"
        assert inspector.get_foreign_keys("email_analyses")[0]["referred_table"] == "emails"
        assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0003_fix_sqlite_confidence"
        confidence_columns = [
            column
            for table_name in ("analyses", "email_analyses")
            for column in inspector.get_columns(table_name)
            if column["name"] == "confidence"
        ]
        assert len(confidence_columns) == 2
        assert all(column["nullable"] for column in confidence_columns)


def test_container_startup_migrates_fresh_database_before_serving(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    dockerfile = (repository_root / "Dockerfile").read_text(encoding="utf-8")
    migration_command = "python -m flask --app src.api.app:create_app db upgrade"
    assert migration_command in dockerfile
    assert dockerfile.index(migration_command) < dockerfile.index("exec python -m src.api.app")

    database_path = tmp_path / "container-startup.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = database_url
    environment["SAFE_BROWSING_ENABLED"] = "false"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "flask",
            "--app",
            "src.api.app:create_app",
            "db",
            "upgrade",
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        assert version == "0003_fix_sqlite_confidence"

    app = create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": database_url,
        "SAFE_BROWSING_ENABLED": False,
    })
    response = app.test_client().post(
        "/api/v1/analyze/url",
        json={"url": "https://container-startup.example/"},
    )
    assert response.status_code == 201
    assert response.get_json()["classification"] == "low_risk"


def test_migration_preserves_existing_complete_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        repo = AnalysisRepository()
        repo.persist_analysis(
            raw_url="https://example.com/",
            normalized_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            registrable_domain="example.com",
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={"uses_https": True},
            evidence=[],
        )
        _upgrade_migrations()
        inspector = inspect(db.engine)
        _assert_required_indexes(inspector)
        assert inspector.get_pk_constraint("urls")["constrained_columns"] == ["id"]
        assert inspector.get_foreign_keys("analyses")[0]["referred_table"] == "urls"
        assert inspector.get_foreign_keys("email_analyses")[0]["referred_table"] == "emails"
        assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0003_fix_sqlite_confidence"
        assert db.session.execute(text("SELECT COUNT(*) FROM urls")).scalar_one() == 1
        assert db.session.execute(text("SELECT COUNT(*) FROM analyses")).scalar_one() == 1


def test_migration_creates_missing_unique_index_when_values_are_unique(tmp_path: Path) -> None:
    database_path = tmp_path / "missing-unique-index.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        repo = AnalysisRepository()
        repo.persist_analysis(
            raw_url="https://example.com/",
            normalized_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            registrable_domain="example.com",
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={},
            evidence=[],
        )
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_urls_raw_url"))

        _upgrade_migrations()

        raw_url_indexes = [
            index
            for index in inspect(db.engine).get_indexes("urls")
            if index["column_names"] == ["raw_url"]
        ]
        assert len(raw_url_indexes) == 1
        assert raw_url_indexes[0]["unique"]
        assert db.session.execute(text("SELECT COUNT(*) FROM urls")).scalar_one() == 1


def test_migration_creates_missing_non_unique_index(tmp_path: Path) -> None:
    database_path = tmp_path / "missing-index.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        repo = AnalysisRepository()
        repo.persist_analysis(
            raw_url="https://example.com/",
            normalized_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            registrable_domain="example.com",
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={},
            evidence=[],
        )
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_urls_hostname"))

        _upgrade_migrations()

        indexes = {index["name"] for index in inspect(db.engine).get_indexes("urls")}
        assert "ix_urls_hostname" in indexes
        assert db.session.execute(text("SELECT COUNT(*) FROM urls")).scalar_one() == 1


def test_migration_rejects_unique_index_where_non_unique_is_required(
    tmp_path: Path,
    capsys,
) -> None:
    database_path = tmp_path / "unexpected-unique-index.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        repo = AnalysisRepository()
        analysis = repo.persist_analysis(
            raw_url="https://example.com/",
            normalized_url="https://example.com/",
            scheme="https",
            hostname="example.com",
            registrable_domain="example.com",
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={},
            evidence=[],
        )
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_analyses_url_id"))
            connection.execute(
                text("CREATE UNIQUE INDEX legacy_unique_analysis_url ON analyses(url_id)")
            )

        with pytest.raises(SystemExit):
            _upgrade_migrations()

        error_output = capsys.readouterr().err
        assert "expected a non-unique index" in error_output
        assert "The migration will not remove it" in error_output
        assert db.session.execute(text("SELECT COUNT(*) FROM urls")).scalar_one() == 1
        assert db.session.execute(text("SELECT COUNT(*) FROM analyses")).scalar_one() == 1
        assert db.session.get(AnalysisRecord, analysis.id) is not None
        indexes = {
            index["name"]: index
            for index in inspect(db.engine).get_indexes("analyses")
        }
        assert indexes["legacy_unique_analysis_url"]["unique"]
        assert "ix_analyses_url_id" not in indexes


def test_migration_rejects_duplicate_values_before_creating_unique_index(
    tmp_path: Path,
    capsys,
) -> None:
    database_path = tmp_path / "duplicate-urls.db"
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        repo = AnalysisRepository()
        repo.persist_analysis(
            raw_url="https://duplicate.example/",
            normalized_url="https://duplicate.example/",
            scheme="https",
            hostname="duplicate.example",
            registrable_domain="duplicate.example",
            classification="low_risk",
            risk_score=0,
            confidence=None,
            features={},
            evidence=[],
        )
        with db.engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_urls_raw_url"))
            connection.execute(
                text(
                    "INSERT INTO urls "
                    "(raw_url, normalized_url, scheme, hostname, registrable_domain, created_at) "
                    "VALUES (:raw_url, :normalized_url, :scheme, :hostname, :domain, :created_at)"
                ),
                {
                    "raw_url": "https://duplicate.example/",
                    "normalized_url": "https://duplicate.example/",
                    "scheme": "https",
                    "hostname": "duplicate.example",
                    "domain": "duplicate.example",
                    "created_at": "2026-11-24 00:00:00",
                },
            )

        with pytest.raises(SystemExit):
            _upgrade_migrations()
        error_output = capsys.readouterr().err
        assert "duplicate existing values" in error_output
        assert "Resolve duplicates without deleting user data" in error_output
        assert db.session.execute(text("SELECT COUNT(*) FROM urls")).scalar_one() == 2


def test_migration_rejects_partial_legacy_schema(tmp_path: Path, capsys) -> None:
    database_path = tmp_path / "partial.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY)")

    app = create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with app.app_context():
        with pytest.raises(SystemExit):
            _upgrade_migrations()
    error_output = capsys.readouterr().err
    assert "Cannot safely upgrade legacy table 'urls'" in error_output
    assert "missing required columns" in error_output


@pytest.mark.parametrize("table_name", ["analyses", "email_analyses"])
def test_confidence_downgrade_rejects_null_without_losing_data(
    tmp_path: Path,
    table_name: str,
) -> None:
    database_path = tmp_path / f"nullable-confidence-{table_name}.db"
    app = create_app({
        "TESTING": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })
    migrations_directory = str(Path(__file__).resolve().parents[2] / "migrations")

    with app.app_context():
        upgrade(directory=migrations_directory, revision="0002_nullable_confidence")
        if table_name == "analyses":
            record = AnalysisRepository().persist_analysis(
                raw_url="https://example.com/",
                normalized_url="https://example.com/",
                scheme="https",
                hostname="example.com",
                registrable_domain="example.com",
                classification="low_risk",
                risk_score=0,
                confidence=None,
                features={},
                evidence=[],
            )
            record_id = record.id
        else:
            record = EmailAnalysisRepository().persist_analysis(
                from_address="alice@example.com",
                reply_to=None,
                subject="Hello",
                body_text="Hi",
                body_html="",
                headers={},
                classification="low_risk",
                risk_score=0,
                confidence=None,
                features={},
                evidence=[],
                urls=[],
            )
            record_id = record.id
        db.session.commit()

        with pytest.raises(IntegrityError, match="NOT NULL constraint failed"):
            downgrade(directory=migrations_directory, revision="0001_initial")

        model = AnalysisRecord if table_name == "analyses" else EmailAnalysisRecord
        persisted = db.session.get(model, record_id)
        assert persisted is not None
        assert persisted.confidence is None
        assert db.session.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "0002_nullable_confidence"
        )
        for migrated_table in ("analyses", "email_analyses"):
            confidence_column = next(
                column
                for column in inspect(db.engine).get_columns(migrated_table)
                if column["name"] == "confidence"
            )
            assert confidence_column["nullable"]


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
