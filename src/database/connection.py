"""Database initialization for the Flask application."""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def init_db(app) -> None:
    """Initialize SQLAlchemy on the given Flask application."""
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///phishguard.db")
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
