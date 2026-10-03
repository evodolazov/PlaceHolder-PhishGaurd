"""Flask application factory for the PhishGuard API."""

from __future__ import annotations

import os

from flask import Flask

from src.api.routes.analysis import analysis_bp
from src.api.routes.health import health_bp
from src.database.connection import db, init_db


def create_app(test_config: dict | None = None) -> Flask:
    """Create a configured Flask application instance."""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key"),
        JSON_SORT_KEYS=False,
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///phishguard.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config:
        app.config.update(test_config)

    init_db(app)
    app.register_blueprint(health_bp)
    app.register_blueprint(analysis_bp)

    with app.app_context():
        db.create_all()

    return app


def main() -> None:
    """Run the Flask application locally."""
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))


if __name__ == "__main__":
    main()
