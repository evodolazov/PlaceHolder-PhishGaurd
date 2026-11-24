"""Flask application factory for the PhishGuard API."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask
from flask import Flask, send_from_directory, request
from pathlib import Path
from flask_migrate import Migrate

from src.api.routes.analysis import analysis_bp
from src.api.routes.health import health_bp
from src.database.connection import db, init_db
from src.database.models import email as _email_models  # noqa: F401
from src.database.models import url as _url_models  # noqa: F401


def create_app(test_config: dict | None = None) -> Flask:
    """Create a configured Flask application instance."""
    load_dotenv()
    app = Flask(__name__)
    FRONTEND_DIR = Path(__file__).resolve().parents[2]/ "frontend"
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key"),
        JSON_SORT_KEYS=False,
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///phishguard.db"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config:
        app.config.update(test_config)

    init_db(app)
    Migrate(app, db)
    app.register_blueprint(health_bp)
    app.register_blueprint(analysis_bp)

    @app.after_request
    def add_extension_cors(response):
        origin = request.headers.get("Origin", "")
        if origin.startswith("chrome-extension://"):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Accept, Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            response.headers["Vary"] = "Origin"
        return response

    @app.route("/")
    def home():
        """Serve the frontend index.html file."""
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/style.css")
    def serve_css():
        return send_from_directory(FRONTEND_DIR, "style.css")

    @app.route("/api.js")
    def serve_api_js():
        return send_from_directory(FRONTEND_DIR, "api.js")

    @app.route("/app.js")
    def serve_app_js():
        return send_from_directory(FRONTEND_DIR, "app.js")

    # Test applications use SQLAlchemy to build isolated in-memory schemas.
    # Production schemas are initialized and upgraded exclusively by Alembic.
    if app.config.get("TESTING"):
        with app.app_context():
            db.create_all()

    return app


def main() -> None:
    """Run the Flask application locally."""
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))


if __name__ == "__main__":
    main()
