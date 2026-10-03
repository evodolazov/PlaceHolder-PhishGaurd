"""Initialize the local database and seed a small sample dataset."""

from __future__ import annotations

from src.api.app import create_app
from src.database.connection import db
from src.database.models.url import URLRecord


def main() -> None:
    app = create_app()
    with app.app_context():
        db.create_all()
        sample_url = "https://example.com"
        existing = URLRecord.query.filter_by(raw_url=sample_url).first()
        if existing is None:
            record = URLRecord(
                raw_url=sample_url,
                normalized_url="https://example.com/",
                scheme="https",
                hostname="example.com",
                registrable_domain="example.com",
            )
            db.session.add(record)
            db.session.commit()
        print("Database initialized and sample URL seed ensured.")


if __name__ == "__main__":
    main()
