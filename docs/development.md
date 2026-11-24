# Development Guide

## Prerequisites

- Python 3.12+
- PostgreSQL for local development
- Git

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Environment configuration

Copy `.env.example` to `.env` and update the database settings if needed.

```env
DATABASE_URL=postgresql://phishguard:phishguard@localhost:5432/phishguard
SECRET_KEY=change-me
SAFE_BROWSING_ENABLED=false
GOOGLE_SAFE_BROWSING_API_KEY=
```

The project also supports SQLite test configuration when using isolated test runs.

Google Safe Browsing is optional. Set `SAFE_BROWSING_ENABLED=true` and add an API key to check submitted URLs (and links inside emails) against Google's lists. If the key is missing or the request fails, analysis still returns the local heuristic score.

## Run the application

```bash
flask --app src.api.app:create_app run --debug
```

or:

```bash
python -m src.api.app
```

## Run tests

```bash
pytest -q
```

## Seed the DB (optional)

```bash
python scripts/seed_database.py
```

## Milestone 0 limitations

This milestone does not crawl webpages, use machine learning, inspect mailboxes, or provide browser extension functionality. Google Safe Browsing is an optional lookup when enabled.
