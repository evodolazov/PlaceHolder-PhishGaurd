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
```

The project also supports SQLite test configuration when using isolated test runs.

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

This milestone intentionally does not fetch remote URLs, call third-party threat-intelligence APIs, perform ML, inspect email, or provide browser extension functionality.
