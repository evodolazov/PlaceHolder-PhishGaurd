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

## Current milestone

The active milestone is the ML/TLS hardening and integration pass.

This branch keeps the deterministic URL/email scoring model as the primary decision engine while layering on optional ML and TLS inspection, safer defaults, sanitization controls, and integration coverage. The optional ML/TLS features are configured explicitly and do not replace the existing deterministic scoring logic.

Current limitations are intentional and documented: the branch is not a complete production-grade real-dataset ML pipeline or a fully enterprise-scale TLS inspection platform. The project still treats those areas as active hardening and validation work.
