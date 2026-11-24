# Development Guide

## Prerequisites

- Python 3.12+
- PostgreSQL for normal development or SQLite for lightweight local/test use
- Git
- Chrome for extension demonstration

## Setup

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

## Environment

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///phishguard.db` |
| `SECRET_KEY` | Flask secret | development fallback |
| `SAFE_BROWSING_ENABLED` | Enable external Google lookup | `false` |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google API key | empty |
| `EMAIL_UPLOAD_MAX_BYTES` | Maximum `.eml` upload size | `2097152` |
| `RETAIN_EMAIL_CONTENTS` | Store original email bodies/headers | `true` |
| `PORT` | Flask listen port | `5000` |

The backend loads credentials exclusively from environment variables. A Safe Browsing lookup transmits the submitted URL to Google.

## Database

Fresh development setup:

```bat
flask --app src.api.app:create_app db upgrade
```

Create a migration after model changes:

```bat
flask --app src.api.app:create_app db migrate -m "describe change"
flask --app src.api.app:create_app db upgrade
```

Test applications create isolated schemas with `db.create_all()` when `TESTING=True`. Production startup does not create tables automatically: run the Alembic upgrade before starting the application. The Docker entrypoint runs `flask db upgrade` before serving requests.

## Run and tests

```bat
flask --app src.api.app:create_app run --debug
.\.venv\Scripts\python.exe -m pytest -q
```

## Privacy and email uploads

Set `RETAIN_EMAIL_CONTENTS=false` to avoid storing submitted bodies and headers while preserving analysis results and explanations. URL userinfo and secret-bearing query values are sanitized before persistence and API/history output.

`.eml` uploads are size-limited and parsed with Python's standard email library. Attachments are never extracted or executed, and HTML remote resources are not fetched. Uploaded content is not written to application logs.
