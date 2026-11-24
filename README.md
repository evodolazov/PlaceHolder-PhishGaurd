# PhishGuard

PhishGuard is a Flask-based phishing analysis prototype. It provides deterministic URL and email risk analysis, optional Google Safe Browsing evidence, analysis history, `.eml` upload support, a browser dashboard, downloadable text reports, and a manual-scan Chrome extension foundation.

## Features

- URL validation, normalization, feature extraction, and explainable heuristic risk scoring
- Email sender, Reply-To, authentication-header, suspicious-language, and embedded-link analysis
- Safe `.eml` parsing with attachment content ignored and a 2 MB default upload limit
- Optional Google Safe Browsing lookup (disabled by default)
- Paginated URL and email history with filtering, search, detail retrieval, and deletion
- Privacy-conscious email retention settings and URL credential/query sanitization
- Flask-Migrate/Alembic database migrations
- Manifest V3 Chrome extension for manual active-tab URL scans

Automated scores are not guarantees that a resource is safe.

## Setup

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Configure `DATABASE_URL` and `SECRET_KEY` in `.env`. SQLite can be used for development, for example:

```env
DATABASE_URL=sqlite:///phishguard.db
SECRET_KEY=change-me
SAFE_BROWSING_ENABLED=false
GOOGLE_SAFE_BROWSING_API_KEY=
EMAIL_UPLOAD_MAX_BYTES=2097152
RETAIN_EMAIL_CONTENTS=true
```

## Run

```bat
flask --app src.api.app:create_app run --debug
```

Open `http://127.0.0.1:5000/`.

## Google Safe Browsing privacy

When enabled, submitted URL values are sent to Google's Safe Browsing service for threat matching. This integration is disabled unless both `SAFE_BROWSING_ENABLED=true` and a key are configured. Missing keys, invalid keys, timeouts, and unavailable-service responses fail open; URL/email analysis continues with local heuristics. API keys are environment-only and are never returned or logged.

If a key is exposed in source history or tracked configuration, revoke and replace it. The repository `.env.example` contains placeholders only.

## Database migrations

```bat
flask --app src.api.app:create_app db init
flask --app src.api.app:create_app db migrate -m "describe change"
flask --app src.api.app:create_app db upgrade
```

`db init` is only needed on a new checkout. Migrations preserve existing records; do not run `db downgrade` or recreate the database in production.

## Tests

```bat
.\.venv\Scripts\python.exe -m pytest -q
```

## Chrome extension

Open Chrome's Extensions page, enable Developer mode, choose **Load unpacked**, and select [chrome-extension/](chrome-extension/). The popup can scan only the active tab's URL manually. Configure the backend URL in the popup; the default is `http://127.0.0.1:5000`.

## Documentation

- [API reference](docs/api.md)
- [Development guide](docs/development.md)
- [Architecture](docs/architecture.md)
