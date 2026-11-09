# PhishGuard

PhishGuard is a modular phishing-detection platform focused on a working URL-analysis foundation. At Milestone 0, the project implements URL validation, normalization, deterministic feature extraction, transparent heuristic scoring, structured evidence generation, and persistent records in a Flask API.

## Current milestone

Milestone 0 — Foundation / URL analysis vertical slice.

## Project purpose

The goal is to establish a clean, extensible architecture for future phishing detection engines without yet implementing ML, external threat intelligence, browser automation, or other future milestone capabilities.

## Technology stack

- Python 3.12+
- Flask
- Flask-SQLAlchemy
- PostgreSQL for normal development usage
- SQLite for isolated automated tests
- pytest
- python-dotenv
- tldextract

## Repository structure

```text
PlaceHolder-PhishGaurd/
├── docs/
│   ├── api.md
│   ├── architecture.md
│   └── development.md
├── scripts/
│   └── seed_database.py
├── src/
│   ├── api/
│   │   ├── app.py
│   │   ├── routes/
│   │   │   ├── analysis.py
│   │   │   └── health.py
│   │   └── schemas/
│   │       └── analysis.py
│   ├── core/
│   │   ├── config.py
│   │   ├── exceptions.py
│   │   └── logging.py
│   ├── database/
│   │   ├── connection.py
│   │   ├── models/
│   │   │   └── url.py
│   │   └── repositories/
│   │       └── analysis_repository.py
│   ├── engines/
│   │   └── url/
│   │       ├── analyzer.py
│   │       ├── features.py
│   │       └── normalizer.py
│   ├── explainability/
│   │   └── reasons.py
│   ├── fusion/
│   │   └── risk_engine.py
│   ├── services/
│   │   └── url_analysis_service.py
│   └── __init__.py
├── tests/
│   ├── integration/
│   │   ├── test_analysis_api.py
│   │   └── test_database_persistence.py
│   └── unit/
│       ├── test_risk_engine.py
│       ├── test_url_features.py
│       └── test_url_normalizer.py
├── .env.example
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
├── requirements.txt
└── scripts/
```

## Installation

```bash
git clone https://github.com/evodolazov/PlaceHolder-PhishGaurd.git
cd PlaceHolder-PhishGaurd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Environment configuration

Create a local `.env` file from the example file:

```bash
copy .env.example .env
```

Set the application database in `.env`:

```env
DATABASE_URL=postgresql://phishguard:phishguard@localhost:5432/phishguard
SECRET_KEY=change-me
```

For test isolation, the application factory can also accept an in-memory SQLite config directly.

## Run the Flask application

```bash
flask --app src.api.app:create_app run
```

or:

```bash
python -m src.api.app
```

## Run tests

```bash
pytest -q
```

## Example API request

```bash
curl -X POST http://127.0.0.1:5000/api/v1/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Example API response

```json
{
  "analysis_id": 1,
  "url": "https://example.com",
  "normalized_url": "https://example.com/",
  "classification": "low_risk",
  "risk_score": 0,
  "confidence": 0.0,
  "features": {
    "uses_https": true,
    "suspicious_keyword_count": 0
  },
  "evidence": [],
  "created_at": "2026-10-02T00:00:00+00:00"
}
```

## URL safety and risk semantics

The URL analysis pipeline treats the submitted URL as an input for analysis, but never persists or returns embedded credentials, passwords, or sensitive query values. A dedicated sanitizer strips userinfo and redacts known secret-bearing query keys before records are stored or exposed in API responses. The normalized URL used for analysis still preserves hostname and structural signals such as userinfo markers, but the public-safe representation stored for history is intentionally different.

Risk score and confidence are intentionally separate concepts in the scoring engine: the risk score is the combined heuristic assessment, while confidence is an explicit measure of the certainty of the heuristic signal rather than a direct transformation of the risk score.

## Current limitations

This Milestone 0 implementation does not:

- perform external network requests
- use machine learning
- query threat-intelligence services
- crawl webpages
- inspect email
- provide Chrome Extension functionality
- perform DNS, RDAP, TLS, or browser automation

Those capabilities are explicitly future milestones.

## Future milestones

- Domain intelligence and DNS analysis
- TLS and certificate inspection
- Threat intelligence service integration
- ML-powered risk scoring
- Email analysis
- Browser extension support
- Security and deployment hardening
