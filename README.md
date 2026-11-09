# PhishGuard

PhishGuard is a modular phishing-detection platform focused on URL and email risk analysis, with optional ML and TLS inspection layers layered on top of the existing deterministic scoring engine.

## Project purpose

The project combines:

- URL validation, normalization, feature extraction, and risk scoring
- URL and email analysis persistence
- privacy-preserving URL sanitization
- optional ML-based probability scoring
- optional HTTPS/TLS inspection with SSRF-focused safeguards
- deterministic fallback behavior when optional engines are unavailable

The core architecture remains deterministic and explainable while allowing optional ML/TLS capabilities to augment analysis without replacing the original risk model.

## Current status

The repository currently includes:

- deterministic URL analysis and risk scoring
- email analysis with embedded URL assessment
- sanitization of credentials and sensitive query values
- ML predictor scaffolding and model compatibility checks
- HTTPS TLS inspection with safe-network gating
- API and database persistence for ML/TLS metadata
- regression tests covering URL/email sanitization and the optional ML/TLS paths

## Current milestone

The active milestone is the ML/TLS hardening and integration pass.

This branch preserves the core deterministic URL/email scoring architecture while adding optional ML and TLS capabilities, strict sanitization, safe fallback behavior, and regression coverage for privacy and network-safety concerns.

Important caveat: the ML/TLS layers are intentionally additive and configurable; they are not presented as a fully production-grade phishing dataset + model pipeline or a comprehensive enterprise TLS inspection stack. Remaining work is documented in the project guidance and should be treated as active follow-up items rather than completed production milestones.

## Technology stack

- Python 3.12+
- Flask
- Flask-SQLAlchemy
- PostgreSQL for normal development usage
- SQLite for isolated automated tests
- pytest
- python-dotenv
- tldextract
- scikit-learn (optional ML model training/inference)

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
│   │   │   ├── email.py
│   │   │   └── url.py
│   │   └── repositories/
│   │       ├── analysis_repository.py
│   │       └── email_analysis_repository.py
│   ├── engines/
│   │   ├── email/
│   │   │   ├── analyzer.py
│   │   │   ├── features.py
│   │   │   ├── parser.py
│   │   │   └── rules.py
│   │   ├── ml/
│   │   │   ├── __init__.py
│   │   │   ├── feature_schema.py
│   │   │   ├── model.py
│   │   │   ├── predictor.py
│   │   │   └── training.py
│   │   ├── tls/
│   │   │   ├── __init__.py
│   │   │   └── inspector.py
│   │   └── url/
│   │       ├── analyzer.py
│   │       ├── features.py
│   │       ├── normalizer.py
│   │       ├── rules.py
│   │       └── sanitizer.py
│   ├── explainability/
│   │   └── reasons.py
│   ├── fusion/
│   │   ├── email_risk_engine.py
│   │   └── risk_engine.py
│   ├── services/
│   │   ├── email_analysis_service.py
│   │   └── url_analysis_service.py
│   └── __init__.py
├── tests/
│   ├── integration/
│   │   ├── test_analysis_api.py
│   │   ├── test_database_persistence.py
│   │   └── test_email_api.py
│   └── unit/
│       ├── test_email_parser.py
│       ├── test_email_risk_engine.py
│       ├── test_email_rules.py
│       ├── test_ml_tls.py
│       ├── test_risk_engine.py
│       ├── test_url_features.py
│       ├── test_url_normalizer.py
│       └── test_url_rules.py
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

Example configuration:

```env
DATABASE_URL=postgresql://localhost:5432/phishguard
SECRET_KEY=change-me
FLASK_APP=src.api.app:create_app

# Optional ML settings
ML_ENABLED=true
ML_MODEL_PATH=artifacts/ml/url_model.pkl
ML_MODEL_VERSION=url-logreg-v1

# Optional TLS settings
TLS_ENABLED=true
TLS_TIMEOUT=5.0
TLS_ALLOWED_PORTS=443
EMAIL_URL_TLS_INSPECTION=false
```

Notes:

- `ML_ENABLED` controls whether the model predictor is consulted.
- `ML_MODEL_PATH` must be set explicitly for a real model artifact; the app does not silently load repository-local artifacts.
- `TLS_ENABLED` enables HTTPS inspection for standalone URL analysis.
- `EMAIL_URL_TLS_INSPECTION=false` keeps embedded email URLs isolated from network contact by default.
- For test isolation, the Flask app also accepts an in-memory SQLite config directly.

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
.\.venv\Scripts\python.exe -m pytest -q
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
  "confidence": null,
  "ml_probability": null,
  "ml_prediction": null,
  "ml_model_status": "unavailable",
  "tls_status": "not_applicable",
  "features": {
    "uses_https": true,
    "suspicious_keyword_count": 0
  },
  "evidence": [],
  "created_at": "2026-10-02T00:00:00+00:00"
}
```

## URL safety and privacy

The URL analysis pipeline sanitizes sensitive userinfo and query values before persisting or returning them in API responses.

Behavior:

- embedded username/password credentials are stripped
- sensitive query keys such as `token`, `secret`, `password`, `api_key`, and similar values are redacted
- harmless query parameters remain intact
- analysis features and evidence still preserve enough structure to explain the decision, without leaking original secrets

This is enforced in the sanitization layer and in the API/database retrieval paths.

## Deterministic risk scoring

URL and email scoring remain based on the existing deterministic rules engine:

- transparent rule evaluation
- explainable evidence objects
- risk score and confidence remain separate concepts
- confidence stays `null` when no statistically defensible confidence measure exists
- heuristic strength remains descriptive and distinct from statistical confidence

## ML scoring

ML support is optional and intentionally safe-by-default:

- the predictor does not silently load repository-local model artifacts
- missing or incompatible models are treated as `unavailable`
- deterministic analysis continues to work when ML is disabled or unavailable
- ML probability is reported separately from the final heuristic risk score

When configured correctly, ML probability and prediction are persisted and included in the analysis payload.

## TLS inspection

TLS inspection is available for standalone HTTPS URL analysis and is built with SSRF-aware safeguards:

- HTTPS-only inspection path
- certificate verification through the standard verified SSL context
- hostname verification and SNI
- DNS validation before connection
- rejection of prohibited private/loopback/reserved addresses
- exact validated-IP connection behavior
- no redirect or webpage download behavior
- no credentials, cookies, or auth headers
- structured failure states instead of crashes

TLS inspection is not automatically triggered for embedded URLs inside email bodies. The default email-analysis behavior is network-isolated.

## Email analysis behavior

The email pipeline keeps the existing email-specific checks and evidence collection while evaluating embedded URLs safely:

- sender checks
- authentication-result analysis
- urgency detection
- credential-request detection
- visible-link mismatch detection
- embedded URL evidence and deterministic URL results

Embedded email URLs are analyzed for feature extraction and scoring, but they do not automatically trigger TLS inspection unless explicitly requested in a standalone URL-analysis flow.

## Database and persistence

The project stores both canonical URL records and analysis records. URL fields include sanitized values, while analysis records preserve ML/TLS metadata where present.

Important notes:

- API responses and stored URL records do not expose raw credentials or sensitive query values
- historical records remain consistent with the sanitization policy
- SQLite test runs remain supported
- PostgreSQL remains the normal development database, but the codebase does not assume `create_all()` will migrate an existing production database schema automatically

## Current limitations

The current implementation intentionally keeps the following constraints:

- ML remains optional and requires an explicitly configured model artifact
- real dataset integration, evaluation metrics, and production model lifecycle are still separate concerns from the deterministic app core
- TLS inspection is designed for HTTPS verification and SSRF-safe inspection, not as proof that a site is legitimate
- the app remains explainable and deterministic-first rather than relying on opaque model decisions alone

## Future work

Planned improvements include:

- real phishing dataset ingestion and documentation
- proper train/test splitting and domain-aware leakage controls
- model evaluation metrics and artifact versioning
- risk-fusion strategy for ML contribution to final scoring
- expanded TLS validation and policy hardening
- more complete documentation of dataset license, training configuration, and model lifecycle

## License

This project is distributed under the repository license included in the project root.
