# API Reference

All successful responses use JSON. Validation errors use HTTP 400 and `{ "error", "message" }`.

## Health

- `GET /api/v1/health`

## URL analysis

- `POST /api/v1/analyze/url` with `{ "url": "https://example.com" }`
- `GET /api/v1/analysis/<id>`
- `DELETE /api/v1/analysis/<id>`
- `GET /api/v1/analysis/<id>/report`

The URL response includes `analysis_id`, `url`, `normalized_url`, `classification`, `risk_score`, `confidence`, `features`, `evidence`, `threat_intelligence`, and `created_at`. `confidence` is `null` because the current heuristic has no calibrated statistical confidence basis.

## Email analysis

- `POST /api/v1/analyze/email` with JSON fields `from`, `reply_to`, `subject`, `body_text`, `body_html`, and optional `headers`
- `POST /api/v1/analyze/email/upload` as multipart form field `file` containing one `.eml`
- `GET /api/v1/email-analysis/<id>`
- `DELETE /api/v1/email-analysis/<id>`
- `GET /api/v1/email-analysis/<id>/report`

Email responses include sender and Reply-To values, risk classification/score, features, evidence, embedded URL findings, authentication findings where available, and threat-intelligence status. Missing authentication evidence does not mean malicious activity.

## History

- `GET /api/v1/analyses/url?page=1&page_size=10&risk_level=&search=`
- `GET /api/v1/analyses/email?page=1&page_size=10&risk_level=&search=`

`page` starts at 1. `page_size` must be 1-100. Risk levels are `low_risk`, `moderate_risk`, `high_risk`, or `critical_risk`. History is newest-first and excludes original email bodies and sensitive URL credentials.

## Safe Browsing

Set `SAFE_BROWSING_ENABLED=true` and provide `GOOGLE_SAFE_BROWSING_API_KEY` to enable external matching. The service reports `disabled`, `unavailable`, or `enabled` status without exposing the key. External lookup failures do not fail the local URL/email analysis.
