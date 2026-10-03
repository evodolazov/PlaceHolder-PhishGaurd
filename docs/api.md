# API Reference

## GET /api/v1/health

Returns the application health status and version.

Example response:

```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

## POST /api/v1/analyze/url

Analyzes a supplied HTTP/HTTPS URL.

Request:

```json
{
  "url": "https://example.com"
}
```

Successful response:

```json
{
  "analysis_id": 1,
  "url": "https://example.com",
  "normalized_url": "https://example.com/",
  "classification": "low_risk",
  "risk_score": 0,
  "confidence": 0.0,
  "features": {},
  "evidence": [],
  "created_at": "2026-10-02T00:00:00+00:00"
}
```

Invalid requests return HTTP 400 with an error object such as:

```json
{
  "error": "invalid_url",
  "message": "A valid HTTP or HTTPS URL is required."
}
```

## GET /api/v1/analysis/<analysis_id>

Returns the stored analysis record for the supplied ID.

If not found, the endpoint responds with HTTP 404 and a JSON error object.
