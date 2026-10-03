"""Core analysis endpoints for detecting phishing risk in URLs."""

from __future__ import annotations

from flask import Blueprint, request

from src.services.url_analysis_service import URLAnalysisService

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.post("/api/v1/analyze/url")
def analyze_url_endpoint() -> tuple[dict[str, object], int]:
    payload = request.get_json(silent=True) or {}
    if not payload or "url" not in payload:
        return {"error": "invalid_url", "message": "A valid HTTP or HTTPS URL is required."}, 400

    raw_url = payload["url"]
    if not isinstance(raw_url, str) or not raw_url.strip():
        return {"error": "invalid_url", "message": "A valid HTTP or HTTPS URL is required."}, 400

    try:
        result = URLAnalysisService().analyze(raw_url)
    except ValueError as exc:
        return {"error": "invalid_url", "message": str(exc)}, 400

    return result, 201


@analysis_bp.get("/api/v1/analysis/<int:analysis_id>")
def get_analysis_endpoint(analysis_id: int) -> tuple[dict[str, object], int]:
    result = URLAnalysisService().get_analysis(analysis_id)
    if result is None:
        return {"error": "not_found", "message": "Analysis record not found."}, 404
    return result, 200
