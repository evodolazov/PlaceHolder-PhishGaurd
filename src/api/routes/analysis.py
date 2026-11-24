"""Core analysis endpoints for detecting phishing risk in URLs and emails."""

from __future__ import annotations

from flask import Blueprint, request, Response
from email import policy
from email.parser import BytesParser
import os
from math import ceil

from src.core.exceptions import InvalidEmail
from src.services.email_analysis_service import EmailAnalysisService
from src.services.url_analysis_service import URLAnalysisService

analysis_bp = Blueprint("analysis", __name__)
MAX_UPLOAD_BYTES = int(os.getenv("EMAIL_UPLOAD_MAX_BYTES", str(2 * 1024 * 1024)))


def _message_body_parts(part, alternative_html_parts=None):
    if part.get_content_disposition() == "attachment" or part.get_filename() is not None:
        return
    content_type = part.get_content_type()
    if content_type == "message/rfc822":
        return
    if not part.is_multipart():
        yield part
        return

    children = list(part.iter_parts())
    if content_type == "multipart/alternative":
        html_fallback = None
        plain_fallback = None
        html_alternatives = []
        for child in children:
            representation = list(_message_body_parts(child, alternative_html_parts))
            content_types = {item.get_content_type() for item in representation}
            if "text/plain" in content_types:
                if plain_fallback is None:
                    plain_fallback = representation
            if html_fallback is None and "text/html" in content_types:
                html_fallback = representation
            if "text/html" in content_types:
                html_alternatives.extend(
                    item for item in representation if item.get_content_type() == "text/html"
                )
        if plain_fallback is not None:
            if alternative_html_parts is not None:
                alternative_html_parts.extend(html_alternatives)
            plain_part_ids = {id(item) for item in plain_fallback}
            yield from plain_fallback
            for item in html_alternatives:
                if id(item) not in plain_part_ids:
                    yield item
            return
        if html_fallback is not None:
            yield from html_fallback
        return

    if content_type == "multipart/related":
        start = part.get_param("start")
        if start is None:
            root = children[0] if children else None
        else:
            root_content_id = str(start).strip().strip("<>")
            root = next(
                (
                    child
                    for child in children
                    if str(child.get("Content-ID") or "").strip().strip("<>")
                    == root_content_id
                ),
                None,
            )
        if root is not None:
            yield from _message_body_parts(root, alternative_html_parts)
        return

    for child in children:
        yield from _message_body_parts(child, alternative_html_parts)


def _pagination():
    try:
        page = int(request.args.get("page", "1"))
        page_size = int(request.args.get("page_size", "10"))
    except (TypeError, ValueError):
        return None
    if page < 1 or page_size < 1 or page_size > 100:
        return None
    risk_level = request.args.get("risk_level", "").strip()
    if risk_level and risk_level not in {"low_risk", "moderate_risk", "high_risk", "critical_risk"}:
        return None
    return page, page_size, risk_level


@analysis_bp.post("/api/v1/analyze/url")
def analyze_url_endpoint() -> tuple[dict[str, object], int]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or "url" not in payload:
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


@analysis_bp.post("/api/v1/analyze/email")
def analyze_email_endpoint() -> tuple[dict[str, object], int]:
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return {"error": "invalid_email", "message": "A JSON email object is required."}, 400

    try:
        result = EmailAnalysisService().analyze(payload)
    except (InvalidEmail, ValueError) as exc:
        return {"error": "invalid_email", "message": str(exc)}, 400

    return result, 201


@analysis_bp.get("/api/v1/email-analysis/<int:analysis_id>")
def get_email_analysis_endpoint(analysis_id: int) -> tuple[dict[str, object], int]:
    result = EmailAnalysisService().get_analysis(analysis_id)
    if result is None:
        return {"error": "not_found", "message": "Email analysis record not found."}, 404
    return result, 200


@analysis_bp.post("/api/v1/analyze/email/upload")
def upload_email_endpoint() -> tuple[dict[str, object], int]:
    uploaded = request.files.get("file")
    if uploaded is None:
        return {"error": "invalid_email", "message": "An .eml file is required."}, 400
    if not uploaded.filename.lower().endswith(".eml"):
        return {"error": "invalid_email", "message": "Only .eml files are accepted."}, 400
    raw = uploaded.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        return {"error": "file_too_large", "message": "The .eml file exceeds the configured upload limit."}, 413
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return {"error": "invalid_email", "message": "The uploaded file could not be parsed as email."}, 400

    def text_part(part) -> str:
        if part.is_multipart():
            return ""
        if part.get_content_type() != "text/plain":
            return ""
        try:
            return str(part.get_content())
        except Exception:
            return ""

    def html_part(part) -> str:
        if part.is_multipart():
            return ""
        if part.get_content_type() != "text/html":
            return ""
        try:
            return str(part.get_content())
        except Exception:
            return ""

    alternative_html_parts = []
    body_parts = list(_message_body_parts(message, alternative_html_parts))
    alternative_html_part_ids = {id(part) for part in alternative_html_parts}
    plain_parts: list[str] = []
    html_parts: list[str] = []
    feature_html_parts: list[str] = []
    for part in body_parts:
        plain_parts.append(text_part(part))
        html_content = html_part(part)
        html_parts.append(html_content)
        if id(part) not in alternative_html_part_ids:
            feature_html_parts.append(html_content)
    headers = {str(key): str(value) for key, value in message.items()}
    payload = {
        "from": str(message.get("From") or ""),
        "reply_to": str(message.get("Reply-To") or ""),
        "subject": str(message.get("Subject") or ""),
        "body_text": "\n".join(item for item in plain_parts if item),
        "body_html": "\n".join(item for item in html_parts if item),
        "headers": headers,
    }
    try:
        result = EmailAnalysisService().analyze(
            payload,
            feature_body_html=(
                "\n".join(item for item in feature_html_parts if item)
                if alternative_html_part_ids
                else None
            ),
        )
    except (InvalidEmail, ValueError) as exc:
        return {"error": "invalid_email", "message": str(exc)}, 400
    return result, 201


@analysis_bp.get("/api/v1/analyses/url")
def list_url_analyses_endpoint() -> tuple[dict[str, object], int]:
    parsed = _pagination()
    if parsed is None:
        return {"error": "invalid_parameters", "message": "Invalid pagination or risk-level parameters."}, 400
    page, page_size, risk_level = parsed
    return URLAnalysisService().list_analyses(page, page_size, risk_level, request.args.get("search", "").strip()), 200


@analysis_bp.get("/api/v1/analyses/email")
def list_email_analyses_endpoint() -> tuple[dict[str, object], int]:
    parsed = _pagination()
    if parsed is None:
        return {"error": "invalid_parameters", "message": "Invalid pagination or risk-level parameters."}, 400
    page, page_size, risk_level = parsed
    return EmailAnalysisService().list_analyses(page, page_size, risk_level, request.args.get("search", "").strip()), 200


@analysis_bp.delete("/api/v1/analysis/<int:analysis_id>")
def delete_url_analysis_endpoint(analysis_id: int) -> tuple[dict[str, object], int]:
    if not URLAnalysisService().delete_analysis(analysis_id):
        return {"error": "not_found", "message": "Analysis record not found."}, 404
    return {"deleted": True, "analysis_id": analysis_id}, 200


@analysis_bp.delete("/api/v1/email-analysis/<int:analysis_id>")
def delete_email_analysis_endpoint(analysis_id: int) -> tuple[dict[str, object], int]:
    if not EmailAnalysisService().delete_analysis(analysis_id):
        return {"error": "not_found", "message": "Email analysis record not found."}, 404
    return {"deleted": True, "analysis_id": analysis_id}, 200


def _plain_report(data: dict[str, object], kind: str) -> str:
    evidence = data.get("evidence") or []
    reasons = "\n".join(
        f"- {item.get('description') or item.get('indicator') or 'Detection evidence'}"
        for item in evidence
        if isinstance(item, dict)
    ) or "- No detection evidence triggered."
    subject = data.get("subject") or data.get("url") or "Not provided"
    intelligence = data.get("threat_intelligence") or {}
    return (
        "PhishGuard Analysis Report\n"
        "==========================\n"
        f"Analysis type: {kind}\n"
        f"Analysis identifier: {data.get('analysis_id')}\n"
        f"Date and time: {data.get('created_at')}\n"
        f"Analyzed item: {subject}\n"
        f"Risk classification: {data.get('classification')}\n"
        f"Risk score: {data.get('risk_score')} / 100\n"
        "Detection reasons:\n"
        f"{reasons}\n"
        f"Threat intelligence: {intelligence.get('message') or 'Status unavailable'}\n"
        "\nAutomated analysis is not a guarantee that a resource is safe.\n"
    )


@analysis_bp.get("/api/v1/analysis/<int:analysis_id>/report")
def url_report_endpoint(analysis_id: int):
    result = URLAnalysisService().get_analysis(analysis_id)
    if result is None:
        return {"error": "not_found", "message": "Analysis record not found."}, 404
    return Response(_plain_report(result, "URL"), mimetype="text/plain")


@analysis_bp.get("/api/v1/email-analysis/<int:analysis_id>/report")
def email_report_endpoint(analysis_id: int):
    result = EmailAnalysisService().get_analysis(analysis_id)
    if result is None:
        return {"error": "not_found", "message": "Email analysis record not found."}, 404
    return Response(_plain_report(result, "email"), mimetype="text/plain")
