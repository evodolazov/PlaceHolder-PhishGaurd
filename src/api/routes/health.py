"""Health-check endpoint for the API."""

from __future__ import annotations

from flask import Blueprint

health_bp = Blueprint("health", __name__)


@health_bp.get("/api/v1/health")
def health() -> tuple[dict[str, str], int]:
    return {"status": "healthy", "version": "0.1.0"}, 200
