"""Input schema helpers for analysis requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AnalysisRequestSchema:
    """Simple request DTO for incoming URL analysis requests."""

    url: str


@dataclass(frozen=True)
class EmailAnalysisRequestSchema:
    """Simple request DTO for incoming email analysis requests."""

    from_address: str = ""
    reply_to: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: dict[str, Any] | None = None
