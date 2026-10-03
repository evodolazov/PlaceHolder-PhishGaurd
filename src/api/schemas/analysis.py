"""Input schema helper for URL analysis requests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisRequestSchema:
    """Simple request DTO for incoming URL analysis requests."""

    url: str
