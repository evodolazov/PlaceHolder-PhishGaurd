"""Database model package."""

from src.database.models.email import EmailAnalysisRecord, EmailRecord
from src.database.models.url import AnalysisRecord, URLRecord

__all__ = [
    "AnalysisRecord",
    "EmailAnalysisRecord",
    "EmailRecord",
    "URLRecord",
]
