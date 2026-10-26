"""Email analysis engine package."""

from src.engines.email.analyzer import analyze_email
from src.engines.email.features import EmailFeatures, extract_features
from src.engines.email.parser import ParsedEmail, parse_email

__all__ = [
    "EmailFeatures",
    "ParsedEmail",
    "analyze_email",
    "extract_features",
    "parse_email",
]
