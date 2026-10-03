"""Core exceptions for PhishGuard."""


class InvalidURL(ValueError):
    """Raised when a supplied URL fails validation."""


class AnalysisNotFoundError(LookupError):
    """Raised when an analysis record does not exist."""
