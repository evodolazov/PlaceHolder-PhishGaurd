"""Core exceptions for PhishGuard."""


class InvalidURL(ValueError):
    """Raised when a supplied URL fails validation."""


class InvalidEmail(ValueError):
    """Raised when a supplied email payload cannot be analyzed."""


class AnalysisNotFoundError(LookupError):
    """Raised when an analysis record does not exist."""
