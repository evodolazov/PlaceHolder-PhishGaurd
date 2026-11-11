"""URL redaction helpers that keep analysis useful without persisting secrets."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "authorization",
    "client_secret",
    "code",
    "credential",
    "email",
    "id_token",
    "jwt",
    "key",
    "login",
    "oauth",
    "otp",
    "pass",
    "passwd",
    "password",
    "pwd",
    "refresh_token",
    "s3cr3t",
    "secret",
    "session",
    "sessionid",
    "sig",
    "signature",
    "state",
    "token",
    "tokenid",
    "user",
    "username",
    "verification_code",
    "webhook",
}

_REDACTED = "[REDACTED]"


def _is_sensitive_query_key(name: str) -> bool:
    normalized = (name or "").strip().lower()
    if not normalized:
        return False
    if normalized in SENSITIVE_QUERY_KEYS:
        return True
    if any(token in normalized for token in ("token", "secret", "session", "passwd", "password", "auth", "jwt", "key", "sig")):
        return True
    return False


def redact_sensitive_query_parameters(query: str) -> str:
    """Return a query string without placeholder-bearing secrets."""
    if not query:
        return ""

    items = parse_qsl(query, keep_blank_values=True)
    sanitized = []
    for key, value in items:
        if _is_sensitive_query_key(key):
            sanitized.append((key, _REDACTED))
        else:
            sanitized.append((key, value))
    return urlencode(sanitized, doseq=True)


def strip_credentials(raw_url: str) -> str:
    """Return a safe URL with any embedded credentials removed."""
    value = (raw_url or "").strip()
    if not value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value

    hostname = parsed.hostname or ""
    if not hostname:
        return value

    if ":" in hostname and not hostname.startswith("["):
        authority = f"[{hostname}]"
    else:
        authority = hostname

    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"

    safe_query = redact_sensitive_query_parameters(parsed.query)
    safe_path = parsed.path or ""
    return urlunsplit((parsed.scheme, authority, safe_path, safe_query, parsed.fragment))


def sanitize_url_for_storage(raw_url: str) -> str:
    """Return the public-safe representation used for persistence and response payloads."""
    return strip_credentials(raw_url)
