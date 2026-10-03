"""URL validation and normalization for Milestone 0."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

from src.core.exceptions import InvalidURL


@dataclass(frozen=True)
class NormalizedURL:
    """Normalized URL representation used across analysis stages."""

    raw_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    port: int | None = None
    username: str | None = None
    password: str | None = None
    path: str = "/"
    query: str = ""
    fragment: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "raw_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "registrable_domain": self.registrable_domain,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }


def validate_url(raw_url: str) -> bool:
    """Return True only for supported, syntactically valid HTTP(S) URLs."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        return False

    value = raw_url.strip()
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return False

    if not parsed.netloc:
        return False

    hostname = parsed.hostname
    if hostname is None:
        return False

    try:
        _ = parsed.port
    except ValueError:
        return False

    return True


def normalize_url(raw_url: str) -> NormalizedURL:
    """Normalize a URL while preserving meaningful data in a safe way."""
    if not validate_url(raw_url):
        raise InvalidURL("A valid HTTP or HTTPS URL is required.")

    value = raw_url.strip()
    parsed = urlsplit(value)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise InvalidURL("A valid HTTP or HTTPS URL is required.")

    port = parsed.port
    username = parsed.username
    password = parsed.password
    path = parsed.path or "/"
    query = parsed.query
    fragment = parsed.fragment

    extracted = tldextract.extract(hostname, include_psl_private_domains=False)
    registrable_domain = (
        getattr(extracted, "top_domain_under_public_suffix", None)
        or getattr(extracted, "domain", None)
        or hostname
    )

    authority = hostname
    if username is not None:
        userinfo = username
        if password is not None:
            userinfo = f"{username}:{password}"
        authority = f"{userinfo}@{hostname}"
    if port is not None:
        authority = f"{authority}:{port}"

    normalized = f"{scheme}://{authority}{path}"
    if query:
        normalized = f"{normalized}?{query}"
    if fragment:
        normalized = f"{normalized}#{fragment}"

    return NormalizedURL(
        raw_url=value,
        normalized_url=normalized,
        scheme=scheme,
        hostname=hostname,
        registrable_domain=registrable_domain,
        port=port,
        username=username,
        password=password,
        path=path,
        query=query,
        fragment=fragment,
    )
