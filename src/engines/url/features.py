"""Deterministic URL feature extraction for Milestone 0."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from src.engines.url.normalizer import NormalizedURL


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "credential",
    "authenticate",
    "confirm",
    "payment",
    "invoice",
    "suspend",
    "unlock",
]


@dataclass(frozen=True)
class URLFeatures:
    """Structured feature bundle for a URL."""

    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    fragment_length: int
    dot_count: int
    hyphen_count: int
    underscore_count: int
    slash_count: int
    question_mark_count: int
    equals_count: int
    ampersand_count: int
    at_symbol_count: int
    digit_count: int
    special_character_count: int
    subdomain_count: int
    has_ip_address: bool
    has_punycode: bool
    has_port: bool
    is_nonstandard_port: bool
    hostname_contains_digits: bool
    uses_https: bool
    suspicious_keyword_count: int
    port: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "url_length": self.url_length,
            "hostname_length": self.hostname_length,
            "path_length": self.path_length,
            "query_length": self.query_length,
            "fragment_length": self.fragment_length,
            "dot_count": self.dot_count,
            "hyphen_count": self.hyphen_count,
            "underscore_count": self.underscore_count,
            "slash_count": self.slash_count,
            "question_mark_count": self.question_mark_count,
            "equals_count": self.equals_count,
            "ampersand_count": self.ampersand_count,
            "at_symbol_count": self.at_symbol_count,
            "digit_count": self.digit_count,
            "special_character_count": self.special_character_count,
            "subdomain_count": self.subdomain_count,
            "has_ip_address": self.has_ip_address,
            "has_punycode": self.has_punycode,
            "has_port": self.has_port,
            "is_nonstandard_port": self.is_nonstandard_port,
            "hostname_contains_digits": self.hostname_contains_digits,
            "uses_https": self.uses_https,
            "suspicious_keyword_count": self.suspicious_keyword_count,
            "port": self.port,
        }


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count(url_text: str, symbol: str) -> int:
    return url_text.count(symbol)


def _count_user_info_at_symbols(normalized_url: NormalizedURL) -> int:
    return 1 if normalized_url.username is not None else 0


def extract_features(normalized_url: NormalizedURL) -> URLFeatures:
    """Compute deterministic features from a normalized URL."""
    hostname = normalized_url.hostname
    url_text = normalized_url.normalized_url
    lower_url = url_text.lower()
    suspicious_keyword_count = sum(lower_url.count(keyword) for keyword in SUSPICIOUS_KEYWORDS)

    labels = [part for part in hostname.split(".") if part]
    subdomain_count = max(0, len(labels) - 2) if not _is_ip_address(hostname) and len(labels) > 2 else 0

    port = normalized_url.port
    has_port = port is not None
    is_nonstandard_port = bool(has_port and port not in {80, 443})
    at_symbol_count = _count_user_info_at_symbols(normalized_url)

    return URLFeatures(
        url_length=len(url_text),
        hostname_length=len(hostname),
        path_length=len(normalized_url.path),
        query_length=len(normalized_url.query),
        fragment_length=len(normalized_url.fragment),
        dot_count=_count(url_text, "."),
        hyphen_count=_count(url_text, "-"),
        underscore_count=_count(url_text, "_"),
        slash_count=_count(url_text, "/"),
        question_mark_count=_count(url_text, "?"),
        equals_count=_count(url_text, "="),
        ampersand_count=_count(url_text, "&"),
        at_symbol_count=at_symbol_count,
        digit_count=sum(ch.isdigit() for ch in url_text),
        special_character_count=sum(
            1
            for ch in url_text
            if not (ch.isalnum() or ch in "-._~:/?#[]@!$&'()*+,;=%")
        ),
        subdomain_count=subdomain_count,
        has_ip_address=_is_ip_address(hostname),
        has_punycode="xn--" in hostname.lower(),
        has_port=has_port,
        is_nonstandard_port=is_nonstandard_port,
        hostname_contains_digits=any(ch.isdigit() for ch in hostname),
        uses_https=normalized_url.scheme.lower() == "https",
        suspicious_keyword_count=suspicious_keyword_count,
        port=port,
    )
