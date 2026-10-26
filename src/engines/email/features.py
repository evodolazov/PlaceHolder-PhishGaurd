"""Deterministic email feature extraction for day-1 rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.engines.email.parser import ParsedEmail, visible_text_domain
from src.engines.url.normalizer import validate_url, normalize_url

BRAND_TOKENS = (
    "paypal",
    "apple",
    "microsoft",
    "amazon",
    "google",
    "netflix",
    "irs",
    "chase",
    "bankofamerica",
    "wellsfargo",
)

URGENCY_KEYWORDS = (
    "urgent",
    "immediately",
    "suspended",
    "verify",
    "account locked",
    "act now",
    "expires",
    "final notice",
)

CREDENTIAL_KEYWORDS = (
    "password",
    "ssn",
    "social security",
    "credit card",
    "login",
    "confirm",
    "pin",
    "one-time",
    "otp",
    "credentials",
)


@dataclass(frozen=True)
class EmailFeatures:
    """Structured feature bundle for an email."""

    from_display_name: str
    from_address: str
    from_registrable_domain: str
    reply_to_address: str
    reply_to_registrable_domain: str
    display_name_brand: str
    display_name_domain_mismatch: bool
    from_reply_to_mismatch: bool
    auth_fail: bool
    auth_spf: str
    auth_dkim: str
    auth_dmarc: str
    missing_core_headers: bool
    urgency_keyword_count: int
    credential_keyword_count: int
    link_count: int
    mismatched_links: tuple[dict[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "from_display_name": self.from_display_name,
            "from_address": self.from_address,
            "from_registrable_domain": self.from_registrable_domain,
            "reply_to_address": self.reply_to_address,
            "reply_to_registrable_domain": self.reply_to_registrable_domain,
            "display_name_brand": self.display_name_brand,
            "display_name_domain_mismatch": self.display_name_domain_mismatch,
            "from_reply_to_mismatch": self.from_reply_to_mismatch,
            "auth_fail": self.auth_fail,
            "auth_spf": self.auth_spf,
            "auth_dkim": self.auth_dkim,
            "auth_dmarc": self.auth_dmarc,
            "missing_core_headers": self.missing_core_headers,
            "urgency_keyword_count": self.urgency_keyword_count,
            "credential_keyword_count": self.credential_keyword_count,
            "link_count": self.link_count,
            "mismatched_links": list(self.mismatched_links),
        }


def _count_keywords(text: str, keywords: tuple[str, ...]) -> int:
    lower = text.lower()
    return sum(lower.count(keyword) for keyword in keywords)


def _brand_in_display_name(display_name: str) -> str:
    compact = re_sub_non_alnum(display_name.lower())
    spaced = display_name.lower()
    for brand in BRAND_TOKENS:
        if brand in compact or brand in spaced:
            return brand
    return ""


def re_sub_non_alnum(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum())


def _mismatched_links(parsed: ParsedEmail) -> tuple[dict[str, str], ...]:
    mismatches: list[dict[str, str]] = []
    for link in parsed.links:
        if not validate_url(link.href):
            continue
        text_domain = visible_text_domain(link.text)
        if not text_domain:
            continue
        href_domain = normalize_url(link.href).registrable_domain.lower()
        if text_domain.lower() != href_domain:
            mismatches.append({"text": link.text, "href": link.href, "text_domain": text_domain, "href_domain": href_domain})
    return tuple(mismatches)


def extract_features(parsed: ParsedEmail) -> EmailFeatures:
    """Compute deterministic features from a parsed email."""
    brand = _brand_in_display_name(parsed.from_display_name)
    domain_blob = f"{parsed.from_registrable_domain}{parsed.from_domain}".replace(".", "")
    display_name_domain_mismatch = bool(brand and brand not in domain_blob)

    from_reply_to_mismatch = bool(
        parsed.from_registrable_domain
        and parsed.reply_to_registrable_domain
        and parsed.from_registrable_domain != parsed.reply_to_registrable_domain
    )

    auth_fail = any(value in {"fail", "permerror", "softfail"} for value in (parsed.auth_spf, parsed.auth_dkim, parsed.auth_dmarc))
    missing_core_headers = bool(parsed.headers_provided and (not parsed.has_date_header or not parsed.has_message_id_header))
    text = parsed.combined_text()

    return EmailFeatures(
        from_display_name=parsed.from_display_name,
        from_address=parsed.from_address,
        from_registrable_domain=parsed.from_registrable_domain,
        reply_to_address=parsed.reply_to_address,
        reply_to_registrable_domain=parsed.reply_to_registrable_domain,
        display_name_brand=brand,
        display_name_domain_mismatch=display_name_domain_mismatch,
        from_reply_to_mismatch=from_reply_to_mismatch,
        auth_fail=auth_fail,
        auth_spf=parsed.auth_spf,
        auth_dkim=parsed.auth_dkim,
        auth_dmarc=parsed.auth_dmarc,
        missing_core_headers=missing_core_headers,
        urgency_keyword_count=_count_keywords(text, URGENCY_KEYWORDS),
        credential_keyword_count=_count_keywords(text, CREDENTIAL_KEYWORDS),
        link_count=len(parsed.links),
        mismatched_links=_mismatched_links(parsed),
    )
