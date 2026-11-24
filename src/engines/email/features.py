"""Deterministic email feature extraction for day-1 rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

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
    "sharepoint",
    "onedrive",
    "outlook",
)

OFFICIAL_BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "office.com", "office365.com", "live.com"),
    "amazon": ("amazon.com", "amazonaws.com"),
    "google": ("google.com", "gmail.com"),
    "netflix": ("netflix.com",),
    "irs": ("irs.gov",),
    "chase": ("chase.com",),
    "bankofamerica": ("bankofamerica.com",),
    "wellsfargo": ("wellsfargo.com",),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com"),
    "outlook": ("outlook.com", "office.com", "microsoft.com"),
}

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
    "current password",
    "username",
    "ssn",
    "social security",
    "credit card",
    "login",
    "account information",
    "billing information",
    "confirm",
    "pin",
    "one-time",
    "otp",
    "credentials",
)

DOCUMENT_PORTAL_KEYWORDS = (
    "sharepoint",
    "onedrive",
    "office 365",
    "office365",
    "document",
    "shared with you",
    "open document",
    "view document",
    "review document",
)


@dataclass(frozen=True)
class EmailFeatures:
    """Structured feature bundle for an email."""

    from_display_name: str
    from_address: str
    from_domain: str
    from_registrable_domain: str
    reply_to_address: str
    reply_to_domain: str
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
    external_document_request: bool
    document_portal_keyword_count: int
    obfuscated_url_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "from_display_name": self.from_display_name,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "from_registrable_domain": self.from_registrable_domain,
            "reply_to_address": self.reply_to_address,
            "reply_to_domain": self.reply_to_domain,
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
            "external_document_request": self.external_document_request,
            "document_portal_keyword_count": self.document_portal_keyword_count,
            "obfuscated_url_count": self.obfuscated_url_count,
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


def _brand_matches_sender_domain(brand: str, sender_domain: str, registrable_domain: str) -> bool:
    domains = {
        (sender_domain or "").lower().strip("."),
        (registrable_domain or "").lower().strip("."),
    }
    domains.discard("")
    official_domains = OFFICIAL_BRAND_DOMAINS.get(brand, ())
    return any(
        domain == official or domain.endswith("." + official)
        for domain in domains
        for official in official_domains
    )


def _external_document_request(
    parsed: ParsedEmail,
    credential_count: int,
    urgency_count: int,
    portal_keyword_count: int,
) -> bool:
    if portal_keyword_count == 0:
        return False
    lower_text = parsed.combined_text().lower()
    strong_portal_brand = any(
        keyword in lower_text
        for keyword in ("sharepoint", "onedrive", "office 365", "office365")
    )
    sensitive_action = credential_count > 0 or urgency_count > 0
    if not strong_portal_brand and not sensitive_action:
        return False
    external_links = []
    brand = _brand_in_display_name(parsed.from_display_name)
    brand_mismatch = bool(
        brand
        and parsed.from_domain
        and not _brand_matches_sender_domain(
            brand,
            parsed.from_domain,
            parsed.from_registrable_domain,
        )
    )
    if strong_portal_brand and brand_mismatch:
        return True
    for link in parsed.links:
        if not validate_url(link.href):
            continue
        normalized = normalize_url(link.href)
        link_domain = normalized.hostname.lower()
        link_registrable = normalized.registrable_domain.lower()
        sender_domain = parsed.from_domain.lower()
        sender_registrable = parsed.from_registrable_domain.lower()
        reserved_test_registrable = sender_registrable in {"example", "test", "invalid", "local"}
        if (
            link_domain
            and link_domain != sender_domain
            and (
                link_registrable != sender_registrable
                or (reserved_test_registrable and link_registrable == sender_registrable)
            )
        ):
            external_links.append(link)
    sensitive_action = credential_count > 0 or urgency_count > 0
    return bool(external_links) and (portal_keyword_count >= 2 or sensitive_action)


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
    display_name_domain_mismatch = bool(
        brand
        and parsed.from_domain
        and not _brand_matches_sender_domain(
            brand,
            parsed.from_domain,
            parsed.from_registrable_domain,
        )
    )

    from_reply_to_mismatch = bool(
        parsed.from_domain
        and parsed.reply_to_domain
        and (
            parsed.from_domain != parsed.reply_to_domain
            or (
                parsed.from_registrable_domain
                and parsed.reply_to_registrable_domain
                and parsed.from_registrable_domain != parsed.reply_to_registrable_domain
            )
        )
    )

    auth_fail = any(value in {"fail", "permerror", "softfail"} for value in (parsed.auth_spf, parsed.auth_dkim, parsed.auth_dmarc))
    missing_core_headers = bool(parsed.headers_provided and (not parsed.has_date_header or not parsed.has_message_id_header))
    text = parsed.combined_text()
    urgency_count = _count_keywords(text, URGENCY_KEYWORDS)
    credential_count = _count_keywords(text, CREDENTIAL_KEYWORDS)
    portal_keyword_count = _count_keywords(text, DOCUMENT_PORTAL_KEYWORDS)
    external_document_request = _external_document_request(
        parsed,
        credential_count,
        urgency_count,
        portal_keyword_count,
    )
    obfuscated_url_count = sum(
        1
        for link in parsed.links
        if validate_url(link.href)
        and "@" in urlsplit(link.href).netloc
    )

    return EmailFeatures(
        from_display_name=parsed.from_display_name,
        from_address=parsed.from_address,
        from_domain=parsed.from_domain,
        from_registrable_domain=parsed.from_registrable_domain,
        reply_to_address=parsed.reply_to_address,
        reply_to_domain=parsed.reply_to_domain,
        reply_to_registrable_domain=parsed.reply_to_registrable_domain,
        display_name_brand=brand,
        display_name_domain_mismatch=display_name_domain_mismatch,
        from_reply_to_mismatch=from_reply_to_mismatch,
        auth_fail=auth_fail,
        auth_spf=parsed.auth_spf,
        auth_dkim=parsed.auth_dkim,
        auth_dmarc=parsed.auth_dmarc,
        missing_core_headers=missing_core_headers,
        urgency_keyword_count=urgency_count,
        credential_keyword_count=credential_count,
        link_count=len(parsed.links),
        mismatched_links=_mismatched_links(parsed),
        external_document_request=external_document_request,
        document_portal_keyword_count=portal_keyword_count,
        obfuscated_url_count=obfuscated_url_count,
    )
