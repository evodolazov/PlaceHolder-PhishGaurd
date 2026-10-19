"""Parse submitted email fields into a structured message for analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any

import tldextract

from src.core.exceptions import InvalidEmail
from src.engines.url.normalizer import validate_url

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z0-9-]+)", re.IGNORECASE)
DOMAIN_LIKE_RE = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.IGNORECASE)


@dataclass(frozen=True)
class ExtractedLink:
    """A URL found in the message body."""

    href: str
    text: str
    source: str


@dataclass(frozen=True)
class ParsedEmail:
    """Normalized email fields used by feature extraction and rules."""

    from_display_name: str
    from_address: str
    from_domain: str
    from_registrable_domain: str
    reply_to_address: str
    reply_to_domain: str
    reply_to_registrable_domain: str
    return_path_domain: str
    subject: str
    body_text: str
    body_html: str
    headers: dict[str, Any]
    headers_provided: bool
    has_date_header: bool
    has_message_id_header: bool
    auth_spf: str
    auth_dkim: str
    auth_dmarc: str
    links: tuple[ExtractedLink, ...] = field(default_factory=tuple)

    def combined_text(self) -> str:
        return f"{self.subject}\n{self.body_text}\n{self.body_html}"


class _HTMLLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[ExtractedLink] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href") or ""
        self._href = href.strip()
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._href is None:
            return
        href = _clean_url(self._href)
        if href:
            self.links.append(ExtractedLink(href=href, text="".join(self._text).strip(), source="html"))
        self._href = None
        self._text = []


def _clean_url(url: str) -> str:
    return url.strip().rstrip(".,);]>\"'")


def _header_value(headers: dict[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    for key, value in headers.items():
        if str(key).lower() == name.lower():
            if isinstance(value, list):
                return " ".join(str(item) for item in value)
            return str(value)
    return ""


def _has_header(headers: dict[str, Any] | None, name: str) -> bool:
    if not headers:
        return False
    return any(str(key).lower() == name.lower() for key in headers)


def _mailbox_parts(value: str) -> tuple[str, str, str, str]:
    display_name, address = parseaddr(value or "")
    address = address.strip().lower()
    domain = address.split("@", 1)[1].lower() if "@" in address else ""
    extracted = tldextract.extract(domain, include_psl_private_domains=False) if domain else None
    registrable = ""
    if extracted is not None:
        registrable = (
            getattr(extracted, "top_domain_under_public_suffix", None)
            or getattr(extracted, "domain", None)
            or domain
        )
        if isinstance(registrable, str):
            registrable = registrable.lower()
        else:
            registrable = domain
    return display_name.strip(), address, domain, registrable


def _parse_auth_results(value: str) -> dict[str, str]:
    results = {"spf": "", "dkim": "", "dmarc": ""}
    for match in AUTH_RE.finditer(value or ""):
        results[match.group(1).lower()] = match.group(2).lower()
    return results


def _text_links(body_text: str) -> list[ExtractedLink]:
    links: list[ExtractedLink] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(body_text or ""):
        href = _clean_url(match.group(0))
        if not href or href in seen:
            continue
        seen.add(href)
        links.append(ExtractedLink(href=href, text=href, source="text"))
    return links


def _html_links(body_html: str) -> list[ExtractedLink]:
    if not body_html:
        return []
    parser = _HTMLLinkParser()
    try:
        parser.feed(body_html)
        parser.close()
    except Exception:
        return []
    return parser.links


def visible_text_domain(text: str) -> str:
    """Return a registrable domain from link text when it looks like a URL or host."""
    candidate = (text or "").strip()
    if not candidate:
        return ""
    match = DOMAIN_LIKE_RE.search(candidate)
    if match is None:
        return ""
    host = match.group(1).lower().rstrip(".")
    extracted = tldextract.extract(host, include_psl_private_domains=False)
    return (
        getattr(extracted, "top_domain_under_public_suffix", None)
        or getattr(extracted, "domain", None)
        or host
    )


def parse_email(payload: dict[str, Any]) -> ParsedEmail:
    """Validate and normalize a JSON email submission."""
    if not isinstance(payload, dict):
        raise InvalidEmail("A JSON email object is required.")

    from_raw = str(payload.get("from") or "").strip()
    reply_to_raw = str(payload.get("reply_to") or "").strip()
    subject = str(payload.get("subject") or "").strip()
    body_text = str(payload.get("body_text") or "")
    body_html = str(payload.get("body_html") or "")
    headers = payload.get("headers")
    headers_provided = headers is not None
    if headers is None:
        headers = {}
    if not isinstance(headers, dict):
        raise InvalidEmail("headers must be an object when provided.")

    if not any([from_raw, reply_to_raw, subject, body_text.strip(), body_html.strip()]):
        raise InvalidEmail("An email from, subject, or body is required.")

    from_display_name, from_address, from_domain, from_registrable = _mailbox_parts(from_raw)
    _, reply_to_address, reply_to_domain, reply_to_registrable = _mailbox_parts(reply_to_raw)
    _, return_path_address, return_path_domain, _ = _mailbox_parts(_header_value(headers, "Return-Path"))
    if not return_path_domain and return_path_address:
        return_path_domain = return_path_address.split("@", 1)[-1]

    auth = _parse_auth_results(_header_value(headers, "Authentication-Results"))

    html_links = _html_links(body_html)
    text_links = _text_links(body_text)
    seen_hrefs = {link.href for link in html_links}
    links = list(html_links)
    for link in text_links:
        if link.href not in seen_hrefs:
            links.append(link)
            seen_hrefs.add(link.href)

    return ParsedEmail(
        from_display_name=from_display_name,
        from_address=from_address,
        from_domain=from_domain,
        from_registrable_domain=from_registrable,
        reply_to_address=reply_to_address,
        reply_to_domain=reply_to_domain,
        reply_to_registrable_domain=reply_to_registrable,
        return_path_domain=return_path_domain.lower() if return_path_domain else "",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        headers_provided=headers_provided,
        has_date_header=_has_header(headers, "Date"),
        has_message_id_header=_has_header(headers, "Message-ID") or _has_header(headers, "Message-Id"),
        auth_spf=auth["spf"],
        auth_dkim=auth["dkim"],
        auth_dmarc=auth["dmarc"],
        links=tuple(links),
    )


def http_links(parsed: ParsedEmail) -> list[ExtractedLink]:
    """Return extracted links that the URL engine can score."""
    return [link for link in parsed.links if validate_url(link.href)]
