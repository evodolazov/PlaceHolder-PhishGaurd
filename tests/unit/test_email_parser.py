from __future__ import annotations

import pytest

from src.core.exceptions import InvalidEmail
from src.engines.email.parser import parse_email, visible_text_domain


def test_parse_rejects_empty_payload() -> None:
    with pytest.raises(InvalidEmail):
        parse_email({})


def test_parse_extracts_sender_and_text_link() -> None:
    parsed = parse_email(
        {
            "from": "Alice <alice@example.com>",
            "subject": "Hello",
            "body_text": "Read this http://example.com/path",
        }
    )
    assert parsed.from_address == "alice@example.com"
    assert parsed.from_registrable_domain == "example.com"
    assert parsed.from_display_name == "Alice"
    assert len(parsed.links) == 1
    assert parsed.links[0].href == "http://example.com/path"
    assert parsed.headers_provided is False


def test_parse_extracts_html_link_text() -> None:
    parsed = parse_email(
        {
            "from": "support@example.com",
            "body_html": '<a href="http://192.0.2.1/login">https://paypal.com/login</a>',
        }
    )
    assert parsed.links[0].href == "http://192.0.2.1/login"
    assert parsed.links[0].text == "https://paypal.com/login"
    assert visible_text_domain(parsed.links[0].text) == "paypal.com"


def test_parse_auth_and_header_flags() -> None:
    parsed = parse_email(
        {
            "from": "a@example.com",
            "subject": "Hi",
            "headers": {
                "Authentication-Results": "mx.example.com; spf=fail smtp.mailfrom=x; dkim=fail; dmarc=fail",
                "Date": "Tue, 13 Oct 2026 18:00:00 -0400",
                "Message-ID": "<abc@example.com>",
            },
        }
    )
    assert parsed.headers_provided is True
    assert parsed.auth_spf == "fail"
    assert parsed.has_date_header is True
    assert parsed.has_message_id_header is True
