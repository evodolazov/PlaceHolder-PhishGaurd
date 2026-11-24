from __future__ import annotations

import pytest

from src.core.exceptions import InvalidEmail
from src.engines.email.parser import parse_email, visible_text_domain
from src.engines.email.features import extract_features


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


def test_parse_reply_to_and_sender_case_insensitively_from_headers() -> None:
    parsed = parse_email(
        {
            "subject": "Hello",
            "headers": {
                "from": "Sender <sender@company.example>",
                "reply-to": "Support <support@external.example>",
                "authentication-results": "mx.example; spf=pass; dkim=pass; dmarc=pass",
            },
        }
    )
    assert parsed.from_address == "sender@company.example"
    assert parsed.from_display_name == "Sender"
    assert parsed.reply_to_address == "support@external.example"
    assert parsed.reply_to_domain == "external.example"
    assert parsed.auth_spf == "pass"


def test_parse_supports_bracketed_sender_address() -> None:
    parsed = parse_email(
        {
            "from": "PayPal Support [support@paypal-account-security.example]",
            "subject": "Account notice",
        }
    )
    assert parsed.from_address == "support@paypal-account-security.example"
    assert parsed.from_display_name == "PayPal Support"


def test_parse_malformed_or_missing_mailboxes_does_not_crash() -> None:
    parsed = parse_email(
        {
            "from": "not-an-email",
            "reply_to": "also malformed",
            "subject": "Hello",
            "body_text": "This is a test.",
        }
    )
    assert parsed.from_address == ""
    assert parsed.reply_to_address == ""


def test_legitimate_official_brand_display_name_and_domain_match() -> None:
    parsed = parse_email(
        {
            "from": "PayPal <service@paypal.com>",
            "subject": "Receipt",
        }
    )
    features = extract_features(parsed)
    assert features.display_name_domain_mismatch is False
