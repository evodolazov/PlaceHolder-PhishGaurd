from __future__ import annotations

from src.engines.email.features import extract_features
from src.engines.email.parser import parse_email
from src.engines.email.rules import (
    auth_results_fail_rule,
    credential_request_rule,
    display_name_domain_mismatch_rule,
    from_reply_to_mismatch_rule,
    link_text_href_mismatch_rule,
    missing_core_headers_rule,
    urgency_language_rule,
)


def _features(payload: dict):
    return extract_features(parse_email(payload))


def test_display_name_mismatch_fires() -> None:
    features = _features({"from": "PayPal Security <support@paypa1-secure.com>", "subject": "Hello"})
    result = display_name_domain_mismatch_rule(features)
    assert result.fired is True
    assert result.weight == 25


def test_display_name_mismatch_does_not_fire_for_matching_brand() -> None:
    features = _features({"from": "PayPal <service@paypal.com>", "subject": "Receipt"})
    result = display_name_domain_mismatch_rule(features)
    assert result.fired is False


def test_from_reply_to_mismatch_fires() -> None:
    features = _features(
        {
            "from": "billing@company.com",
            "reply_to": "help@gmail.com",
            "subject": "Invoice",
        }
    )
    result = from_reply_to_mismatch_rule(features)
    assert result.fired is True
    assert result.weight == 20


def test_auth_results_fail_fires() -> None:
    features = _features(
        {
            "from": "a@example.com",
            "subject": "Hi",
            "headers": {"Authentication-Results": "spf=fail; dkim=pass; dmarc=pass"},
        }
    )
    assert auth_results_fail_rule(features).fired is True


def test_link_text_href_mismatch_fires() -> None:
    features = _features(
        {
            "from": "a@example.com",
            "body_html": '<a href="http://192.0.2.1/login">https://paypal.com/login</a>',
        }
    )
    result = link_text_href_mismatch_rule(features)
    assert result.fired is True
    assert result.weight == 30


def test_urgency_and_credential_rules_fire() -> None:
    features = _features(
        {
            "from": "a@example.com",
            "subject": "Urgent: verify your account",
            "body_text": "Please confirm your password now.",
        }
    )
    assert urgency_language_rule(features).fired is True
    assert credential_request_rule(features).fired is True


def test_missing_core_headers_only_when_headers_submitted() -> None:
    without_headers = _features({"from": "a@example.com", "subject": "Hi"})
    with_headers = _features({"from": "a@example.com", "subject": "Hi", "headers": {}})
    assert missing_core_headers_rule(without_headers).fired is False
    assert missing_core_headers_rule(with_headers).fired is True
