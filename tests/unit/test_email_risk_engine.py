from __future__ import annotations

from src.engines.email.analyzer import analyze_email
from src.engines.email.features import extract_features
from src.engines.email.parser import parse_email
from src.fusion.email_risk_engine import score_email


def test_clean_email_is_low_risk() -> None:
    result = analyze_email(
        {
            "from": "Alice <alice@example.com>",
            "subject": "Lunch tomorrow",
            "body_text": "Want to meet at noon?",
        }
    )
    assert result["classification"] == "low_risk"
    assert result["risk_score"] == 0
    assert result["evidence"] == []
    assert result["urls"] == []


def test_suspicious_email_stacks_rules_and_urls() -> None:
    result = analyze_email(
        {
            "from": "PayPal Security <support@paypa1-secure.com>",
            "reply_to": "help@gmail.com",
            "subject": "Urgent: verify your account",
            "body_html": '<a href="http://192.0.2.1/login">https://paypal.com/login</a>',
            "headers": {"Authentication-Results": "spf=fail; dkim=fail; dmarc=fail"},
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.display_name_domain_mismatch" in indicators
    assert "email.from_reply_to_mismatch" in indicators
    assert "email.link_text_href_mismatch" in indicators
    assert result["risk_score"] >= 60
    assert result["urls"]
    assert result["urls"][0]["url"] == "http://192.0.2.1/login"


def test_url_component_is_capped() -> None:
    features = extract_features(parse_email({"from": "a@example.com", "subject": "Hi"}))
    assessment = score_email(features, [{"url": "http://192.0.2.1/", "risk_score": 100, "evidence": []}])
    assert assessment.risk_score == 40
