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


def test_embedded_url_results_are_sanitized() -> None:
    result = analyze_email(
        {
            "from": "support@example.com",
            "body_html": '<a href="https://user:pass@evil.example/login?token=abc123&safe=1">Click here</a>',
        }
    )
    assert result["urls"]
    assert result["urls"][0]["url"].startswith("https://evil.example/login?")
    assert "pass" not in result["urls"][0]["url"]
    assert "abc123" not in result["urls"][0]["url"]
    assert "token=%5BREDACTED%5D" in result["urls"][0]["url"]
    assert "safe=1" in result["urls"][0]["url"]


def test_legitimate_urgent_tuition_reminder_stays_low_risk() -> None:
    result = analyze_email(
        {
            "from": "Tuition Office <billing@university.example>",
            "subject": "Urgent: tuition reminder",
            "body_text": "Your tuition payment is due Friday. Please sign in to the student portal.",
            "headers": {"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"},
        }
    )
    assert result["classification"] == "low_risk"
    assert result["risk_score"] < 30


def test_professional_document_portal_phishing_is_high_risk() -> None:
    result = analyze_email(
        {
            "from": "Microsoft SharePoint <notifications@portal-security.example>",
            "subject": "SharePoint document notification",
            "body_html": '<a href="https://login-verify.example/portal">Review the shared document in SharePoint</a>',
            "headers": {"Authentication-Results": "spf=fail; dkim=pass; dmarc=pass"},
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.external_document_request" in indicators
    assert "email.display_name_domain_mismatch" in indicators
    assert result["classification"] in {"high_risk", "critical_risk"}


def test_paypal_sender_spoofing_is_high_risk() -> None:
    result = analyze_email(
        {
            "from": "PayPal Support [support@paypal-account-security.example]",
            "reply_to": "help@gmail.com",
            "subject": "Urgent account verification",
            "body_text": "Verify your account and confirm your password now.",
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.display_name_domain_mismatch" in indicators
    assert "email.sensitive_reply_to_mismatch" in indicators
    assert result["classification"] in {"high_risk", "critical_risk"}


def test_suspicious_reply_to_mismatch_with_credentials_is_high_risk() -> None:
    result = analyze_email(
        {
            "from": "Billing <billing@company.example>",
            "reply_to": "collection@gmail.com",
            "subject": "Urgent invoice",
            "body_text": "Please sign in and confirm your password.",
        }
    )
    assert "email.sensitive_reply_to_mismatch" in {item["indicator"] for item in result["evidence"]}
    assert result["classification"] in {"high_risk", "critical_risk"}


def test_legitimate_reply_to_difference_does_not_become_high_risk() -> None:
    result = analyze_email(
        {
            "from": "Billing <billing@company.example>",
            "reply_to": "support@company.example",
            "subject": "Invoice delivered",
            "body_text": "Your monthly invoice is attached. Reply if you have questions.",
        }
    )
    assert result["classification"] not in {"high_risk", "critical_risk"}


def test_reserved_example_domains_still_compare_full_domains() -> None:
    result = analyze_email(
        {
            "from": "Campus IT Helpdesk <helpdesk@campus-it-notice.example>",
            "reply_to": "credential-collection@external-mail.example",
            "subject": "Urgent mailbox security verification",
            "body_text": "Your mailbox may be suspended within two hours. Reply with your username and current password.",
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.from_reply_to_mismatch" in indicators
    assert "email.sensitive_reply_to_mismatch" in indicators
    assert result["classification"] == "high_risk"
    assert result["risk_score"] >= 60


def test_obfuscated_at_symbol_url_remains_critical_risk() -> None:
    result = analyze_email(
        {
            "from": "Support <support@company.example>",
            "subject": "Secure account review",
            "body_html": '<a href="https://paypal.example@evil.example/login">Continue</a>',
        }
    )
    assert result["risk_score"] >= 60
    assert result["urls"]


def test_downloaded_sharepoint_fixture_is_high_risk() -> None:
    result = analyze_email(
        {
            "from": "Microsoft SharePoint Notifications <document-alert@sharepoint-access.example>",
            "subject": "Shared Document: Updated Project Requirements",
            "body_text": (
                "Open the document using the link below and sign in to continue. "
                "If you do not review this document today, access may be suspended."
            ),
            "body_html": '<a href="http://sharepoint-access.example/secure/document?id=48291">Open document</a>',
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.display_name_domain_mismatch" in indicators
    assert "email.external_document_request" in indicators
    assert "email.urgency_language" in indicators
    assert result["classification"] in {"high_risk", "critical_risk"}


def test_downloaded_paypal_fixture_is_high_risk() -> None:
    result = analyze_email(
        {
            "from": "PayPal Support <billing@paypal-account-review.example>",
            "subject": "Your PayPal Account Requires Verification",
            "body_text": (
                "Billing information associated with your PayPal account requires review. "
                "Review your account information immediately."
            ),
            "body_html": '<a href="http://paypal-account-review.example/confirm">Review account</a>',
        }
    )
    indicators = {item["indicator"] for item in result["evidence"]}
    assert "email.display_name_domain_mismatch" in indicators
    assert "email.credential_request" in indicators
    assert "email.urgency_language" in indicators
    assert result["classification"] in {"high_risk", "critical_risk"}
