from __future__ import annotations
import io

import pytest

from src.api.app import create_app


@pytest.fixture()
def client():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with app.test_client() as test_client:
        yield test_client


def _upload_eml(client, eml: bytes):
    return client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(eml), "message.eml")},
        content_type="multipart/form-data",
    )


def _plain_eml(body: bytes) -> bytes:
    return (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        + body
    )


def _multipart_mixed_eml(part_headers: bytes, part_body: bytes) -> bytes:
    return (
        b"MIME-Version: 1.0\r\n"
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'Content-Type: multipart/mixed; boundary="mixed"\r\n\r\n'
        b"--mixed\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"The meeting is scheduled for tomorrow.\r\n"
        b"--mixed\r\n"
        + part_headers
        + b"\r\n\r\n"
        + part_body
        + b"\r\n--mixed--\r\n"
    )


def _multipart_related_eml(
    parts: list[tuple[bytes, bytes]],
    start: bytes | None = None,
) -> bytes:
    content_type = b'multipart/related; boundary="related"'
    if start is not None:
        content_type += b'; start="' + start + b'"'
    body = b"".join(
        b"--related\r\n" + headers + b"\r\n\r\n" + content + b"\r\n"
        for headers, content in parts
    )
    return (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: "
        + content_type
        + b"\r\n\r\n"
        + body
        + b"--related--\r\n"
    )


def _outer_email_with_attached_message(part_headers: bytes, attached_message: bytes) -> bytes:
    return (
        b"MIME-Version: 1.0\r\n"
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'Content-Type: multipart/mixed; boundary="mixed"\r\n\r\n'
        b"--mixed\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please review the agenda at https://example.com/meeting.\r\n"
        b"--mixed\r\n"
        + part_headers
        + b"\r\n\r\n"
        + attached_message
        + b"\r\n--mixed--\r\n"
    )


def _nested_phishing_message() -> bytes:
    return (
        b"From: attacker@example.net\r\n"
        b"Subject: Urgent account verification\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/alternative; boundary="nested"\r\n\r\n'
        b"--nested\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Urgently provide your username and current password at "
        b"https://malicious.example/login.\r\n"
        b"--nested\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b'<p>Provide your password at <a href="https://malicious.example/login">'
        b"this page</a>.</p>\r\n"
        b"--nested--\r\n"
    )


def test_email_analysis_and_retrieval(client) -> None:
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "from": "Alice <alice@example.com>",
            "subject": "Hello",
            "body_text": "See you soon.",
        },
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["classification"] == "low_risk"
    assert payload["confidence"] is None
    assert "analysis_id" in payload
    assert payload["from"] == "Alice <alice@example.com>"

    fetch = client.get(f"/api/v1/email-analysis/{payload['analysis_id']}")
    assert fetch.status_code == 200
    fetch_payload = fetch.get_json()
    assert fetch_payload["analysis_id"] == payload["analysis_id"]
    assert fetch_payload["confidence"] is None


def test_email_threat_status_is_preserved_on_retrieval(client, monkeypatch) -> None:
    threat_status = {
        "status": "unavailable",
        "match_found": None,
        "message": "Google Safe Browsing lookup is currently unavailable.",
    }
    monkeypatch.setattr(
        "src.services.email_analysis_service.get_status",
        lambda: threat_status,
    )

    created = client.post(
        "/api/v1/analyze/email",
        json={"from": "alice@example.com", "subject": "Hello", "body_text": "See you soon."},
    )
    assert created.status_code == 201
    initial = created.get_json()

    retrieved = client.get(f"/api/v1/email-analysis/{initial['analysis_id']}")
    assert retrieved.status_code == 200
    saved = retrieved.get_json()
    assert saved["threat_intelligence"] == threat_status
    assert saved["features"] == initial["features"]


@pytest.mark.parametrize(
    ("matches", "lookup_status", "expected_status", "expected_match"),
    [
        (
            [],
            {"status": "disabled", "match_found": None, "message": "Safe Browsing is disabled."},
            "disabled",
            None,
        ),
        (
            [],
            {"status": "enabled", "match_found": False, "message": "No matches found."},
            "enabled",
            False,
        ),
        (
            [{"threatType": "SOCIAL_ENGINEERING"}],
            {"status": "enabled", "match_found": True, "message": "A match was found."},
            "enabled",
            True,
        ),
        (
            [],
            {"status": "unavailable", "match_found": None, "message": "Lookup unavailable."},
            "unavailable",
            None,
        ),
    ],
)
def test_email_embedded_url_threat_status_is_preserved(
    client,
    monkeypatch,
    matches,
    lookup_status,
    expected_status,
    expected_match,
) -> None:
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.lookup_url_with_status",
        lambda _url: (matches, lookup_status),
    )
    monkeypatch.setattr(
        "src.services.email_analysis_service.get_status",
        lambda: {"status": "enabled", "match_found": None, "message": "No lookup status."},
    )
    created = client.post(
        "/api/v1/analyze/email",
        json={
            "from": "alice@example.com",
            "subject": "Hello",
            "body_text": "Please review https://example.com/login",
        },
    )
    assert created.status_code == 201
    initial = created.get_json()
    threat_status = initial["threat_intelligence"]
    assert threat_status["status"] == expected_status
    assert threat_status["match_found"] is expected_match
    assert initial["urls"][0]["threat_intelligence"] == lookup_status

    retrieved = client.get(f"/api/v1/email-analysis/{initial['analysis_id']}")
    assert retrieved.status_code == 200
    saved = retrieved.get_json()
    assert saved["threat_intelligence"] == threat_status
    assert saved["urls"] == initial["urls"]


def test_email_analysis_with_sensitive_embedded_url_is_sanitized(client) -> None:
    raw_url = "https://user:secret@evil.example/login?token=abc123&safe=1&api_key=xyz"
    response = client.post(
        "/api/v1/analyze/email",
        json={
            "from": "Alice <alice@example.com>",
            "subject": "Urgent action required",
            "body_html": f'<a href="{raw_url}">Confirm account</a>',
        },
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["confidence"] is None
    assert payload["urls"]
    url_result = payload["urls"][0]["url"]
    assert "user:secret" not in url_result
    assert "abc123" not in url_result
    assert "xyz" not in url_result
    assert "safe=1" in url_result
    assert "token=%5BREDACTED%5D" in url_result
    assert "api_key=%5BREDACTED%5D" in url_result
    assert "user:secret" not in str(payload["evidence"])

    fetch = client.get(f"/api/v1/email-analysis/{payload['analysis_id']}")
    assert fetch.status_code == 200
    fetch_payload = fetch.get_json()
    assert fetch_payload["urls"]
    assert "user:secret" not in str(fetch_payload["urls"])
    assert "abc123" not in str(fetch_payload["urls"])
    assert "token=%5BREDACTED%5D" in str(fetch_payload["urls"]) 
    assert fetch_payload["confidence"] is None


def test_empty_email_returns_400(client) -> None:
    response = client.post("/api/v1/analyze/email", json={})
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_email"


def test_missing_email_analysis_returns_404(client) -> None:
    response = client.get("/api/v1/email-analysis/999999")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_valid_eml_upload(client) -> None:
    eml = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Meeting\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"See you tomorrow."
    )
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(eml), "meeting.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["subject"] == "Meeting"
    assert payload["confidence"] is None


def test_eml_upload_rejects_wrong_extension(client) -> None:
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(b"hello"), "hello.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_eml_upload_rejects_missing_file(client) -> None:
    response = client.post("/api/v1/analyze/email/upload", data={}, content_type="multipart/form-data")
    assert response.status_code == 400


def test_eml_upload_rejects_empty_message(client) -> None:
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(b""), "empty.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_eml_upload_rejects_oversized_file(client, monkeypatch) -> None:
    monkeypatch.setattr("src.api.routes.analysis.MAX_UPLOAD_BYTES", 8)
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(b"123456789"), "large.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 413


def test_eml_attachment_is_not_executed_or_analyzed_as_content(client) -> None:
    eml = (
        b"MIME-Version: 1.0\r\n"
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Attachment\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
        b"--b\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="malware.exe"\r\n\r\n'
        b"MZ dangerous bytes\r\n"
        b"--b--\r\n"
    )
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(eml), "attachment.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert "dangerous bytes" not in str(payload)
    assert "MZ" not in str(payload)


def test_email_history_filter_delete_and_privacy(client) -> None:
    created = client.post(
        "/api/v1/analyze/email",
        json={"from": "Private <private@example.com>", "subject": "Status", "body_text": "secret-body-value"},
    )
    assert created.status_code == 201
    analysis_id = created.get_json()["analysis_id"]

    listing = client.get("/api/v1/analyses/email?page=1&page_size=10&search=private")
    assert listing.status_code == 200
    assert "secret-body-value" not in str(listing.get_json())

    deleted = client.delete(f"/api/v1/email-analysis/{analysis_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/v1/email-analysis/{analysis_id}").status_code == 404


def test_reply_to_password_harvesting_eml_is_high_risk(client) -> None:
    eml = (
        b"From: IT Help Desk <helpdesk@campus-it-notice.example>\r\n"
        b"Reply-To: credential-collection@external-mail.example\r\n"
        b"To: student@example.net\r\n"
        b"Subject: Action Required: Mailbox Password Expiration\r\n"
        b"Date: Mon, 24 Nov 2026 09:00:00 -0500\r\n"
        b"Message-ID: <reply-to-regression@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Reply with your username and current password.\r\n"
        b"This request is urgent. Failure to respond within two hours may result in mailbox suspension."
    )
    response = client.post(
        "/api/v1/analyze/email/upload",
        data={"file": (io.BytesIO(eml), "05_reply_to_password_harvesting.eml")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["classification"] == "high_risk"
    assert payload["risk_score"] >= 60
    indicators = {item["indicator"] for item in payload["evidence"]}
    assert "email.from_reply_to_mismatch" in indicators
    assert "email.sensitive_reply_to_mismatch" in indicators
    assert "email.urgency_language" in indicators
    assert "email.credential_request" in indicators


def test_plain_text_eml_body_still_contributes_suspicious_features(client) -> None:
    response = _upload_eml(
        client,
        _plain_eml(b"Please respond immediately and confirm your password."),
    )

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] > 0
    assert features["urgency_keyword_count"] > 0


def test_multipart_alternative_analyzes_plain_and_html_body_parts(client) -> None:
    eml = (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="alt"\r\n\r\n'
        b"--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please confirm your password.\r\n"
        b"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Please urgently sign in and provide your password.</p>\r\n"
        b"--alt--\r\n"
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 2
    assert features["urgency_keyword_count"] == 0


def test_equivalent_multipart_alternatives_are_not_counted_twice(client) -> None:
    eml = (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="alt"\r\n\r\n'
        b"--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please confirm your password.\r\n"
        b"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Please confirm your password.</p>\r\n"
        b"--alt--\r\n"
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    assert response.get_json()["features"]["credential_keyword_count"] == 2


def test_html_only_alternative_link_is_scored_without_double_counting_text(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.lookup_url_with_status",
        lambda _url: (
            [],
            {
                "status": "disabled",
                "match_found": None,
                "message": "Google Safe Browsing is disabled.",
            },
        ),
    )
    eml = (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="alt"\r\n\r\n'
        b"--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Please confirm your password.\r\n"
        b"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b'<p>Please confirm your password.</p><a href="https://example.com/hidden-login">'
        b"Sign in</a>\r\n"
        b"--alt--\r\n"
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    payload = response.get_json()
    assert payload["features"]["credential_keyword_count"] == 2
    assert payload["features"]["link_count"] == 1
    assert len(payload["urls"]) == 1
    link_result = payload["urls"][0]
    assert link_result["normalized_url"] == "https://example.com/hidden-login"
    assert link_result["risk_score"] > 0
    assert any(
        item["indicator"] == "url.suspicious_keywords"
        for item in link_result["evidence"]
    )
    assert any(
        item["indicator"] == "url.suspicious_keywords"
        and item["url"] == link_result["url"]
        for item in payload["evidence"]
    )


def test_html_only_multipart_alternative_remains_analyzable(client) -> None:
    eml = (
        b"From: Sender <sender@example.com>\r\n"
        b"Subject: Routine meeting\r\n"
        b'MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary="alt"\r\n\r\n'
        b"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Please confirm your password.</p>\r\n"
        b"--alt--\r\n"
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    assert response.get_json()["features"]["credential_keyword_count"] == 2


@pytest.mark.parametrize(
    "part_headers",
    [
        pytest.param(b"Content-Type: message/rfc822\r\n", id="unmarked"),
        pytest.param(
            b"Content-Type: message/rfc822\r\n"
            b"Content-Disposition: attachment\r\n",
            id="attachment-disposition",
        ),
        pytest.param(
            b'Content-Type: message/rfc822; name="forwarded.eml"\r\n',
            id="filename-only",
        ),
    ],
)
def test_message_rfc822_attachment_is_not_analyzed(
    client,
    monkeypatch,
    part_headers: bytes,
) -> None:
    monkeypatch.setattr("src.engines.email.analyzer._score_links", lambda _parsed: [])
    eml = _outer_email_with_attached_message(part_headers, _nested_phishing_message())

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 0
    assert features["urgency_keyword_count"] == 0
    assert features["link_count"] == 1


def test_multipart_related_defaults_to_first_root_and_ignores_inline_resources(client) -> None:
    eml = _multipart_related_eml(
        [
            (
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-ID: <root>",
                b"<p>Please confirm your password.</p>",
            ),
            (
                b"Content-Type: image/png\r\n"
                b"Content-ID: <image>\r\n"
                b"Content-Disposition: inline",
                b"not an email body",
            ),
        ]
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 2
    assert features["urgency_keyword_count"] == 0


def test_multipart_related_start_selects_nonfirst_root(client) -> None:
    eml = _multipart_related_eml(
        [
            (
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-ID: <resource>",
                b"Please respond immediately with your password.",
            ),
            (
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-ID: <body>",
                b"<p>Please confirm your password.</p>",
            ),
        ],
        start=b"<body>",
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 2
    assert features["urgency_keyword_count"] == 0


def test_multipart_related_text_resource_does_not_affect_body_features(client) -> None:
    eml = _multipart_related_eml(
        [
            (
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-ID: <body>",
                b"Your password reset is complete.",
            ),
            (
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-ID: <resource>",
                b"Immediately disclose your username and current password.",
            ),
        ]
    )

    response = _upload_eml(client, eml)

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 1
    assert features["urgency_keyword_count"] == 0


def test_text_attachment_credential_request_does_not_change_features_or_score(client) -> None:
    baseline = _upload_eml(client, _plain_eml(b"The meeting is scheduled for tomorrow.")).get_json()
    attached = _upload_eml(
        client,
        _multipart_mixed_eml(
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Disposition: attachment\r\n",
            b"Please confirm your password and provide your username.",
        ),
    )

    assert attached.status_code == 201
    result = attached.get_json()
    assert result["features"]["credential_keyword_count"] == 0
    assert result["risk_score"] == baseline["risk_score"]
    assert result["classification"] == baseline["classification"]


def test_text_attachment_filename_does_not_contribute_urgency_features(client) -> None:
    baseline = _upload_eml(client, _plain_eml(b"The meeting is scheduled for tomorrow.")).get_json()
    attached = _upload_eml(
        client,
        _multipart_mixed_eml(
            b'Content-Type: text/plain; charset=utf-8; name="urgent-note.txt"\r\n',
            b"Respond immediately or access will be suspended.",
        ),
    )

    assert attached.status_code == 201
    result = attached.get_json()
    assert result["features"]["urgency_keyword_count"] == 0
    assert result["risk_score"] == baseline["risk_score"]


def test_named_attachment_with_attachment_disposition_is_excluded(client) -> None:
    response = _upload_eml(
        client,
        _multipart_mixed_eml(
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b'Content-Disposition: attachment; filename="account-notes.txt"\r\n',
            b"Urgently provide your password and username.",
        ),
    )

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] == 0
    assert features["urgency_keyword_count"] == 0


def test_inline_text_part_without_filename_is_analyzed(client) -> None:
    response = _upload_eml(
        client,
        _multipart_mixed_eml(
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Disposition: inline\r\n",
            b"Please respond immediately and confirm your password.",
        ),
    )

    assert response.status_code == 201
    features = response.get_json()["features"]
    assert features["credential_keyword_count"] > 0
    assert features["urgency_keyword_count"] > 0
