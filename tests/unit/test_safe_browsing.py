from __future__ import annotations
import io
import urllib.error

from src.engines.threat_intel.safe_browsing import MATCH_WEIGHT, apply_safe_browsing, lookup_url
from src.engines.url.analyzer import analyze_url
from src.fusion.risk_engine import RiskAssessment


def test_lookup_skips_without_key_or_flag(monkeypatch) -> None:
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("SAFE_BROWSING_ENABLED", raising=False)
    assert lookup_url("https://example.com") == []


def test_lookup_skips_when_disabled(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setenv("SAFE_BROWSING_ENABLED", "false")
    assert lookup_url("https://example.com") == []


def test_lookup_reports_unavailable_when_service_errors(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    monkeypatch.setenv("SAFE_BROWSING_ENABLED", "true")
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(urllib.error.URLError("unavailable")),
    )
    from src.engines.threat_intel.safe_browsing import lookup_url_with_status
    matches, status = lookup_url_with_status("https://example.com")
    assert matches == []
    assert status["status"] == "unavailable"


def test_lookup_reports_invalid_key_as_unavailable(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "invalid-key")
    monkeypatch.setenv("SAFE_BROWSING_ENABLED", "true")
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.urllib.request.urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            urllib.error.HTTPError("https://example.com", 400, "Bad Request", {}, io.BytesIO(b""))
        ),
    )
    from src.engines.threat_intel.safe_browsing import lookup_url_with_status
    matches, status = lookup_url_with_status("https://example.com")
    assert matches == []
    assert status["status"] == "unavailable"


def test_apply_safe_browsing_adds_score_and_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.lookup_url_with_status",
        lambda _url: ([{"threatType": "SOCIAL_ENGINEERING"}], {"status": "enabled", "message": "Lookup completed."}),
    )
    original = RiskAssessment(classification="low_risk", risk_score=0, confidence=None, evidence=[])
    updated = apply_safe_browsing("https://evil.example/login", original)

    assert updated.risk_score == MATCH_WEIGHT
    assert updated.classification == "moderate_risk"
    assert updated.evidence[0]["source"] == "google_safe_browsing"
    assert updated.evidence[0]["indicator"] == "gsb.social_engineering"
    assert updated.confidence is None


def test_apply_safe_browsing_no_match_leaves_score(monkeypatch) -> None:
    monkeypatch.setattr(
        "src.engines.threat_intel.safe_browsing.lookup_url_with_status",
        lambda _url: ([], {"status": "enabled", "message": "Lookup completed."}),
    )
    original = RiskAssessment(classification="low_risk", risk_score=0, confidence=0.05, evidence=[])
    updated = apply_safe_browsing("https://example.com", original)
    assert updated.risk_score == 0
    assert updated.evidence == []


def test_analyze_url_includes_safe_browsing_when_listed(monkeypatch) -> None:
    monkeypatch.setattr(
        "src.engines.url.analyzer.apply_safe_browsing",
        lambda url, assessment: RiskAssessment(
            classification="high_risk",
            risk_score=min(100, assessment.risk_score + MATCH_WEIGHT),
            confidence=0.5,
            evidence=assessment.evidence
            + [
                {
                    "source": "google_safe_browsing",
                    "indicator": "gsb.social_engineering",
                    "severity": "high",
                    "value": {"url": url, "threatType": "SOCIAL_ENGINEERING"},
                    "description": "Google Safe Browsing lists this URL as phishing.",
                }
            ],
        ),
    )
    result = analyze_url("https://example.com")
    assert result["risk_score"] >= MATCH_WEIGHT
    assert any(item["source"] == "google_safe_browsing" for item in result["evidence"])
