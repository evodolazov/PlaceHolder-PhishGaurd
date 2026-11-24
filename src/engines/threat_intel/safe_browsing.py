"""Optional Google Safe Browsing URL lookup.

This is fail-open: missing keys, disabled config, timeouts, and API errors
leave the heuristic score unchanged.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from src.explainability.reasons import build_evidence
from src.fusion.risk_engine import RiskAssessment, _classify

LOOKUP_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT_SECONDS = 3
MATCH_WEIGHT = 50
THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)

_THREAT_DESCRIPTIONS = {
    "SOCIAL_ENGINEERING": "Google Safe Browsing lists this URL as phishing.",
    "MALWARE": "Google Safe Browsing lists this URL as malware.",
    "UNWANTED_SOFTWARE": "Google Safe Browsing lists this URL as unwanted software.",
    "POTENTIALLY_HARMFUL_APPLICATION": "Google Safe Browsing lists this URL as a potentially harmful app.",
}


def _enabled() -> bool:
    flag = os.getenv("SAFE_BROWSING_ENABLED", "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


def _api_key() -> str:
    return os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()


def lookup_url(url: str) -> list[dict[str, Any]]:
    """Ask Google whether a URL is on a known-bad list. Returns [] if skipped or clean."""
    api_key = _api_key()
    if not _enabled() or not api_key or not url:
        return []

    body = {
        "client": {"clientId": "phishguard", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    query = urllib.parse.urlencode({"key": api_key})
    request = urllib.request.Request(
        f"{LOOKUP_ENDPOINT}?{query}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return []

    matches = payload.get("matches") or []
    if not isinstance(matches, list):
        return []
    return [match for match in matches if isinstance(match, dict)]


def lookup_url_with_status(url: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return matches and a non-secret external-check status."""
    if not _enabled():
        return [], {"status": "disabled", "message": "Google Safe Browsing is disabled."}
    if not _api_key():
        return [], {"status": "unavailable", "message": "Google Safe Browsing is enabled but has no API key."}

    api_key = _api_key()
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    query = urllib.parse.urlencode({"key": api_key})
    request = urllib.request.Request(
        f"{LOOKUP_ENDPOINT}?{query}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return [], {"status": "unavailable", "message": "Google Safe Browsing lookup is currently unavailable."}

    matches = payload.get("matches") or []
    if not isinstance(matches, list):
        matches = []
    clean_matches = [match for match in matches if isinstance(match, dict)]
    return clean_matches, {"status": "enabled", "message": "Google Safe Browsing lookup completed."}


def get_status() -> dict[str, str]:
    """Return a non-secret status describing external lookup availability."""
    if not _enabled():
        return {"status": "disabled", "message": "Google Safe Browsing is disabled."}
    if not _api_key():
        return {"status": "unavailable", "message": "Google Safe Browsing is enabled but has no API key."}
    return {"status": "enabled", "message": "Google Safe Browsing is enabled."}


def _evidence_for_match(url: str, match: dict[str, Any]) -> dict[str, Any]:
    threat_type = str(match.get("threatType") or "UNKNOWN")
    indicator = f"gsb.{threat_type.lower()}"
    description = _THREAT_DESCRIPTIONS.get(
        threat_type,
        "Google Safe Browsing lists this URL as a known threat.",
    )
    return build_evidence(
        source="google_safe_browsing",
        indicator=indicator,
        severity="high",
        value={"url": url, "threatType": threat_type},
        description=description,
    ).to_dict()


def apply_safe_browsing(url: str, assessment: RiskAssessment) -> RiskAssessment:
    """Bump the heuristic score when Safe Browsing reports a match."""
    matches, threat_status = lookup_url_with_status(url)
    if not matches:
        return RiskAssessment(
            classification=assessment.classification,
            risk_score=assessment.risk_score,
            confidence=None,
            evidence=assessment.evidence,
            ml_probability=assessment.ml_probability,
            heuristic_strength=assessment.heuristic_strength,
            threat_intelligence=threat_status,
        )

    evidence = list(assessment.evidence)
    seen_types: set[str] = set()
    for match in matches:
        threat_type = str(match.get("threatType") or "UNKNOWN")
        if threat_type in seen_types:
            continue
        seen_types.add(threat_type)
        evidence.append(_evidence_for_match(url, match))

    score = min(100, assessment.risk_score + MATCH_WEIGHT)
    return RiskAssessment(
        classification=_classify(score),
        risk_score=score,
        confidence=None,
        evidence=evidence,
        threat_intelligence=threat_status,
    )
