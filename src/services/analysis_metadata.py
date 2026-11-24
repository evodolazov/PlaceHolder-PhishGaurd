"""Metadata stored alongside analysis features without changing the schema."""

from __future__ import annotations

from typing import Any


_THREAT_STATUS_KEY = "_phishguard_threat_intelligence"
_UNKNOWN_THREAT_STATUS = {
    "status": "unknown",
    "match_found": None,
    "message": "Threat-intelligence status was not recorded for this analysis.",
}


def features_with_threat_status(
    features: dict[str, Any],
    status: dict[str, Any],
) -> dict[str, Any]:
    return {**features, _THREAT_STATUS_KEY: dict(status)}


def features_without_threat_status(
    features: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(features, dict):
        return {}, dict(_UNKNOWN_THREAT_STATUS)

    visible_features = dict(features)
    status = visible_features.pop(_THREAT_STATUS_KEY, None)
    if (
        not isinstance(status, dict)
        or not isinstance(status.get("status"), str)
        or status.get("status") not in {"disabled", "enabled", "unavailable", "unknown"}
        or (
            status.get("match_found") is not None
            and not isinstance(status.get("match_found"), bool)
        )
        or (status.get("status") != "enabled" and status.get("match_found") is not None)
        or not isinstance(status.get("message"), str)
    ):
        return visible_features, dict(_UNKNOWN_THREAT_STATUS)
    return visible_features, status
