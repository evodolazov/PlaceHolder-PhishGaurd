"""Stable feature schema used across training and inference."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

FEATURE_SCHEMA_VERSION = "url-feature-schema-v1"

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "question_mark_count",
    "equals_count",
    "ampersand_count",
    "at_symbol_count",
    "digit_count",
    "special_character_count",
    "subdomain_count",
    "has_ip_address",
    "has_punycode",
    "has_port",
    "is_nonstandard_port",
    "hostname_contains_digits",
    "uses_https",
    "suspicious_keyword_count",
    "port",
]


@dataclass(frozen=True)
class FeatureSchema:
    """Describe the URL feature schema used by the ML pipeline."""

    version: str = FEATURE_SCHEMA_VERSION
    feature_names: tuple[str, ...] = tuple(FEATURE_COLUMNS)


def normalize_feature_map(raw_features: Mapping[str, Any]) -> dict[str, float | int | bool | None]:
    """Normalize the feature map to the schema and preserve explicit missing values."""
    normalized: dict[str, float | int | bool | None] = {}
    for name in FEATURE_COLUMNS:
        value = raw_features.get(name)
        if value is None:
            normalized[name] = 0
        elif isinstance(value, bool):
            normalized[name] = value
        elif isinstance(value, (int, float)):
            normalized[name] = value
        else:
            raise ValueError(f"Feature '{name}' must be numeric or boolean, got {type(value).__name__}")
    return normalized
