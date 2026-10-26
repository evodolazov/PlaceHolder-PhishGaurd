"""Named, deterministic URL heuristics for Milestone 0."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.engines.url.features import URLFeatures
from src.engines.url.normalizer import NormalizedURL
from src.explainability.reasons import build_evidence

RuleFn = Callable[[URLFeatures, NormalizedURL], "RuleResult"]


@dataclass(frozen=True)
class RuleResult:
    """Outcome of a single URL heuristic."""

    rule_id: str
    fired: bool
    weight: int
    severity: str
    value: Any
    description: str

    def to_evidence(self) -> dict[str, Any]:
        return build_evidence(
            source="url_rules",
            indicator=self.rule_id,
            severity=self.severity,
            value=self.value,
            description=self.description,
        ).to_dict()


def _result(
    *,
    rule_id: str,
    fired: bool,
    weight: int,
    severity: str,
    value: Any,
    description: str,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        fired=fired,
        weight=weight if fired else 0,
        severity=severity,
        value=value,
        description=description,
    )


def ip_hostname_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    return _result(
        rule_id="url.ip_hostname",
        fired=features.has_ip_address,
        weight=30,
        severity="high",
        value=features.has_ip_address,
        description="IP-based hostnames are common in phishing infrastructure.",
    )


def punycode_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    return _result(
        rule_id="url.punycode",
        fired=features.has_punycode,
        weight=25,
        severity="high",
        value=features.has_punycode,
        description="Punycode disguises lookalike domains.",
    )


def at_symbol_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    fired = features.at_symbol_count > 0
    return _result(
        rule_id="url.at_symbol",
        fired=fired,
        weight=25,
        severity="high",
        value=features.at_symbol_count,
        description="The URL authority contains an @ sign that can hide the true hostname.",
    )


def suspicious_keywords_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    count = features.suspicious_keyword_count
    fired = count > 0
    return _result(
        rule_id="url.suspicious_keywords",
        fired=fired,
        weight=count * 5,
        severity="low",
        value=count,
        description="The URL contains credential-related or urgent-action keywords.",
    )


def long_url_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    fired = features.url_length > 75
    return _result(
        rule_id="url.long_url",
        fired=fired,
        weight=10,
        severity="medium",
        value=features.url_length,
        description="The URL is unusually long for a normal destination.",
    )


def multiple_subdomains_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    fired = features.subdomain_count > 2
    return _result(
        rule_id="url.multiple_subdomains",
        fired=fired,
        weight=10,
        severity="medium",
        value=features.subdomain_count,
        description="Multiple subdomains may be used to disguise or impersonate trusted brands.",
    )


def nonstandard_port_rule(features: URLFeatures, url: NormalizedURL) -> RuleResult:
    fired = features.is_nonstandard_port
    return _result(
        rule_id="url.nonstandard_port",
        fired=fired,
        weight=10,
        severity="medium",
        value=features.port if features.port is not None else url.port,
        description="The URL specifies a non-standard port, which may be used to hide traffic intent.",
    )


def http_not_https_rule(features: URLFeatures, _url: NormalizedURL) -> RuleResult:
    fired = not features.uses_https
    return _result(
        rule_id="url.http_not_https",
        fired=fired,
        weight=5,
        severity="low",
        value=features.uses_https,
        description="The URL does not use HTTPS, which is a weak but meaningful signal.",
    )


DEFAULT_RULES: tuple[RuleFn, ...] = (
    ip_hostname_rule,
    punycode_rule,
    at_symbol_rule,
    suspicious_keywords_rule,
    long_url_rule,
    multiple_subdomains_rule,
    nonstandard_port_rule,
    http_not_https_rule,
)


def evaluate_rules(
    features: URLFeatures,
    normalized_url: NormalizedURL,
    rules: tuple[RuleFn, ...] = DEFAULT_RULES,
) -> list[RuleResult]:
    """Run the registered URL heuristics in order."""
    return [rule(features, normalized_url) for rule in rules]
