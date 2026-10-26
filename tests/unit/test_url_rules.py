from __future__ import annotations

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url
from src.engines.url.rules import (
    at_symbol_rule,
    evaluate_rules,
    http_not_https_rule,
    ip_hostname_rule,
    long_url_rule,
    multiple_subdomains_rule,
    nonstandard_port_rule,
    punycode_rule,
    suspicious_keywords_rule,
)


def _eval(url: str, rule):
    data = normalize_url(url)
    return rule(extract_features(data), data)


def test_ip_hostname_rule_fires() -> None:
    result = _eval("https://192.0.2.1/login", ip_hostname_rule)
    assert result.fired is True
    assert result.weight == 30
    assert result.rule_id == "url.ip_hostname"


def test_ip_hostname_rule_does_not_fire_on_domain() -> None:
    result = _eval("https://example.com/login", ip_hostname_rule)
    assert result.fired is False
    assert result.weight == 0


def test_punycode_rule_fires() -> None:
    result = _eval("https://xn--pple-43d.com/", punycode_rule)
    assert result.fired is True
    assert result.weight == 25


def test_at_symbol_rule_fires() -> None:
    result = _eval("https://user@example.com/path", at_symbol_rule)
    assert result.fired is True
    assert result.weight == 25
    assert result.value == 1


def test_suspicious_keywords_rule_scales_weight() -> None:
    result = _eval("https://example.com/login", suspicious_keywords_rule)
    assert result.fired is True
    assert result.weight == result.value * 5
    assert result.weight >= 5


def test_long_url_rule_fires() -> None:
    result = _eval("https://example.com/" + ("a" * 80), long_url_rule)
    assert result.fired is True
    assert result.weight == 10


def test_multiple_subdomains_rule_fires() -> None:
    result = _eval("https://a.b.c.example.com/", multiple_subdomains_rule)
    assert result.fired is True
    assert result.weight == 10


def test_nonstandard_port_rule_fires() -> None:
    result = _eval("https://example.com:8443/path", nonstandard_port_rule)
    assert result.fired is True
    assert result.weight == 10
    assert result.value == 8443


def test_http_not_https_rule_fires() -> None:
    result = _eval("http://example.com/", http_not_https_rule)
    assert result.fired is True
    assert result.weight == 5


def test_evaluate_rules_only_includes_default_heuristics() -> None:
    data = normalize_url("https://example.com")
    results = evaluate_rules(extract_features(data), data)
    assert [item.rule_id for item in results] == [
        "url.ip_hostname",
        "url.punycode",
        "url.at_symbol",
        "url.suspicious_keywords",
        "url.long_url",
        "url.multiple_subdomains",
        "url.nonstandard_port",
        "url.http_not_https",
    ]
    assert all(item.fired is False for item in results)
