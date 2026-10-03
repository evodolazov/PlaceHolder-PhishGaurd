from __future__ import annotations

from src.engines.url.features import extract_features
from src.engines.url.normalizer import normalize_url


def test_extract_normal_domain_features() -> None:
    data = normalize_url("https://example.com/path")
    features = extract_features(data)
    assert features.uses_https is True
    assert features.suspicious_keyword_count == 0
    assert features.subdomain_count == 0


def test_ip_address_url_features() -> None:
    data = normalize_url("https://192.168.0.1/login")
    features = extract_features(data)
    assert features.has_ip_address is True
    assert features.suspicious_keyword_count >= 1


def test_punycode_and_keyword_detection() -> None:
    data = normalize_url("https://xn--pple-43d.com/login?verify=1")
    features = extract_features(data)
    assert features.has_punycode is True
    assert features.suspicious_keyword_count >= 1


def test_multiple_subdomains_and_userinfo_at_symbol() -> None:
    data = normalize_url("https://user@secure.login.example.com/path")
    features = extract_features(data)
    assert features.subdomain_count >= 2
    assert features.at_symbol_count == 1


def test_long_url_detection() -> None:
    long_url = "https://example.com/" + ("a" * 80)
    data = normalize_url(long_url)
    features = extract_features(data)
    assert features.url_length > 75
