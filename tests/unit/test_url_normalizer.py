from __future__ import annotations

from src.engines.url.normalizer import normalize_url, validate_url


def test_normal_https_url() -> None:
    normalized = normalize_url("https://example.com")
    assert normalized.scheme == "https"
    assert normalized.hostname == "example.com"
    assert normalized.normalized_url == "https://example.com/"


def test_http_url_with_uppercase_hostname_and_query_fragment() -> None:
    normalized = normalize_url("http://Example.com/path?x=1#frag")
    assert normalized.scheme == "http"
    assert normalized.hostname == "example.com"
    assert normalized.path == "/path"
    assert normalized.query == "x=1"
    assert normalized.fragment == "frag"


def test_missing_path_is_normalized_to_root() -> None:
    normalized = normalize_url("https://example.com")
    assert normalized.path == "/"


def test_port_is_preserved() -> None:
    normalized = normalize_url("https://example.com:8443/path")
    assert normalized.port == 8443
    assert normalized.normalized_url == "https://example.com:8443/path"


def test_malformed_url_is_rejected() -> None:
    assert validate_url("not a url") is False
    try:
        normalize_url("not a url")
    except ValueError:
        pass
    else:
        raise AssertionError("normalize_url should reject malformed input")


def test_unsupported_protocol_is_rejected() -> None:
    assert validate_url("ftp://example.com") is False
    try:
        normalize_url("ftp://example.com")
    except ValueError:
        pass
    else:
        raise AssertionError("Unsupported protocols should raise ValueError")
