"""Tests for core.validators – input validation helpers."""

import pytest

from core.exceptions import ValidationError
from core.validators import (
    parse_port_list,
    validate_cidr,
    validate_domain,
    validate_hostname,
    validate_ip,
    validate_port,
    validate_port_range,
    validate_target,
    validate_url,
)

# ── validate_ip ─────────────────────────────────────────────────

def test_validate_ip_valid_v4():
    assert validate_ip("192.168.1.1") == "192.168.1.1"


def test_validate_ip_valid_v6():
    assert validate_ip("::1") == "::1"


def test_validate_ip_strips_whitespace():
    assert validate_ip("  10.0.0.1  ") == "10.0.0.1"


def test_validate_ip_rejects_hostname():
    with pytest.raises(ValidationError):
        validate_ip("not-an-ip")


def test_validate_ip_rejects_cidr():
    with pytest.raises(ValidationError):
        validate_ip("10.0.0.0/24")


# ── validate_cidr ───────────────────────────────────────────────

def test_validate_cidr_valid():
    assert validate_cidr("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_cidr_non_strict():
    # 10.0.0.5/24 is accepted as non-strict and normalised
    result = validate_cidr("10.0.0.5/24")
    assert result == "10.0.0.0/24"


def test_validate_cidr_rejects_garbage():
    with pytest.raises(ValidationError):
        validate_cidr("not-a-cidr")


# ── validate_hostname ───────────────────────────────────────────

def test_validate_hostname_simple():
    assert validate_hostname("dc01.corp.local") == "dc01.corp.local"


def test_validate_hostname_single_label():
    assert validate_hostname("localhost") == "localhost"


def test_validate_hostname_rejects_empty():
    with pytest.raises(ValidationError):
        validate_hostname("")


def test_validate_hostname_rejects_spaces():
    with pytest.raises(ValidationError):
        validate_hostname("bad host")


# ── validate_target ─────────────────────────────────────────────

def test_validate_target_ip():
    assert validate_target("192.168.1.1") == "192.168.1.1"


def test_validate_target_cidr():
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_target_hostname():
    assert validate_target("dc01.corp.local") == "dc01.corp.local"


def test_validate_target_url():
    result = validate_target("https://example.com")
    assert "example.com" in result


def test_validate_target_rejects_empty():
    with pytest.raises(ValidationError):
        validate_target("")


# ── validate_port ───────────────────────────────────────────────

def test_validate_port_int():
    assert validate_port(80) == 80


def test_validate_port_string():
    assert validate_port("443") == 443


def test_validate_port_min_max():
    assert validate_port(1) == 1
    assert validate_port(65535) == 65535


def test_validate_port_rejects_zero():
    with pytest.raises(ValidationError):
        validate_port(0)


def test_validate_port_rejects_negative():
    with pytest.raises(ValidationError):
        validate_port(-1)


def test_validate_port_rejects_too_high():
    with pytest.raises(ValidationError):
        validate_port(65536)


# ── validate_port_range ─────────────────────────────────────────

def test_validate_port_range_single():
    assert validate_port_range("80") == "80"


def test_validate_port_range_range():
    assert validate_port_range("80-443") == "80-443"


def test_validate_port_range_rejects_inverted():
    with pytest.raises(ValidationError):
        validate_port_range("443-80")


# ── parse_port_list ─────────────────────────────────────────────

def test_parse_port_list_simple():
    assert parse_port_list("80,443") == [80, 443]


def test_parse_port_list_range():
    result = parse_port_list("20-22")
    assert result == [20, 21, 22]


def test_parse_port_list_mixed():
    result = parse_port_list("22,80-82,443")
    assert result == [22, 80, 81, 82, 443]


def test_parse_port_list_dedup_sorted():
    result = parse_port_list("443,80,443")
    assert result == [80, 443]


# ── validate_url ────────────────────────────────────────────────

def test_validate_url_http():
    assert validate_url("http://example.com") == "http://example.com"


def test_validate_url_https():
    assert validate_url("https://example.com/path") == "https://example.com/path"


def test_validate_url_rejects_no_scheme():
    with pytest.raises(ValidationError):
        validate_url("example.com")


def test_validate_url_rejects_embedded_credentials():
    with pytest.raises(ValidationError, match="userinfo"):
        validate_url("http://admin:password@example.com")


def test_validate_url_rejects_newline():
    with pytest.raises(ValidationError, match="control"):
        validate_url("http://example.com/\nSet-Cookie: evil=1")


def test_validate_url_rejects_null_byte():
    with pytest.raises(ValidationError, match="control"):
        validate_url("http://example.com/\x00.txt")


def test_validate_url_rejects_excessive_length():
    with pytest.raises(ValidationError, match="length"):
        validate_url("http://example.com/" + "a" * 3000)


def test_validate_url_rejects_missing_host():
    with pytest.raises(ValidationError):
        validate_url("http://")


# ── validate_domain ─────────────────────────────────────────────

def test_validate_domain_simple():
    assert validate_domain("corp.local") == "corp.local"


def test_validate_domain_subdomain():
    assert validate_domain("sub.corp.local") == "sub.corp.local"


def test_validate_domain_rejects_empty():
    with pytest.raises(ValidationError):
        validate_domain("")
