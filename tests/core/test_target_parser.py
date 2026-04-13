"""Tests for core.target_parser – parse_target."""

import pytest

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
    """A /32 has only 1 address \u2013 num_addresses == 1 so not treated as network."""
    t = parse_target("10.0.0.5/32")
    # Falls through network check (1 addr) and IP check (has /32 suffix),
    # then treated as hostname-like string.
    assert t.is_network is False


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
