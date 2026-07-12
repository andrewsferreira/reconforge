"""Tests for WebModule._normalise_url — Phase 5-B URL validation wiring."""

import pytest

from core.exceptions import ValidationError
from modules.web.web_module import WebModule


def test_normalise_url_adds_scheme():
    assert WebModule._normalise_url("example.com") == "http://example.com"


def test_normalise_url_strips_trailing_slash():
    assert WebModule._normalise_url("http://example.com/") == "http://example.com"


def test_normalise_url_preserves_https():
    assert WebModule._normalise_url("https://example.com") == "https://example.com"


def test_normalise_url_rejects_embedded_credentials():
    with pytest.raises(ValidationError):
        WebModule._normalise_url("admin:password@example.com")


def test_normalise_url_rejects_control_characters():
    with pytest.raises(ValidationError):
        WebModule._normalise_url("example.com/\r\nSet-Cookie: evil=1")
