"""Tests for modules.api.parsers.arjun_parser – ArjunParser."""

import json

import pytest

from modules.api.parsers.arjun_parser import ArjunParser


@pytest.fixture
def parser():
    return ArjunParser()


def _write_url_format(tmp_path, url="http://target/api", params=None):
    """Write Arjun JSON in standard {url: [params]} format."""
    if params is None:
        params = ["id", "name", "token", "page", "password"]
    data = {url: params}
    path = tmp_path / "arjun.json"
    path.write_text(json.dumps(data))
    return path


def _write_method_grouped(tmp_path, url="http://target/api"):
    """Write Arjun JSON with method-grouped params: {url: {GET: [...], POST: [...]}}."""
    data = {
        url: {
            "GET": ["id", "search", "api_key"],
            "POST": ["username", "password", "secret"],
        }
    }
    path = tmp_path / "arjun_grouped.json"
    path.write_text(json.dumps(data))
    return path


def test_parse_url_format(parser, tmp_path):
    path = _write_url_format(tmp_path)
    result = parser.parse_json(path)
    assert len(result.params) == 5
    names = result.param_names
    assert "id" in names
    assert "password" in names


def test_parse_method_grouped(parser, tmp_path):
    path = _write_method_grouped(tmp_path)
    result = parser.parse_json(path)
    names = result.param_names
    assert "id" in names
    assert "password" in names
    assert "secret" in names


def test_sensitive_params(parser, tmp_path):
    path = _write_url_format(
        tmp_path, params=["id", "name", "password", "api_key", "secret_token"]
    )
    result = parser.parse_json(path)
    sensitive = result.sensitive_params
    assert len(sensitive) >= 2
    sensitive_names = [p.name for p in sensitive]
    assert "password" in sensitive_names


def test_missing_file(parser, tmp_path):
    result = parser.parse_json(tmp_path / "missing.json")
    assert len(result.params) == 0


def test_malformed_json(parser, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    result = parser.parse_json(bad)
    assert len(result.params) == 0


def test_empty_params(parser, tmp_path):
    path = _write_url_format(tmp_path, params=[])
    result = parser.parse_json(path)
    assert len(result.params) == 0


def test_param_to_severity():
    assert ArjunParser.param_to_severity("password") == "high"
    assert ArjunParser.param_to_severity("id") == "medium"
    assert ArjunParser.param_to_severity("page") == "low"


def test_urls_scanned(parser, tmp_path):
    path = _write_url_format(tmp_path, url="http://target/api/v2")
    result = parser.parse_json(path)
    assert "http://target/api/v2" in result.urls_scanned
