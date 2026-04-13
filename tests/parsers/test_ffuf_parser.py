"""Tests for modules.web.parsers.ffuf_parser – FfufParser."""

import json
from pathlib import Path

import pytest

from modules.web.parsers.ffuf_parser import FfufParser, FfufResult


@pytest.fixture
def parser():
    return FfufParser()


def _write_ffuf_json(tmp_path, results=None):
    data = {
        "commandline": "ffuf -u http://target/FUZZ -w wordlist.txt",
        "results": results or [
            {"url": "http://target/admin", "status": 200, "length": 1234, "words": 56, "lines": 12,
             "input": {"FUZZ": "admin"}},
            {"url": "http://target/login", "status": 302, "length": 0, "words": 0, "lines": 0,
             "input": {"FUZZ": "login"}},
            {"url": "http://target/secret", "status": 403, "length": 277, "words": 20, "lines": 10,
             "input": {"FUZZ": "secret"}},
        ],
    }
    path = tmp_path / "ffuf.json"
    path.write_text(json.dumps(data))
    return path


def test_parse_json_basic(parser, tmp_path):
    path = _write_ffuf_json(tmp_path)
    result = parser.parse_json(path)
    assert len(result.entries) == 3
    assert result.command_line.startswith("ffuf")


def test_parse_json_entry_fields(parser, tmp_path):
    path = _write_ffuf_json(tmp_path)
    result = parser.parse_json(path)
    admin = result.entries[0]
    assert admin.url == "http://target/admin"
    assert admin.status == 200
    assert admin.input_word == "admin"


def test_by_status(parser, tmp_path):
    path = _write_ffuf_json(tmp_path)
    result = parser.parse_json(path)
    by_status = result.by_status
    assert 200 in by_status
    assert 403 in by_status


def test_parse_missing_file(parser, tmp_path):
    result = parser.parse_json(tmp_path / "missing.json")
    assert len(result.entries) == 0


def test_parse_malformed_json(parser, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    result = parser.parse_json(bad)
    assert len(result.entries) == 0


def test_parse_empty_results(parser, tmp_path):
    data = {"commandline": "ffuf -u http://target/FUZZ", "results": []}
    path = tmp_path / "empty.json"
    path.write_text(json.dumps(data))
    result = parser.parse_json(path)
    assert len(result.entries) == 0


def test_status_to_severity():
    assert FfufParser.status_to_severity(500) == "medium"
    assert FfufParser.status_to_severity(403) == "low"
    assert FfufParser.status_to_severity(200) == "info"


def test_status_recommendation():
    assert "authentication" in FfufParser.status_recommendation(401).lower()
    assert "bypass" in FfufParser.status_recommendation(403).lower()
