"""Tests for modules.api.parsers.nuclei_parser – NucleiApiParser."""

import json
from pathlib import Path

import pytest

from modules.api.parsers.nuclei_parser import NucleiApiParser


@pytest.fixture
def parser():
    return NucleiApiParser()


def _write_jsonl(tmp_path, entries=None):
    """Write a JSONL nuclei output file."""
    entries = entries or [
        {
            "template-id": "swagger-api",
            "info": {"name": "Swagger API Exposed", "severity": "medium",
                     "tags": ["api", "swagger"]},
            "matched-at": "http://target/swagger.json",
            "host": "http://target",
        },
        {
            "template-id": "jwt-none-alg",
            "info": {"name": "JWT None Algorithm", "severity": "critical",
                     "tags": ["jwt", "token"]},
            "matched-at": "http://target/api/auth",
            "host": "http://target",
        },
        {
            "template-id": "xss-reflected",
            "info": {"name": "XSS Reflected", "severity": "high",
                     "tags": ["xss"]},
            "matched-at": "http://target/page",
            "host": "http://target",
        },
    ]
    path = tmp_path / "nuclei.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries))
    return path


def test_parse_jsonl(parser, tmp_path):
    path = _write_jsonl(tmp_path)
    result = parser.parse_jsonl(path)
    assert len(result.findings) == 3


def test_api_specific_filter(parser, tmp_path):
    path = _write_jsonl(tmp_path)
    result = parser.parse_jsonl(path)
    api_specific = result.api_specific
    # swagger-api and jwt-none-alg have api/swagger/jwt/token tags
    assert len(api_specific) >= 2
    template_ids = [e.template_id for e in api_specific]
    assert "swagger-api" in template_ids
    assert "jwt-none-alg" in template_ids


def test_severity_mapping(parser, tmp_path):
    path = _write_jsonl(tmp_path)
    result = parser.parse_jsonl(path)
    by_sev = result.by_severity
    assert "critical" in by_sev
    assert "medium" in by_sev


def test_missing_file(parser, tmp_path):
    result = parser.parse_jsonl(tmp_path / "missing.jsonl")
    assert len(result.findings) == 0


def test_malformed_jsonl(parser, tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not valid\n{also bad")
    result = parser.parse_jsonl(bad)
    assert len(result.findings) == 0


def test_empty_file(parser, tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    result = parser.parse_jsonl(empty)
    assert len(result.findings) == 0
