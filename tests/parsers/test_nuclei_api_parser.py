"""Tests for modules.api.parsers.nuclei_parser – NucleiApiParser."""

import json

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


def test_null_info_does_not_crash(parser, tmp_path):
    """Phase 7-A regression: entry.get("info", {}) returns None (not {})
    when the JSON literally has "info": null. Previously this raised an
    uncaught AttributeError on info.get(...), aborting the entire file's
    parse from one malformed record."""
    path = tmp_path / "nuclei.jsonl"
    entries = [
        {"template-id": "null-info-template", "info": None,
         "matched-at": "http://target/x"},
        {"template-id": "swagger-api",
         "info": {"name": "Swagger API Exposed", "severity": "medium"},
         "matched-at": "http://target/swagger.json"},
    ]
    path.write_text("\n".join(json.dumps(e) for e in entries))

    result = parser.parse_jsonl(path)

    # The null-info record no longer crashes the parse (info coerces to
    # {}, so the finding gets defaulted fields), and the second, valid
    # record on the next line is still parsed correctly.
    assert len(result.findings) == 2
    assert result.findings[0].template_id == "null-info-template"
    assert result.findings[0].severity == "info"
    assert result.findings[1].template_id == "swagger-api"


def test_non_dict_jsonl_line_skipped(parser, tmp_path):
    """A JSONL line that's valid JSON but not an object (e.g. a bare
    string or number) must be skipped, not crash the whole parse."""
    path = tmp_path / "nuclei.jsonl"
    path.write_text('"just a string"\n42\n' + json.dumps({
        "template-id": "swagger-api",
        "info": {"name": "Swagger API Exposed", "severity": "medium"},
    }))

    result = parser.parse_jsonl(path)

    assert len(result.findings) == 1
    assert result.findings[0].template_id == "swagger-api"


def test_severity_alias_normalized(parser, tmp_path):
    """Phase 7-F: severity now routes through the shared normalize_severity()
    used by modules/web/parsers/nuclei_parser.py, so aliases like
    "critical"/"important"/"moderate" that the old bare SEVERITY_MAP
    didn't recognize now normalize correctly instead of falling through
    to "info"."""
    path = tmp_path / "nuclei.jsonl"
    entries = [
        {"template-id": "t1", "info": {"severity": "important"}},
        {"template-id": "t2", "info": {"severity": "moderate"}},
        {"template-id": "t3", "info": {"severity": "crit"}},
    ]
    path.write_text("\n".join(json.dumps(e) for e in entries))

    result = parser.parse_jsonl(path)
    severities = {f.template_id: f.severity for f in result.findings}

    assert severities["t1"] == "high"
    assert severities["t2"] == "medium"
    assert severities["t3"] == "critical"
