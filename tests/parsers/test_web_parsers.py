"""Focused tests for web parser robustness improvements."""

import json

from modules.web.parsers.gobuster_parser import GobusterParser
from modules.web.parsers.whatweb_parser import WhatwebParser


def test_whatweb_parse_text_ignores_url_token_and_extracts_plugins():
    parser = WhatwebParser()
    text = (
        "http://10.10.10.10 [200 OK] Country[RESERVED][ZZ], "
        "HTTPServer[nginx/1.22.1], WordPress[6.5.2], JQuery[3.7.1]"
    )
    result = parser.parse_text(text)

    names = [t.name for t in result.technologies]
    assert "HTTPServer" in names
    assert "WordPress" in names
    assert "JQuery" in names
    assert "http://10.10.10.10" not in names

    categories = {t.name: t.category for t in result.technologies}
    assert categories["HTTPServer"] == "server"
    assert categories["WordPress"] == "cms"


def test_whatweb_parse_json_httpserver_classified_as_server(tmp_path):
    parser = WhatwebParser()
    payload = [{
        "target": "http://target",
        "plugins": {
            "HTTPServer": {"string": ["Apache"]},
            "X-Powered-By": {"string": ["PHP/8.2"]},
        },
    }]
    output = tmp_path / "whatweb.json"
    output.write_text(json.dumps(payload), encoding="utf-8")

    result = parser.parse_json(output)
    categories = {t.name: t.category for t in result.technologies}
    assert categories["HTTPServer"] == "server"
    assert categories["X-Powered-By"] == "header"


def test_gobuster_parser_supports_multiple_output_variants():
    parser = GobusterParser()
    text = """
/admin               (Status: 301) [Size: 0] [--> http://10.10.10.10/admin/]
/api                 [Status: 200] [Length: 123]
/health              [Status: 204]
"""
    result = parser.parse_text(text, base_url="http://10.10.10.10")
    by_path = {e.path: e for e in result.entries}

    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 0
    assert by_path["/api"].status == 200
    assert by_path["/api"].size == 123
    assert by_path["/health"].status == 204
    assert by_path["/health"].size == 0
