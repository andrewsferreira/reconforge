"""Priority hardening tests for ffuf and nuclei web parsers."""

import json

from modules.web.parsers.ffuf_parser import FfufParser
from modules.web.parsers.nuclei_parser import NucleiParser


def test_ffuf_parser_handles_string_numbers_and_input_variants(tmp_path):
    parser = FfufParser()
    payload = {
        "commandLine": "ffuf -u http://target/FUZZ -w words.txt -json",
        "results": [
            {
                "url": "http://target/admin",
                "status": "403",
                "length": "1234",
                "words": "150",
                "lines": "20",
                "input": {"FUZZ": "admin"},
            },
            {
                "url": "http://target/debug",
                "status": "502",
                "length": 88,
                "words": 9,
                "lines": 1,
                "input": "debug",
            },
        ],
    }
    output = tmp_path / "ffuf.json"
    output.write_text(json.dumps(payload), encoding="utf-8")

    result = parser.parse_json(output)
    assert result.command_line.startswith("ffuf -u")
    assert result.entries[0].status == 403
    assert result.entries[0].length == 1234
    assert result.entries[1].input_word == "debug"
    assert parser.status_to_severity(result.entries[1].status) == "medium"


def test_nuclei_parser_normalizes_mixed_jsonl_shapes(tmp_path):
    parser = NucleiParser()
    lines = [
        {
            "templateID": "cve-test",
            "matched": "http://target/vuln",
            "extracted-results": "admin panel",
            "info": {
                "name": "Test CVE",
                "severity": "moderate",
                "references": "https://example.com/ref",
                "tags": "cve,web,auth",
            },
        },
        {
            "template-id": "xss-test",
            "matched-at": "http://target/search",
            "extracted-results": {"evidence": ["payload reflected"]},
            "info": {
                "name": "Reflected XSS",
                "severity": "HIGH",
                "reference": ["https://owasp.org/www-community/attacks/xss/"],
                "tags": ["xss,web"],
            },
        },
    ]
    output = tmp_path / "nuclei.jsonl"
    output.write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n" + json.dumps(["unexpected-array-entry"]),
        encoding="utf-8",
    )

    result = parser.parse_jsonl(output)
    assert len(result.findings) == 2
    assert result.findings[0].severity == "medium"
    assert result.findings[0].extracted == ["admin panel"]
    assert result.findings[0].tags == ["cve", "web", "auth"]
    assert result.findings[1].severity == "high"
    assert result.findings[1].tags == ["xss", "web"]
    assert "payload reflected" in result.findings[1].extracted
