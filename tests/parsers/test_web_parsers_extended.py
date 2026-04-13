"""Additional real-world style tests for web parsers."""

import json

from modules.web.parsers.nikto_parser import NiktoParser
from modules.web.parsers.wafw00f_parser import Wafw00fParser
from modules.web.parsers.wpscan_parser import WpscanParser


def test_nikto_text_parses_target_metadata_and_filters_noise():
    parser = NiktoParser()
    text = """
- Nikto v2.5.0
- Target IP:          10.10.10.10
- Target Hostname:    app.local
- Target Port:        80
+ Server: nginx
+ /admin/: Directory indexing found.
+ OSVDB-3092: /backup.zip: This might be sensitive
+ Retrieved x-powered-by header: PHP/8.2.1
+ /search.php?q=: Possible XSS injection point
"""
    result = parser.parse_text(text)

    assert result.target_ip == "10.10.10.10"
    assert result.target_hostname == "app.local"
    assert result.target_port == "80"
    assert len(result.findings) == 3
    assert result.findings[1].osvdb_id == "3092"
    assert result.findings[2].severity in ("high", "critical")


def test_wpscan_json_extracts_references_and_deduplicates_users(tmp_path):
    parser = WpscanParser()
    payload = {
        "version": {"number": "6.5.2", "status": "latest"},
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.8"},
                "vulnerabilities": [{
                    "title": "Contact Form 7 XSS vulnerability",
                    "fixed_in": "5.9",
                    "references": {
                        "url": ["https://example.com/advisory"],
                        "cve": ["2024-9999"],
                    },
                }],
            }
        },
        "users": [{"username": "admin"}, {"username": "admin"}, "editor"],
    }
    output = tmp_path / "wpscan.json"
    output.write_text(json.dumps(payload), encoding="utf-8")

    result = parser.parse_json(output)
    assert result.wp_version == "6.5.2"
    assert result.plugins["contact-form-7"] == "5.8"
    assert set(result.users) == {"admin", "editor"}
    assert result.vulnerabilities[0].severity == "high"
    assert "https://example.com/advisory" in result.vulnerabilities[0].references
    assert "CVE-2024-9999" in result.vulnerabilities[0].references


def test_wpscan_text_extracts_version_and_classifies_findings():
    parser = WpscanParser()
    text = """
[i] WordPress version 6.4 identified
[!] Authentication Bypass in plugin xyz
[!] Information disclosure via debug.log
"""
    result = parser.parse_text(text)
    assert result.wp_version == "6.4"
    severities = [v.severity for v in result.vulnerabilities]
    assert "high" in severities
    assert "medium" in severities


def test_wpscan_text_filters_known_noise_lines():
    parser = WpscanParser()
    text = """
[!] No WPScan API Token given, as a result vulnerability data has not been output.
[i] WordPress version 6.4 identified
[!] Authentication Bypass in plugin xyz
"""
    result = parser.parse_text(text)
    assert result.wp_version == "6.4"
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].severity == "high"


def test_wafw00f_parser_handles_common_wording_and_deduplicates():
    parser = Wafw00fParser()
    text = """
[+] The site http://target.local is behind a Cloudflare WAF (Cloudflare)
[+] The site http://target.local is behind a Cloudflare WAF (Cloudflare)
[!] No WAF detected by the generic detection engine
"""
    result = parser.parse_text(text)
    assert result.waf_detected is True
    assert len(result.detections) == 1
    assert result.detections[0].product == "Cloudflare"
