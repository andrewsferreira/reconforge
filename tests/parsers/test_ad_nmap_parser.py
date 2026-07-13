"""Tests for modules.ad.parsers.nmap_parser – ADNmapParser."""

import textwrap

import pytest

from modules.ad.parsers.nmap_parser import ADNmapParser


@pytest.fixture
def parser():
    return ADNmapParser()


def test_parse_text_smb_signing_on_underscore_continuation_line(parser):
    """Phase 7-B regression: nmap's text output marks the LAST line of a
    multi-line NSE script block with '|_' (no space), not '| '. The old
    regex only matched '| ' continuation lines, silently dropping the
    '|_' line — which is exactly where SMB signing status commonly is."""
    text = textwrap.dedent("""\
        Nmap scan report for dc01.corp.local (10.10.10.1)
        PORT    STATE SERVICE
        445/tcp open  microsoft-ds
        | smb2-security-mode:
        |   3.1.1:
        |_    Message signing enabled but not required

        Nmap done: 1 IP address (1 host up) scanned in 2.00 seconds
    """)

    result = parser.parse_text(text)

    assert result.smb_signing == "enabled_not_required"


def test_parse_text_smb_signing_required_on_underscore_continuation_line(parser):
    text = textwrap.dedent("""\
        Nmap scan report for dc01.corp.local (10.10.10.1)
        PORT    STATE SERVICE
        445/tcp open  microsoft-ds
        | smb2-security-mode:
        |   3.1.1:
        |_    Message signing required
    """)

    result = parser.parse_text(text)

    assert result.smb_signing == "required"


def test_parse_xml_missing_file_returns_empty_result(parser, tmp_path):
    result = parser.parse_xml(tmp_path / "missing.xml")
    assert result.services == []
    assert result.raw == ""


def test_parse_xml_malformed_preserves_raw_for_debugging(parser, tmp_path):
    """Phase 7-E regression: on a malformed-XML parse failure, raw must
    still be populated with the file's actual content so an operator can
    debug what nmap actually produced — previously parse_xml() returned
    a bare ADNmapResult() with raw always empty on this path."""
    bad_xml = tmp_path / "scan.xml"
    bad_xml.write_text("<nmaprun><host><not-closed>")

    result = parser.parse_xml(bad_xml)

    assert result.services == []
    assert "<nmaprun>" in result.raw


def test_parse_xml_valid_populates_raw(parser, tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(textwrap.dedent("""\
        <?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="10.10.10.1" addrtype="ipv4"/>
            <hostnames><hostname name="dc01.corp.local"/></hostnames>
            <ports>
              <port protocol="tcp" portid="445">
                <state state="open"/>
                <service name="microsoft-ds"/>
              </port>
            </ports>
          </host>
        </nmaprun>
    """))

    result = parser.parse_xml(xml_path)

    assert result.target == "10.10.10.1"
    assert "<nmaprun>" in result.raw
    assert len(result.services) == 1
