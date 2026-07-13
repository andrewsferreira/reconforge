"""Tests for modules.network.parsers.nmap_parser – NmapParser."""

import textwrap
from pathlib import Path

import pytest

from modules.network.parsers.nmap_parser import NmapParser, NmapHost, NmapPort, NmapResult


@pytest.fixture
def parser():
    return NmapParser()


# ── XML parsing ───────────────────────────────────────────────────

def test_parse_xml_basic(parser, tmp_path):
    xml_content = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun args="nmap -sS 10.10.10.1">
      <scaninfo type="syn" protocol="tcp"/>
      <host>
        <status state="up"/>
        <address addr="10.10.10.1" addrtype="ipv4"/>
        <hostnames><hostname name="target.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.52"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """)
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(xml_content)

    result = parser.parse_xml(xml_file)
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.10.10.1"
    assert host.hostname == "target.local"
    assert len(host.open_ports) == 2
    assert host.open_ports[0].port == 22
    assert host.open_ports[0].product == "OpenSSH"


def test_parse_xml_missing_file(parser, tmp_path):
    result = parser.parse_xml(tmp_path / "missing.xml")
    assert len(result.hosts) == 0
    assert "Error" in result.raw_output


def test_parse_xml_malformed(parser, tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<not valid xml")
    result = parser.parse_xml(bad)
    assert len(result.hosts) == 0


def test_parse_xml_directory_path_does_not_crash(parser, tmp_path):
    """Phase 7-C regression: the exception tuple previously caught
    FileNotFoundError but not the broader OSError, so IsADirectoryError/
    PermissionError (both OSError subclasses, neither FileNotFoundError)
    propagated uncaught out of parse_xml() instead of returning a
    graceful empty result."""
    result = parser.parse_xml(tmp_path)  # a directory, not a file
    assert len(result.hosts) == 0
    assert "Error" in result.raw_output


# ── Text parsing ──────────────────────────────────────────────────

def test_parse_text(parser):
    text = textwrap.dedent("""\
    Nmap scan report for 10.10.10.1
    Host is up (0.040s latency).
    22/tcp  open  ssh     OpenSSH 8.9p1
    80/tcp  open  http    Apache httpd 2.4.52
    443/tcp closed https
    """)
    result = parser.parse_text(text)
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.10.10.1"
    open_ports = host.open_ports
    assert len(open_ports) == 2
    assert open_ports[0].port == 22


def test_parse_text_with_hostname(parser):
    text = "Nmap scan report for dc01.corp.local (10.10.10.1)\nHost is up.\n80/tcp open http\n"
    result = parser.parse_text(text)
    host = result.hosts[0]
    assert host.hostname == "dc01.corp.local"
    assert host.ip == "10.10.10.1"


# ── Vuln checks ───────────────────────────────────────────────────

def test_check_known_vulns(parser):
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=21, service="ftp", product="vsftpd", version="2.3.4"),
    ])
    vulns = parser.check_known_vulns(host)
    assert len(vulns) == 1
    assert vulns[0]["severity"] == "critical"


def test_check_anon_access(parser):
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=21, service="ftp"),
    ])
    findings = parser.check_anonymous_access(host)
    assert len(findings) >= 1


def test_check_anon_access_no_duplicate_when_both_signals_fire(parser):
    """Phase 9-B regression: a port matching both the service-name
    heuristic AND an NSE script anonymous-access indicator must produce
    exactly one finding, not two describing the same condition."""
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=21, service="ftp",
                 scripts={"ftp-anon": "Anonymous FTP login allowed"}),
    ])
    findings = parser.check_anonymous_access(host)
    assert len(findings) == 1
    # NSE script evidence takes priority over the bare heuristic
    assert "ftp-anon" in findings[0]["description"]
    assert findings[0]["evidence"]


def test_check_anon_access_heuristic_only(parser):
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=21, service="ftp"),
    ])
    findings = parser.check_anonymous_access(host)
    assert len(findings) == 1
    assert "may allow anonymous access" in findings[0]["description"]


def test_check_anon_access_script_only(parser):
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=445, service="microsoft-ds",
                 scripts={"smb-enum-shares": "null session access allowed"}),
    ])
    findings = parser.check_anonymous_access(host)
    assert len(findings) == 1
    assert "smb-enum-shares" in findings[0]["description"]


def test_check_weak_configs_unencrypted(parser):
    host = NmapHost(ip="10.0.0.1", ports=[
        NmapPort(port=23, service="telnet"),
    ])
    findings = parser.check_weak_configs(host)
    assert any("Unencrypted" in f["description"] for f in findings)


def test_all_open_ports():
    result = NmapResult(hosts=[
        NmapHost(ip="10.0.0.1", ports=[
            NmapPort(port=22), NmapPort(port=80),
        ]),
        NmapHost(ip="10.0.0.2", ports=[
            NmapPort(port=80), NmapPort(port=443),
        ]),
    ])
    assert result.all_open_ports == [22, 80, 443]
