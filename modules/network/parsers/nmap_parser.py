"""ReconForge Nmap Parser - Parse nmap XML and text output.

Extracts:
- Live hosts
- Open ports with service info
- OS detection results
- NSE script output
- Vulnerability findings
- Service banners
"""

import xml.etree.ElementTree as ET  # nosec B405 - only used for type hints (Element, ParseError); parsing itself goes through defusedxml below
import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class NmapPort:
    """A single port result."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)
    cpe: str = ""

    @property
    def display(self) -> str:
        parts = [f"{self.port}/{self.protocol}"]
        if self.service:
            parts.append(self.service)
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class NmapHost:
    """A single host result."""
    ip: str
    hostname: str = ""
    state: str = "up"
    os_matches: List[str] = field(default_factory=list)
    ports: List[NmapPort] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""

    @property
    def open_ports(self) -> List[NmapPort]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def port_list(self) -> str:
        """Comma-separated list of open port numbers."""
        return ",".join(str(p.port) for p in self.open_ports)


@dataclass
class NmapResult:
    """Complete nmap scan result."""
    hosts: List[NmapHost] = field(default_factory=list)
    scan_info: Dict[str, str] = field(default_factory=dict)
    raw_output: str = ""

    @property
    def live_hosts(self) -> List[NmapHost]:
        return [h for h in self.hosts if h.state == "up"]

    @property
    def all_open_ports(self) -> List[int]:
        """All unique open port numbers across all hosts."""
        ports = set()
        for h in self.live_hosts:
            for p in h.open_ports:
                ports.add(p.port)
        return sorted(ports)


class NmapParser:
    """Parse nmap XML and text output into structured data."""

    # Known vulnerable service versions (simplified - in production, use a CVE database)
    KNOWN_VULNS = {
        "vsftpd 2.3.4": {
            "severity": "critical",
            "description": "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        },
        "ProFTPD 1.3.5": {
            "severity": "high",
            "description": "ProFTPD 1.3.5 mod_copy RCE (CVE-2015-3306)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        },
        "Apache httpd 2.4.49": {
            "severity": "critical",
            "description": "Apache 2.4.49 Path Traversal/RCE (CVE-2021-41773)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        "Apache httpd 2.4.50": {
            "severity": "critical",
            "description": "Apache 2.4.50 Path Traversal/RCE (CVE-2021-42013)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        },
        "OpenSSH 7.2p2": {
            "severity": "medium",
            "description": "OpenSSH 7.2p2 username enumeration (CVE-2016-6210)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2016-6210",
        },
        "Samba 3.0.20": {
            "severity": "critical",
            "description": "Samba 3.0.20 username map script RCE (CVE-2007-2447)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2007-2447",
        },
        "Microsoft IIS httpd 6.0": {
            "severity": "critical",
            "description": "IIS 6.0 WebDAV RCE (CVE-2017-7269)",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
        },
    }

    # Services that commonly allow anonymous access
    ANON_SERVICES = {"ftp", "smb", "nfs", "ldap", "redis", "mongodb", "elasticsearch"}

    def parse_xml(self, xml_path: Path) -> NmapResult:
        """Parse nmap XML output file.

        Args:
            xml_path: Path to nmap XML output.

        Returns:
            NmapResult with structured scan data.
        """
        result = NmapResult()

        try:
            tree = DefusedET.parse(xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError, OSError, DefusedXmlException) as e:
            result.raw_output = f"Error parsing XML: {e}"
            return result

        # Scan info
        if root.get("args"):
            result.scan_info["command"] = root.get("args", "")
        scaninfo = root.find(".//scaninfo")
        if scaninfo is not None:
            result.scan_info["type"] = scaninfo.get("type", "")
            result.scan_info["protocol"] = scaninfo.get("protocol", "")

        # Parse hosts
        for host_elem in root.findall(".//host"):
            host = self._parse_host(host_elem)
            if host:
                result.hosts.append(host)

        return result

    def parse_text(self, text: str) -> NmapResult:
        """Parse nmap normal text output (fallback when XML isn't available).

        Args:
            text: Nmap text output string.

        Returns:
            NmapResult with parsed data.
        """
        result = NmapResult(raw_output=text)

        # Extract hosts from ping sweep
        for match in re.finditer(
            r"Nmap scan report for ([^\n]+)",
            text
        ):
            host_str = match.group(1).strip()
            # Format: "hostname (1.2.3.4)" or just "1.2.3.4"
            ip_in_parens = re.search(r"\(([\d.]+)\)$", host_str)
            if ip_in_parens:
                ip = ip_in_parens.group(1)
                hostname = host_str[:ip_in_parens.start()].strip()
            else:
                ip = host_str
                hostname = ""

            host = NmapHost(ip=ip, hostname=hostname)

            # Check if host is up
            if "Host is up" in text[match.end():match.end() + 200]:
                host.state = "up"
            else:
                host.state = "down"
                continue

            # Extract ports for this host
            host_section = text[match.end():]
            next_host = re.search(r"Nmap scan report for", host_section)
            if next_host:
                host_section = host_section[:next_host.start()]

            for port_match in re.finditer(
                r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?",
                host_section
            ):
                port = NmapPort(
                    port=int(port_match.group(1)),
                    protocol=port_match.group(2),
                    state=port_match.group(3),
                    service=port_match.group(4),
                    version=port_match.group(5).strip() if port_match.group(5) else "",
                )
                host.ports.append(port)

            result.hosts.append(host)

        return result

    def _parse_host(self, host_elem: ET.Element) -> Optional[NmapHost]:
        """Parse a single host element from XML."""
        # Get host status
        status = host_elem.find("status")
        if status is None:
            return None

        state = status.get("state", "down")

        # Get IP address
        ip = ""
        mac = ""
        vendor = ""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        if not ip:
            return None

        # Get hostname
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        host = NmapHost(
            ip=ip, hostname=hostname, state=state,
            mac=mac, vendor=vendor
        )

        # Parse ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = self._parse_port(port_elem)
                if port:
                    host.ports.append(port)

        # Parse OS matches
        for osmatch in host_elem.findall(".//osmatch"):
            name = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "")
            if name:
                host.os_matches.append(f"{name} ({accuracy}%)")

        return host

    def _parse_port(self, port_elem: ET.Element) -> Optional[NmapPort]:
        """Parse a single port element from XML."""
        state_elem = port_elem.find("state")
        if state_elem is None:
            return None

        port = NmapPort(
            port=int(port_elem.get("portid", 0)),
            protocol=port_elem.get("protocol", "tcp"),
            state=state_elem.get("state", "unknown"),
        )

        # Service info
        service_elem = port_elem.find("service")
        if service_elem is not None:
            port.service = service_elem.get("name", "")
            port.product = service_elem.get("product", "")
            port.version = service_elem.get("version", "")
            port.extra_info = service_elem.get("extrainfo", "")
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None and cpe_elem.text:
                port.cpe = cpe_elem.text

        # Script output
        for script in port_elem.findall("script"):
            script_id = script.get("id", "")
            script_output = script.get("output", "")
            if script_id:
                port.scripts[script_id] = script_output

        return port

    def check_known_vulns(self, host: NmapHost) -> List[Dict]:
        """Check host services against known vulnerable versions.

        Args:
            host: NmapHost to check.

        Returns:
            List of vulnerability findings.
        """
        vulns = []
        for port in host.open_ports:
            service_str = f"{port.product} {port.version}".strip()
            for vuln_sig, vuln_info in self.KNOWN_VULNS.items():
                if vuln_sig.lower() in service_str.lower():
                    vulns.append({
                        "port": port.port,
                        "service": service_str,
                        "severity": vuln_info["severity"],
                        "description": vuln_info["description"],
                        "reference": vuln_info["reference"],
                    })
        return vulns

    def check_anonymous_access(self, host: NmapHost) -> List[Dict]:
        """Check for services that may allow anonymous access.

        A port is reported at most once, even when both the service-name
        heuristic and an NSE script both indicate anonymous access — these
        two signals used to be appended independently, producing two
        separate findings describing the same underlying condition for
        one port. NSE script evidence (a concrete indicator string) takes
        priority over the bare service-name heuristic when both fire.

        Args:
            host: NmapHost to check.

        Returns:
            List of anonymous access findings, at most one per port.
        """
        findings = []
        for port in host.open_ports:
            service_name_match = port.service in self.ANON_SERVICES
            script_evidence = None
            script_id_matched = ""

            for script_id, output in port.scripts.items():
                if any(indicator in output.lower() for indicator in
                       ["anonymous", "anonymous login", "ftp-anon", "null session"]):
                    script_evidence = output[:500]
                    script_id_matched = script_id
                    break

            if not service_name_match and script_evidence is None:
                continue

            if script_evidence is not None:
                findings.append({
                    "port": port.port,
                    "service": port.service,
                    "description": f"Anonymous access detected via {script_id_matched}",
                    "evidence": script_evidence,
                })
            else:
                findings.append({
                    "port": port.port,
                    "service": port.service,
                    "description": f"{port.service} on port {port.port} may allow anonymous access",
                })
        return findings

    def check_weak_configs(self, host: NmapHost) -> List[Dict]:
        """Check for weak service configurations.

        Args:
            host: NmapHost to check.

        Returns:
            List of weak configuration findings.
        """
        findings = []
        for port in host.open_ports:
            # Check for SMB signing disabled
            for script_id, output in port.scripts.items():
                if "smb-security-mode" in script_id:
                    if "message_signing: disabled" in output.lower():
                        findings.append({
                            "port": port.port,
                            "severity": "medium",
                            "description": "SMB message signing is disabled",
                            "evidence": output[:300],
                            "recommendation": "Enable SMB signing to prevent relay attacks",
                        })

                # Check for outdated SSL/TLS
                if "ssl" in script_id.lower():
                    for weak in ["sslv2", "sslv3", "tlsv1.0"]:
                        if weak in output.lower():
                            findings.append({
                                "port": port.port,
                                "severity": "medium",
                                "description": f"Weak SSL/TLS protocol supported: {weak.upper()}",
                                "evidence": output[:300],
                                "recommendation": "Disable outdated SSL/TLS protocols",
                            })

            # Check for unencrypted services
            if port.service in ("telnet", "ftp", "pop3", "imap") and port.port not in (990, 993, 995):
                findings.append({
                    "port": port.port,
                    "severity": "low",
                    "description": f"Unencrypted service: {port.service} on port {port.port}",
                    "recommendation": f"Use encrypted alternative for {port.service}",
                })

        return findings

    def extract_script_vulns(self, host: NmapHost) -> List[Dict]:
        """Extract vulnerability findings from NSE script output.

        Args:
            host: NmapHost to check.

        Returns:
            List of vulnerability findings from scripts.
        """
        vulns = []
        for port in host.open_ports:
            for script_id, output in port.scripts.items():
                if "vuln" in script_id.lower():
                    # Parse NSE vuln script output
                    if "VULNERABLE" in output:
                        # Extract CVE if present
                        cves = re.findall(r"CVE-\d{4}-\d+", output)
                        vulns.append({
                            "port": port.port,
                            "script": script_id,
                            "severity": "high",
                            "description": f"Vulnerability detected by {script_id}",
                            "evidence": output[:500],
                            "cves": cves,
                        })
        return vulns
