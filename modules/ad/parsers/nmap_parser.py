"""ReconForge AD - Nmap Output Parser (AD-specific).

Extracts AD-relevant information from nmap NSE script output:
- LDAP RootDSE data
- SMB security mode / signing
- SMB OS discovery
- Kerberos service detection
- Domain controller identification

Author: Andrews Ferreira
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ADServiceInfo:
    """AD service information from nmap scan."""
    port: int = 0
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    state: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class ADNmapResult:
    """AD-specific nmap scan result."""
    target: str = ""
    hostname: str = ""
    services: List[ADServiceInfo] = field(default_factory=list)
    # Extracted AD intelligence
    domain_name: str = ""
    forest_name: str = ""
    dc_hostname: str = ""
    smb_signing: str = ""       # "enabled", "disabled", "required"
    smb_os: str = ""
    ldap_base_dn: str = ""
    kerberos_detected: bool = False
    functional_level: str = ""
    raw: str = ""

    @property
    def has_ldap(self) -> bool:
        return any(s.port in (389, 636, 3268, 3269) and s.state == "open" for s in self.services)

    @property
    def has_smb(self) -> bool:
        return any(s.port in (139, 445) and s.state == "open" for s in self.services)

    @property
    def has_kerberos(self) -> bool:
        return self.kerberos_detected or any(
            s.port == 88 and s.state == "open" for s in self.services
        )

    @property
    def open_ports(self) -> List[int]:
        return [s.port for s in self.services if s.state == "open"]


class ADNmapParser:
    """Parse nmap output for AD-relevant intelligence."""

    # ------------------------------------------------------------------
    # XML parsing
    # ------------------------------------------------------------------

    def parse_xml(self, xml_path: Path) -> ADNmapResult:
        """Parse nmap XML output for AD data."""
        result = ADNmapResult()
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError, OSError):
            return result

        for host_elem in root.findall(".//host"):
            # IP
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    result.target = addr.get("addr", "")

            # Hostname
            hn_elem = host_elem.find(".//hostname")
            if hn_elem is not None:
                result.hostname = hn_elem.get("name", "")

            # Ports
            for port_elem in host_elem.findall(".//port"):
                svc = self._parse_port_xml(port_elem)
                if svc:
                    result.services.append(svc)

        self._extract_ad_intel(result)
        return result

    def _parse_port_xml(self, port_elem: ET.Element) -> Optional[ADServiceInfo]:
        state_elem = port_elem.find("state")
        if state_elem is None:
            return None
        svc = ADServiceInfo(
            port=int(port_elem.get("portid", 0)),
            protocol=port_elem.get("protocol", "tcp"),
            state=state_elem.get("state", ""),
        )
        svc_elem = port_elem.find("service")
        if svc_elem is not None:
            svc.service = svc_elem.get("name", "")
            svc.product = svc_elem.get("product", "")
            svc.version = svc_elem.get("version", "")
        for script in port_elem.findall("script"):
            sid = script.get("id", "")
            if sid:
                svc.scripts[sid] = script.get("output", "")
        return svc

    # ------------------------------------------------------------------
    # Text parsing
    # ------------------------------------------------------------------

    def parse_text(self, text: str) -> ADNmapResult:
        """Parse nmap normal text output."""
        result = ADNmapResult(raw=text)

        # Extract host
        m = re.search(r"Nmap scan report for (\S+)", text)
        if m:
            result.target = m.group(1)

        # Extract ports
        for m in re.finditer(
            r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.+))?",
            text
        ):
            svc = ADServiceInfo(
                port=int(m.group(1)),
                protocol=m.group(2),
                state=m.group(3),
                service=m.group(4),
                version=m.group(5).strip() if m.group(5) else "",
            )
            result.services.append(svc)

        # Extract script output blocks
        for m in re.finditer(
            r"\|\s+(\S+):\s*\n((?:\|\s+.*\n)*)",
            text
        ):
            script_id = m.group(1)
            script_output = m.group(2)
            # Attach to the most recent service
            if result.services:
                result.services[-1].scripts[script_id] = script_output

        self._extract_ad_intel(result)
        return result

    # ------------------------------------------------------------------
    # AD intelligence extraction
    # ------------------------------------------------------------------

    def _extract_ad_intel(self, result: ADNmapResult):
        """Extract AD-specific intelligence from parsed services."""
        for svc in result.services:
            # Kerberos detection
            if svc.port == 88 and svc.state == "open":
                result.kerberos_detected = True

            for script_id, output in svc.scripts.items():
                # LDAP RootDSE
                if "ldap-rootdse" in script_id:
                    self._parse_ldap_rootdse_script(output, result)

                # SMB security mode
                if "smb-security-mode" in script_id or "smb2-security-mode" in script_id:
                    self._parse_smb_security(output, result)

                # SMB OS discovery
                if "smb-os-discovery" in script_id:
                    self._parse_smb_os(output, result)

    def _parse_ldap_rootdse_script(self, output: str, result: ADNmapResult):
        """Extract domain info from ldap-rootdse NSE script."""
        m = re.search(r"rootDomainNamingContext:\s*(\S+)", output, re.I)
        if m:
            result.forest_name = m.group(1)

        m = re.search(r"defaultNamingContext:\s*(\S+)", output, re.I)
        if m:
            result.ldap_base_dn = m.group(1)
            # Derive domain name
            parts = []
            for dc in re.findall(r"DC=([^,]+)", m.group(1), re.I):
                parts.append(dc)
            if parts:
                result.domain_name = ".".join(parts)

        m = re.search(r"dnsHostName:\s*(\S+)", output, re.I)
        if m:
            result.dc_hostname = m.group(1)

        m = re.search(r"domainFunctionality:\s*(\d+)", output, re.I)
        if m:
            result.functional_level = self._fl_to_str(m.group(1))

    @staticmethod
    def _parse_smb_security(output: str, result: ADNmapResult):
        """Extract SMB signing status from NSE script output."""
        lower = output.lower()
        if "signing enabled but not required" in lower:
            result.smb_signing = "enabled_not_required"
        elif "signing required" in lower or "message_signing: required" in lower:
            result.smb_signing = "required"
        elif "signing disabled" in lower or "message_signing: disabled" in lower:
            result.smb_signing = "disabled"
        elif "signing enabled" in lower:
            result.smb_signing = "enabled"

    @staticmethod
    def _parse_smb_os(output: str, result: ADNmapResult):
        """Extract OS/domain info from smb-os-discovery."""
        m = re.search(r"OS:\s*(.+)", output)
        if m:
            result.smb_os = m.group(1).strip()

        m = re.search(r"Domain name:\s*(\S+)", output, re.I)
        if m and not result.domain_name:
            result.domain_name = m.group(1)

        m = re.search(r"FQDN:\s*(\S+)", output, re.I)
        if m and not result.dc_hostname:
            result.dc_hostname = m.group(1)

        m = re.search(r"Forest name:\s*(\S+)", output, re.I)
        if m and not result.forest_name:
            result.forest_name = m.group(1)

    @staticmethod
    def _fl_to_str(level: str) -> str:
        return {
            "0": "Windows 2000",
            "1": "Windows Server 2003 Interim",
            "2": "Windows Server 2003",
            "3": "Windows Server 2008",
            "4": "Windows Server 2008 R2",
            "5": "Windows Server 2012",
            "6": "Windows Server 2012 R2",
            "7": "Windows Server 2016",
        }.get(level, f"Level {level}")
