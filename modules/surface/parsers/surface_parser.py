"""ReconForge - Surface Module Parser

Author: Andrews Ferreira

Parses nmap XML/text output and httpx JSON output for attack-surface
mapping. Extracts open ports, services, versions, and HTTP metadata.
"""

import json
import xml.etree.ElementTree as ET  # nosec B405 - only used for type hints (Element, ParseError); parsing itself goes through defusedxml below
import defusedxml.ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PortInfo:
    """Represents a discovered open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    product: str = ""
    banner: str = ""
    confidence: str = "medium"


@dataclass
class ServiceInfo:
    """Represents a detected HTTP service."""
    url: str = ""
    status_code: int = 0
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    content_length: int = 0
    web_server: str = ""


@dataclass
class SurfaceParseResult:
    """Combined parsing results for attack-surface data."""
    ports: List[PortInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    raw_output: str = ""


class SurfaceParser:
    """Parser for nmap and httpx output in the surface module."""

    def parse_nmap_xml(self, xml_path: Path) -> SurfaceParseResult:
        """Parse nmap XML output for open ports and services.

        Args:
            xml_path: Path to nmap XML output file.

        Returns:
            SurfaceParseResult with discovered ports.
        """
        result = SurfaceParseResult()
        if not xml_path.is_file():
            return result

        try:
            tree = DefusedET.parse(xml_path)
            root = tree.getroot()

            for host in root.findall(".//host"):
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    port_info = PortInfo(
                        port=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        state="open",
                        service=service_el.get("name", "") if service_el is not None else "",
                        version=service_el.get("version", "") if service_el is not None else "",
                        product=service_el.get("product", "") if service_el is not None else "",
                        confidence="high",
                    )
                    result.ports.append(port_info)

        except (ET.ParseError, DefusedXmlException):
            pass

        return result

    def parse_nmap_text(self, text: str) -> SurfaceParseResult:
        """Parse nmap normal text output for open ports.

        Args:
            text: Raw nmap text output.

        Returns:
            SurfaceParseResult with discovered ports.
        """
        result = SurfaceParseResult(raw_output=text)

        for line in text.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    port_info = PortInfo(
                        port=int(port_proto[0]),
                        protocol=port_proto[1] if len(port_proto) > 1 else "tcp",
                        state="open",
                        service=parts[2] if len(parts) > 2 else "",
                        version=" ".join(parts[3:]) if len(parts) > 3 else "",
                    )
                    result.ports.append(port_info)
            elif "/udp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    port_info = PortInfo(
                        port=int(port_proto[0]),
                        protocol="udp",
                        state="open",
                        service=parts[2] if len(parts) > 2 else "",
                    )
                    result.ports.append(port_info)

        return result

    def parse_httpx_json(self, json_path: Path) -> SurfaceParseResult:
        """Parse httpx JSON output for HTTP service metadata.

        Args:
            json_path: Path to httpx JSON output file.

        Returns:
            SurfaceParseResult with discovered services.
        """
        result = SurfaceParseResult()
        if not json_path.is_file():
            return result

        try:
            content = json_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.raw_output = f"Error reading httpx JSON output: {e}"
            return result

        for line in content.strip().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                # A line that's valid JSON but not an object (e.g. a bare
                # number/array/string) has no fields to extract — skip it
                # rather than letting .get() raise on a non-dict.
                continue

            svc = ServiceInfo(
                url=entry.get("url", ""),
                status_code=entry.get("status_code", 0),
                title=entry.get("title", ""),
                technologies=entry.get("technologies", []),
                content_length=entry.get("content_length", 0),
                web_server=entry.get("webserver", ""),
            )
            result.services.append(svc)

        return result
