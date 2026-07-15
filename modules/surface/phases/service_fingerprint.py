"""ReconForge - Surface Phase 2: Service Fingerprinting

Author: Andrews Ferreira

Detailed service version detection and HTTP service probing across
discovered open ports. Uses nmap version detection and httpx probing.
"""

import json
from typing import Any

from modules.surface.base import SurfacePhaseBase
from modules.surface.parsers.surface_parser import SurfaceParser
from modules.surface.tools.nmap_stealth import NmapStealthTool
from modules.surface.tools.service_detector import ServiceDetectorTool


class ServiceFingerprintPhase(SurfacePhaseBase):
    """Phase 2 \u2013 Fingerprint services on discovered open ports."""

    PHASE_NUMBER = 2
    PHASE_NAME = "service_fingerprint"
    PHASE_DESCRIPTION = "Service version detection & HTTP probing"

    def __init__(
        self,
        nmap: NmapStealthTool,
        detector: ServiceDetectorTool,
        parser: SurfaceParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.detector = detector
        self.parser = parser

    def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Execute service fingerprinting phase.

        Args:
            target: Target IP / hostname.
            **kwargs: Must include 'ports' (list of port dicts from Phase 1).

        Returns:
            Dict with fingerprinted services, finding count, and success flag.
        """
        ports = kwargs.get("ports", [])
        results: dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "services": [],
            "http_services": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        # \u2500\u2500 Nmap version detection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        finding_count += self._run_version_scan(target, ports, results)

        # \u2500\u2500 HTTP service probing \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        finding_count += self._run_http_probe(target, ports, results)

        results["finding_count"] = finding_count
        # Honest success signal: both sub-steps can no-op (opsec-blocked,
        # tool unavailable, no candidate ports) without raising — success
        # reflects whether a tool actually executed, tracked via the
        # existing tools_used list, not whether findings were generated.
        results["success"] = bool(self.tools_used)

        parsed_file = self.phase_output("service_fingerprint_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        return results

    def _run_version_scan(self, target: str, ports: list[dict],
                          results: dict) -> int:
        """Run nmap service version detection on discovered ports."""
        count = 0

        if not self.nmap.is_available():
            self.logger.warning("nmap not installed \u2013 skipping version scan")
            return count

        if not ports:
            self.logger.info("No ports from Phase 1 \u2013 skipping version scan")
            return count

        if not self.opsec.check("nmap_version_scan"):
            return count

        port_list = ",".join(str(p["port"]) for p in ports[:100])
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis="Service versions can reveal known vulnerabilities",
            command=f"nmap -sV -p {port_list} {target}",
            justification="Version detection for CVE correlation",
        )

        run_result = self.nmap.service_version_scan(
            target, ports=f"-p {port_list}"
        )
        self.tools_used.append("nmap")

        if not run_result.success:
            self.logger.warning(f"Version scan failed: {run_result.stderr[:200]}")
            return count

        xml_path = self.nmap.get_xml_path("service_version")
        parse_result = self.parser.parse_nmap_xml(xml_path)

        for port_info in parse_result.ports:
            svc_entry = {
                "port": port_info.port,
                "service": port_info.service,
                "version": port_info.version,
                "product": port_info.product,
            }
            results["services"].append(svc_entry)

            if port_info.version:
                self.add_finding(
                    finding_type="information",
                    severity="info",
                    confidence="high",
                    target=f"{target}:{port_info.port}",
                    description=(
                        f"Service version: {port_info.product} "
                        f"{port_info.version} on {port_info.port}/{port_info.protocol}"
                    ),
                    evidence=f"{port_info.product} {port_info.version}",
                )
                count += 1

                self.loot.add_service(
                    service=port_info.service,
                    version=port_info.version,
                    port=port_info.port,
                    source="nmap-sV",
                    module="surface",
                )

        self.workflow.record_result(
            f"Version scan: {len(parse_result.ports)} services fingerprinted"
        )
        return count

    def _run_http_probe(self, target: str, ports: list[dict],
                        results: dict) -> int:
        """Probe for HTTP services on discovered ports."""
        count = 0

        if not self.detector.is_available():
            self.logger.warning("httpx not installed \u2013 skipping HTTP probe")
            return count

        http_ports = [str(p["port"]) for p in ports
                      if p.get("service", "") in ("http", "https", "http-proxy", "")]
        if not http_ports:
            return count

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis="Open ports may host HTTP services",
            command=f"httpx -u {target} -ports {','.join(http_ports)}",
            justification="HTTP probing for web service discovery",
        )

        run_result = self.detector.probe_services(
            target, ports=",".join(http_ports)
        )
        self.tools_used.append("httpx")

        if not run_result.success:
            self.logger.warning(f"httpx probe failed: {run_result.stderr[:200]}")
            return count

        parse_result = self.parser.parse_httpx_json(
            self.detector.get_output_path()
        )

        for svc in parse_result.services:
            results["http_services"].append({
                "url": svc.url,
                "status_code": svc.status_code,
                "title": svc.title,
                "technologies": svc.technologies,
                "web_server": svc.web_server,
            })

            self.add_finding(
                finding_type="information",
                severity="info",
                confidence="high",
                target=svc.url,
                description=(
                    f"HTTP service: {svc.title or 'No title'} "
                    f"(status {svc.status_code}, server: {svc.web_server})"
                ),
                evidence=f"Technologies: {', '.join(svc.technologies) or 'none'}",
            )
            count += 1

        self.workflow.record_result(
            f"HTTP probe: {len(parse_result.services)} HTTP services detected"
        )
        return count
