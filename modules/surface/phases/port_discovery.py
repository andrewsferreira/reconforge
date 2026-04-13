"""ReconForge - Surface Phase 1: Port Discovery

Author: Andrews Ferreira

Stealth port scanning to map the target's exposed network surface.
Uses nmap SYN stealth scans with OPSEC-aware timing.
"""

import json
from typing import Any, Dict

from modules.surface.base import SurfacePhaseBase
from modules.surface.tools.nmap_stealth import NmapStealthTool
from modules.surface.parsers.surface_parser import SurfaceParser


class PortDiscoveryPhase(SurfacePhaseBase):
    """Phase 1 \u2013 Discover open ports via stealth scanning."""

    PHASE_NUMBER = 1
    PHASE_NAME = "port_discovery"
    PHASE_DESCRIPTION = "Stealth port discovery & enumeration"

    def __init__(
        self,
        nmap: NmapStealthTool,
        parser: SurfaceParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.parser = parser

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute port discovery phase.

        Args:
            target: Target IP / hostname / CIDR.

        Returns:
            Dict with discovered ports, finding count, and success flag.
        """
        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "ports": [],
            "finding_count": 0,
            "success": False,
        }

        finding_count = 0

        if not self.nmap.is_available():
            self.logger.warning("nmap not installed \u2013 skipping port discovery")
            self.notes.add("nmap not found \u2013 skipped", "general")
            return results

        if not self.opsec.check("nmap_syn_scan"):
            return results

        # Run stealth SYN scan
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Target {target} has exposed network services",
            command=f"nmap -sS {target}",
            justification="SYN stealth scan to discover open ports",
            alternatives=["masscan", "rustscan"],
        )

        run_result = self.nmap.stealth_syn_scan(target)
        self.tools_used.append("nmap")

        if not run_result.success:
            self.logger.warning(f"nmap scan failed: {run_result.stderr[:200]}")
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            return results

        # Parse results
        xml_path = self.nmap.get_xml_path("stealth_syn")
        parse_result = self.parser.parse_nmap_xml(xml_path)

        if not parse_result.ports and run_result.stdout:
            parse_result = self.parser.parse_nmap_text(run_result.stdout)

        for port_info in parse_result.ports:
            results["ports"].append({
                "port": port_info.port,
                "protocol": port_info.protocol,
                "service": port_info.service,
                "version": port_info.version,
                "product": port_info.product,
            })

            self.add_finding(
                finding_type="information",
                severity="info",
                confidence=port_info.confidence,
                target=f"{target}:{port_info.port}",
                description=f"Open port {port_info.port}/{port_info.protocol}: {port_info.service}",
                evidence=f"{port_info.product} {port_info.version}".strip(),
            )
            finding_count += 1

            # Record service as loot
            if port_info.service:
                self.loot.add_service(
                    service=port_info.service,
                    version=port_info.version or "",
                    port=port_info.port,
                    source="nmap",
                    module="surface",
                )

        port_summary = ", ".join(str(p.port) for p in parse_result.ports[:20])
        self.workflow.record_result(f"Open ports: {port_summary or 'none'}")
        self.notes.add_command_note(
            f"nmap -sS {target}",
            f"{len(parse_result.ports)} open ports discovered",
        )

        results["finding_count"] = finding_count
        results["success"] = True

        # Save parsed results
        parsed_file = self.phase_output("port_discovery_results.json")
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        return results
