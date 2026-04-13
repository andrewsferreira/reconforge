"""ReconForge Host Discovery Phase - Identify live hosts on the network.

Phase 1 of the network reconnaissance kill chain.
Uses nmap ping sweep to discover live hosts, then records findings
and updates the attack workflow with next steps.
"""

from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.network.base import NetworkPhaseBase
from modules.network.tools.nmap import NmapTool
from modules.network.parsers.nmap_parser import NmapParser, NmapResult


class HostDiscoveryPhase(NetworkPhaseBase):
    """Discover live hosts on the target network."""

    PHASE_NUMBER = 1
    PHASE_NAME = "host_discovery"
    PHASE_DESCRIPTION = "Host discovery via ping sweep"

    def __init__(self, nmap: NmapTool, parser: NmapParser, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.parser = parser

    def run(self, target: str, is_network: bool = False) -> Dict[str, Any]:
        """Execute host discovery phase.

        Args:
            target: Target IP, hostname, or CIDR range.
            is_network: True if target is a network range.

        Returns:
            Dict with discovered hosts and phase results.
        """
        self.logger.info(f"=== Phase 1: Host Discovery on {target} ===")
        self.notes.add_phase_start(self.PHASE_NAME)

        results = {
            "phase": self.PHASE_NAME,
            "target": target,
            "live_hosts": [],
            "total_hosts": 0,
            "success": False,
        }

        # For single hosts, we can skip ping sweep and go directly to scanning
        if not is_network:
            self.logger.info(f"Single target {target} - adding directly as live host")
            results["live_hosts"] = [target]
            results["total_hosts"] = 1
            results["success"] = True

            self.notes.add(f"Single target mode: {target} assumed live", "phase")

            # Record workflow step
            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis="Single target is a live host",
                command=f"Target: {target}",
                justification="Single IP/hostname provided, skipping ping sweep",
                alternatives=["nmap -sn to verify host is up"]
            )
            self.workflow.record_result(f"1 host targeted: {target}")

            self._suggest_next_steps(results)
            self.notes.add_phase_end(self.PHASE_NAME, f"1 host targeted")
            return results

        # OPSEC check for ping sweep
        if not self.opsec.check("nmap_ping_sweep"):
            self.logger.warning("Ping sweep blocked by OPSEC policy")
            results["error"] = "Blocked by OPSEC policy"
            self.notes.add("Ping sweep blocked by OPSEC policy", "phase")
            return results

        # Record workflow step
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"There are live hosts on {target}",
            command=f"nmap -sn {target}",
            justification="Ping sweep to discover live hosts before port scanning",
            alternatives=["arp-scan for local subnet", "masscan for large ranges"]
        )

        # Run ping sweep
        run_result = self.nmap.ping_sweep(target)

        if not run_result.success:
            self.logger.error(f"Ping sweep failed: {run_result.stderr}")
            results["error"] = run_result.stderr
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            self.notes.add(f"Ping sweep failed: {run_result.stderr[:200]}", "command")
            return results

        # Parse results
        xml_path = self.nmap.get_xml_path("ping_sweep")
        if xml_path.exists():
            nmap_result = self.parser.parse_xml(xml_path)
        else:
            nmap_result = self.parser.parse_text(run_result.stdout)

        # Extract live hosts
        live_hosts = []
        for host in nmap_result.live_hosts:
            live_hosts.append(host.ip)
            self.logger.info(f"Live host: {host.ip} ({host.hostname or 'no hostname'})")

            # Store as loot
            self.loot.add(
                loot_type="host",
                value=host.ip,
                source="nmap_ping_sweep",
                module="network",
                confidence="confirmed",
                metadata={"hostname": host.hostname, "mac": host.mac, "vendor": host.vendor}
            )

        results["live_hosts"] = live_hosts
        results["total_hosts"] = len(live_hosts)
        results["success"] = True

        # Generate findings
        if len(live_hosts) > 0:
            self.findings.add(
                finding_type="exposure",
                severity="info",
                confidence="confirmed",
                target=target,
                module="network",
                phase=self.PHASE_NAME,
                description=f"{len(live_hosts)} live host(s) discovered on {target}",
                evidence=f"Live hosts: {', '.join(live_hosts[:20])}",
            )

        # Record result
        self.workflow.record_result(f"{len(live_hosts)} live hosts found")
        self.notes.add_command_note(
            f"nmap -sn {target}",
            f"{len(live_hosts)} live hosts discovered"
        )

        self._suggest_next_steps(results)

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"{len(live_hosts)} live hosts found"
        )

        return results

    def _suggest_next_steps(self, results: Dict):
        """Add suggested next commands to the workflow."""
        for host in results["live_hosts"][:5]:  # Limit suggestions
            self.workflow.suggest_next(
                command=f"nmap -sS -p- -T4 --open {host}",
                justification=f"Full TCP port scan on live host {host}",
                priority="high"
            )
