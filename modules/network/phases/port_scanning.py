"""ReconForge Port Scanning Phase - Enumerate open ports and services.

Phase 2 of the network reconnaissance kill chain.
Performs SYN/connect scans, version detection, and identifies
interesting services for further enumeration.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.network.base import NetworkPhaseBase
from modules.network.tools.nmap import NmapTool
from modules.network.parsers.nmap_parser import NmapParser, NmapHost


class PortScanningPhase(NetworkPhaseBase):
    """Enumerate open ports and services on discovered hosts."""

    PHASE_NUMBER = 2
    PHASE_NAME = "port_scanning"
    PHASE_DESCRIPTION = "Port scanning and service detection"

    # Services that warrant deeper enumeration
    INTERESTING_SERVICES = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        88: "kerberos",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        514: "syslog",
        587: "submission",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "ms-sql",
        1521: "oracle",
        2049: "nfs",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        5985: "winrm",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        8888: "http-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }

    def __init__(self, nmap: NmapTool, parser: NmapParser, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.parser = parser

    def run(self, targets: List[str], opsec_mode: str = "normal") -> Dict[str, Any]:
        """Execute port scanning phase.

        Args:
            targets: List of target IPs to scan.
            opsec_mode: Scanning intensity (stealth, normal, aggressive).

        Returns:
            Dict with scan results per host.
        """
        self.logger.info(f"=== Phase 2: Port Scanning ({len(targets)} targets) ===")
        self.notes.add_phase_start(self.PHASE_NAME)

        results = {
            "phase": self.PHASE_NAME,
            "hosts": {},
            "total_open_ports": 0,
            "services_found": [],
            "success": False,
        }

        for target in targets:
            host_result = self._scan_host(target, opsec_mode)
            results["hosts"][target] = host_result

            if host_result.get("open_ports"):
                results["total_open_ports"] += len(host_result["open_ports"])
                results["services_found"].extend(host_result.get("services", []))

        results["success"] = True

        # Save parsed results
        parsed_file = self.output_dir / "port_scan_results.json"
        parsed_file.parent.mkdir(parents=True, exist_ok=True)
        parsed_file.write_text(json.dumps(results["hosts"], indent=2, default=str))

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"{results['total_open_ports']} total open ports across {len(targets)} hosts"
        )

        return results

    def _scan_host(self, target: str, opsec_mode: str) -> Dict[str, Any]:
        """Scan a single host."""
        host_result = {
            "target": target,
            "open_ports": [],
            "services": [],
            "interesting_services": [],
            "vulnerabilities": [],
        }

        # Determine scan type based on OPSEC mode
        if opsec_mode == "stealth":
            if not self.opsec.check("nmap_syn_scan"):
                self.logger.warning(f"SYN scan blocked in stealth mode for {target}")
                return host_result
            scan_func = self.nmap.syn_scan
            scan_type = "SYN"
            ports = "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,636,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443"
        elif opsec_mode == "aggressive":
            scan_func = self.nmap.syn_scan
            scan_type = "SYN (all ports)"
            ports = "-"
        else:  # normal
            scan_func = self.nmap.syn_scan
            scan_type = "SYN"
            ports = "-"

        # Record workflow
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Host {target} has open services",
            command=f"nmap -sS -p {ports} {target}",
            justification=f"{scan_type} scan to identify open ports",
            alternatives=["nmap -sT for unprivileged scan", "masscan for speed"]
        )

        # Run the scan
        run_result = scan_func(target, ports=ports)

        if not run_result.success:
            self.logger.error(f"Port scan failed for {target}: {run_result.stderr}")
            self.workflow.record_result(f"Failed: {run_result.stderr[:100]}")
            self.notes.add_command_note(run_result.command, f"Failed: {run_result.stderr[:100]}")
            host_result["error"] = run_result.stderr
            return host_result

        # Parse results
        xml_path = self.nmap.get_xml_path("syn_scan")
        if xml_path.exists():
            nmap_result = self.parser.parse_xml(xml_path)
        else:
            nmap_result = self.parser.parse_text(run_result.stdout)

        # Process discovered hosts
        for host in nmap_result.live_hosts:
            if host.ip == target or not host_result["open_ports"]:
                self._process_host(host, host_result, target)

        # Run version scan on open ports if any found
        if host_result["open_ports"] and opsec_mode != "stealth":
            self._version_scan(target, host_result)

        # Record result
        port_count = len(host_result["open_ports"])
        self.workflow.record_result(f"{port_count} open ports found on {target}")
        self.notes.add_command_note(
            run_result.command,
            f"{port_count} open ports found"
        )

        # Suggest next steps
        self._suggest_next_steps(target, host_result)

        return host_result

    def _process_host(self, host: NmapHost, host_result: Dict, target: str):
        """Process a scanned host and extract findings."""
        for port in host.open_ports:
            port_info = {
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "scripts": port.scripts,
            }
            host_result["open_ports"].append(port_info)

            # Track service
            service_str = f"{port.port}/{port.protocol} {port.service}"
            if port.product:
                service_str += f" ({port.product} {port.version})"
            host_result["services"].append(service_str)

            # Store as loot
            if port.product:
                self.loot.add_service(
                    service=port.service or "unknown",
                    version=f"{port.product} {port.version}".strip(),
                    port=port.port,
                    source="nmap_scan",
                    module="network"
                )

            # Check if it's an interesting service
            if port.port in self.INTERESTING_SERVICES or port.service in self.INTERESTING_SERVICES.values():
                host_result["interesting_services"].append(port_info)

            # Generate finding for each open port
            self.findings.add(
                finding_type="exposure",
                severity="info",
                confidence="confirmed",
                target=f"{target}:{port.port}",
                module="network",
                phase=self.PHASE_NAME,
                description=f"Open port: {service_str}",
                evidence=f"State: {port.state}, Banner: {port.extra_info}" if port.extra_info else f"State: {port.state}",
            )

        # Check for known vulnerabilities
        vulns = self.parser.check_known_vulns(host)
        for vuln in vulns:
            host_result["vulnerabilities"].append(vuln)
            self.findings.add(
                finding_type="vulnerability",
                severity=vuln["severity"],
                confidence="high",
                target=f"{target}:{vuln['port']}",
                module="network",
                phase=self.PHASE_NAME,
                description=vuln["description"],
                evidence=f"Service: {vuln['service']}",
                recommendation="Update the service to the latest version",
                references=[vuln["reference"]],
            )
            self.logger.finding(vuln["severity"], vuln["description"])

        # Check anonymous access potential
        anon_findings = self.parser.check_anonymous_access(host)
        for finding in anon_findings:
            self.findings.add(
                finding_type="misconfiguration",
                severity="medium",
                confidence="medium",
                target=f"{target}:{finding['port']}",
                module="network",
                phase=self.PHASE_NAME,
                description=finding["description"],
                evidence=finding.get("evidence", ""),
                recommendation="Disable anonymous access unless explicitly required",
            )

        # Check weak configs
        weak_configs = self.parser.check_weak_configs(host)
        for config in weak_configs:
            self.findings.add(
                finding_type="misconfiguration",
                severity=config.get("severity", "medium"),
                confidence="confirmed",
                target=f"{target}:{config['port']}",
                module="network",
                phase=self.PHASE_NAME,
                description=config["description"],
                evidence=config.get("evidence", ""),
                recommendation=config.get("recommendation", ""),
            )

    def _version_scan(self, target: str, host_result: Dict):
        """Run version detection on discovered open ports."""
        open_port_str = ",".join(str(p["port"]) for p in host_result["open_ports"])
        if not open_port_str:
            return

        self.logger.info(f"Running version detection on {target} ports: {open_port_str}")

        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis=f"Service versions on {target} may reveal vulnerabilities",
            command=f"nmap -sV -p {open_port_str} {target}",
            justification="Version detection for vulnerability identification",
        )

        result = self.nmap.version_scan(target, ports=open_port_str)
        if result.success:
            xml_path = self.nmap.get_xml_path("version_scan")
            if xml_path.exists():
                nmap_result = self.parser.parse_xml(xml_path)
                for host in nmap_result.live_hosts:
                    # Update port info with version data
                    for port in host.open_ports:
                        for existing_port in host_result["open_ports"]:
                            if existing_port["port"] == port.port:
                                existing_port["product"] = port.product
                                existing_port["version"] = port.version
                                if port.product:
                                    self.loot.add_service(
                                        service=port.service or "unknown",
                                        version=f"{port.product} {port.version}".strip(),
                                        port=port.port,
                                        source="nmap_version_scan",
                                        module="network"
                                    )

                    # Re-check for known vulns with version info
                    vulns = self.parser.check_known_vulns(host)
                    for vuln in vulns:
                        if vuln not in host_result["vulnerabilities"]:
                            host_result["vulnerabilities"].append(vuln)
                            self.findings.add(
                                finding_type="vulnerability",
                                severity=vuln["severity"],
                                confidence="high",
                                target=f"{target}:{vuln['port']}",
                                module="network",
                                phase=self.PHASE_NAME,
                                description=vuln["description"],
                                evidence=f"Service: {vuln['service']}",
                                recommendation="Update the service to the latest version",
                                references=[vuln["reference"]],
                            )
                            self.logger.finding(vuln["severity"], vuln["description"])

            self.workflow.record_result("Version detection complete")

    def _suggest_next_steps(self, target: str, host_result: Dict):
        """Suggest next steps based on scan results."""
        for port_info in host_result.get("interesting_services", []):
            port = port_info["port"]
            service = port_info.get("service", "")

            if service in ("microsoft-ds", "netbios-ssn") or port in (139, 445):
                self.workflow.suggest_next(
                    command=f"enum4linux -a {target}",
                    justification=f"SMB detected on port {port} - enumerate shares/users",
                    priority="high"
                )
                self.workflow.suggest_next(
                    command=f"smbclient -L //{target} -N",
                    justification=f"Test null session SMB share listing",
                    priority="high"
                )

            if service == "ldap" or port in (389, 636):
                self.workflow.suggest_next(
                    command=f"ldapsearch -x -H ldap://{target} -s base",
                    justification=f"LDAP detected on port {port} - enumerate directory",
                    priority="high"
                )

            if service == "ftp" or port == 21:
                self.workflow.suggest_next(
                    command=f"ftp {target} (test anonymous)",
                    justification=f"FTP detected - test anonymous access",
                    priority="medium"
                )

            if service in ("http", "https") or port in (80, 443, 8080, 8443):
                self.workflow.suggest_next(
                    command=f"Web enumeration on {target}:{port}",
                    justification=f"Web service detected on port {port}",
                    priority="medium"
                )

            if service == "ssh" or port == 22:
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                self.workflow.suggest_next(
                    command=f"ssh {target} (check auth methods)",
                    justification=f"SSH detected: {product} {version}",
                    priority="low"
                )

        # Attack path identification
        has_smb = any(p["port"] in (139, 445) for p in host_result.get("open_ports", []))
        has_ldap = any(p["port"] in (389, 636) for p in host_result.get("open_ports", []))
        has_kerberos = any(p["port"] == 88 for p in host_result.get("open_ports", []))

        if has_smb and has_ldap:
            self.workflow.add_attack_path(
                name="Active Directory Enumeration",
                description="SMB and LDAP detected - likely a Domain Controller",
                steps=[
                    "Enumerate LDAP for base DN and users",
                    "Test SMB null session for share enumeration",
                    "Enumerate users via RID cycling",
                    "Check for ASREPRoasting if Kerberos available",
                    "Attempt password spray with discovered users",
                ],
                risk="high",
                prerequisites=["SMB port 445 open", "LDAP port 389 open"],
            )

        if has_smb:
            self.workflow.add_attack_path(
                name="SMB Enumeration Path",
                description="SMB service detected - enumerate shares and users",
                steps=[
                    "Test null session access",
                    "Enumerate shares with smbclient",
                    "Run enum4linux for full enumeration",
                    "Check accessible shares for sensitive files",
                    "Test default credentials if auth required",
                ],
                risk="medium",
                prerequisites=["SMB port 445 or 139 open"],
            )
