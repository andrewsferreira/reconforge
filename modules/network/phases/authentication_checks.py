"""ReconForge Authentication Checks Phase - Test for weak/default credentials.

Phase 4 of the network reconnaissance kill chain.
⚠️  Hydra brute-force testing is OPT-IN ONLY.
Passive checks (anonymous access, default creds) run by default.
Active brute-force requires explicit --brute-force flag.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.network.base import NetworkPhaseBase
from modules.network.tools.hydra import HydraTool
from modules.network.tools.smbclient import SmbclientTool


class AuthenticationChecksPhase(NetworkPhaseBase):
    """Test for authentication weaknesses."""

    PHASE_NUMBER = 4
    PHASE_NAME = "authentication_checks"
    PHASE_DESCRIPTION = "Authentication and credential checks"

    # Services to test for anonymous/default access
    ANON_TEST_SERVICES = {
        21: {"name": "ftp", "test": "anonymous_ftp"},
        445: {"name": "smb", "test": "null_session"},
        139: {"name": "smb", "test": "null_session"},
        389: {"name": "ldap", "test": "anonymous_bind"},
        3306: {"name": "mysql", "test": "root_no_password"},
        5432: {"name": "postgresql", "test": "default_creds"},
        6379: {"name": "redis", "test": "no_auth"},
        27017: {"name": "mongodb", "test": "no_auth"},
        9200: {"name": "elasticsearch", "test": "no_auth"},
    }

    def __init__(self, hydra: HydraTool, smbclient: SmbclientTool, **kwargs) -> None:
        super().__init__(**kwargs)
        self.hydra = hydra
        self.smbclient = smbclient

    def run(self, target: str, scan_results: Dict[str, Any],
            brute_force: bool = False, opsec_mode: str = "normal") -> Dict[str, Any]:
        """Execute authentication checks phase.

        Args:
            target: Target IP or hostname.
            scan_results: Results from port scanning phase.
            brute_force: If True, enable hydra testing (opt-in).
            opsec_mode: Scanning intensity.

        Returns:
            Dict with authentication check results.
        """
        self.logger.info(f"=== Phase 4: Authentication Checks on {target} ===")
        self.notes.add_phase_start(self.PHASE_NAME)

        results = {
            "phase": self.PHASE_NAME,
            "target": target,
            "anonymous_access": [],
            "default_creds": [],
            "weak_auth": [],
            "brute_force_results": [],
            "success": False,
        }

        # Get open ports for this target
        host_data = scan_results.get("hosts", {}).get(target, {})
        open_ports = host_data.get("open_ports", [])
        port_numbers = [p["port"] for p in open_ports]

        # Passive checks (always run)
        self._check_anonymous_access(target, port_numbers, open_ports, results)

        # Active brute-force (opt-in only)
        if brute_force:
            self._run_brute_force(target, port_numbers, open_ports, results, opsec_mode)
        else:
            self.logger.info(
                "Brute-force testing skipped (not opted in). "
                "Use --brute-force flag to enable."
            )
            self.notes.add(
                "Brute-force testing not enabled. Use --brute-force to opt in.",
                "phase"
            )

        # Honest success signal: anonymous-access checks are gated on
        # matching open ports being present, and brute-force is opt-in —
        # a run where nothing applicable was found and brute-force wasn't
        # requested genuinely checked nothing. success reflects whether a
        # real check actually ran, tracked via the existing tools_used list.
        results["success"] = bool(self.tools_used)

        # Save results
        parsed_file = self.output_dir / "auth_check_results.json"
        parsed_file.parent.mkdir(parents=True, exist_ok=True)
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Anonymous access: {len(results['anonymous_access'])}, "
            f"Default creds: {len(results['default_creds'])}"
        )

        return results

    def _check_anonymous_access(self, target: str, port_numbers: List[int],
                                 open_ports: List[Dict], results: Dict):
        """Check for anonymous/unauthenticated access on services."""
        self.logger.info("Checking for anonymous/unauthenticated access...")

        # SMB null-session testing is host-level (smbclient.null_session_test()
        # takes no port argument), but ANON_TEST_SERVICES maps BOTH 139 and 445
        # to the same "null_session" test. Running it once per matching port
        # produced two near-identical findings for any dual-port SMB host
        # (the overwhelming majority of Windows/Samba targets) — track
        # whether it's already run this call and test at most once.
        null_session_tested = False

        for port_num in port_numbers:
            if port_num not in self.ANON_TEST_SERVICES:
                continue

            svc_info = self.ANON_TEST_SERVICES[port_num]
            test_type = svc_info["test"]
            svc_name = svc_info["name"]

            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis=f"{svc_name} on port {port_num} may allow anonymous access",
                command=f"Test anonymous access on {target}:{port_num}",
                justification=f"Check for unauthenticated {svc_name} access",
            )

            if test_type == "null_session" and self.smbclient.is_available():
                if null_session_tested:
                    continue
                null_session_tested = True
                smb_ports = [p for p in port_numbers if self.ANON_TEST_SERVICES.get(p, {}).get("test") == "null_session"]

                result = self.smbclient.null_session_test(target)
                self.tools_used.append("smbclient")
                if result.success and "NT_STATUS_ACCESS_DENIED" not in result.stdout:
                    results["anonymous_access"].append({
                        "port": smb_ports,
                        "service": svc_name,
                        "type": "null_session",
                        "evidence": result.stdout[:300],
                    })
                    self.findings.add(
                        finding_type="misconfiguration",
                        severity="medium",
                        confidence="confirmed",
                        target=target,
                        module="network",
                        phase=self.PHASE_NAME,
                        description=(
                            "SMB null session allows anonymous access "
                            f"(ports {', '.join(str(p) for p in smb_ports)})"
                        ),
                        evidence=result.stdout[:300],
                        recommendation="Disable SMB null sessions",
                    )
                    self.workflow.record_result("Null session confirmed")
                else:
                    self.workflow.record_result("Null session denied")

            elif test_type in ("no_auth", "anonymous_bind"):
                # These are already tested in service enumeration phase;
                # here we document the finding if not already done
                for port_info in open_ports:
                    if port_info["port"] == port_num:
                        service_banner = port_info.get("product", "") + " " + port_info.get("version", "")
                        results["weak_auth"].append({
                            "port": port_num,
                            "service": svc_name,
                            "type": test_type,
                            "note": f"{svc_name} on port {port_num} should be tested for {test_type}",
                            "banner": service_banner.strip(),
                        })
                        self.workflow.suggest_next(
                            command=f"Test {test_type} on {target}:{port_num}",
                            justification=f"{svc_name} detected - verify authentication requirements",
                            priority="medium"
                        )
                        break

    def _run_brute_force(self, target: str, port_numbers: List[int],
                          open_ports: List[Dict], results: Dict,
                          opsec_mode: str):
        """Run brute-force testing with hydra (opt-in only)."""
        self.logger.warning("⚠️  Brute-force testing enabled - proceeding with caution")

        if not self.opsec.check("hydra_brute"):
            self.logger.warning("Hydra blocked by OPSEC policy")
            return

        if not self.hydra.is_available():
            self.logger.warning("Hydra not available on system")
            return

        # Determine which services to test
        brute_services = []
        service_map = {
            22: "ssh",
            21: "ftp",
            445: "smb",
            3389: "rdp",
            5985: "winrm",
            3306: "mysql",
            5432: "postgres",
            1433: "mssql",
        }

        for port_num in port_numbers:
            if port_num in service_map:
                brute_services.append({
                    "port": port_num,
                    "service": service_map[port_num],
                })

        for svc in brute_services:
            self.logger.warning(
                f"⚠️  Testing default credentials on {target}:{svc['port']} ({svc['service']})"
            )

            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis=f"Default credentials may work on {svc['service']}",
                command=f"hydra -t 4 {target} {svc['service']}",
                justification=f"Test common default credentials on {svc['service']}",
                alternatives=["Manual testing", "crackmapexec"]
            )

            hydra_result = self.hydra.test_default_creds(
                target, svc["service"], port=svc["port"]
            )
            self.tools_used.append("hydra")

            if hydra_result.success:
                # Check for found credentials
                creds_found = self._parse_hydra_output(hydra_result.stdout)
                for cred in creds_found:
                    results["default_creds"].append({
                        "port": svc["port"],
                        "service": svc["service"],
                        **cred,
                    })

                    self.loot.add_credential(
                        username=cred["username"],
                        password=cred["password"],
                        source="hydra",
                        module="network",
                        service=svc["service"],
                    )

                    self.findings.add(
                        finding_type="credential",
                        severity="critical",
                        confidence="confirmed",
                        target=f"{target}:{svc['port']}",
                        module="network",
                        phase=self.PHASE_NAME,
                        description=f"Default credentials found: {cred['username']}:{cred['password']} on {svc['service']}",
                        evidence=f"Service: {svc['service']}, Port: {svc['port']}",
                        recommendation="Change default credentials immediately",
                    )
                    self.logger.finding("critical", f"Credentials found: {cred['username']}:{cred['password']} on {svc['service']}")

                if creds_found:
                    self.workflow.record_result(f"{len(creds_found)} credentials found!")
                    self.workflow.add_attack_path(
                        name=f"Authenticated Access via {svc['service']}",
                        description=f"Valid credentials discovered for {svc['service']}",
                        steps=[
                            f"Login with {creds_found[0]['username']}:{creds_found[0]['password']}",
                            f"Enumerate privileges on {svc['service']}",
                            "Check for lateral movement opportunities",
                            "Escalate privileges if possible",
                        ],
                        risk="critical",
                    )
                else:
                    self.workflow.record_result("No default credentials found")

    @staticmethod
    def _parse_hydra_output(output: str) -> List[Dict[str, str]]:
        """Parse hydra output for discovered credentials."""
        import re
        creds = []
        for match in re.finditer(
            r"\[\d+\]\[\S+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
            output
        ):
            creds.append({
                "username": match.group(1),
                "password": match.group(2),
            })
        return creds
