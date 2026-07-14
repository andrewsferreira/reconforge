"""ReconForge Service Enumeration Phase - Deep dive into discovered services.

Phase 3 of the network reconnaissance kill chain.
Performs targeted enumeration of SMB, LDAP, and other interesting
services discovered during port scanning.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules.network.base import NetworkPhaseBase
from modules.network.tools.nmap import NmapTool
from modules.network.tools.enum4linux import Enum4linuxTool
from modules.network.tools.smbclient import SmbclientTool
from modules.network.tools.ldapsearch import LdapsearchTool
from modules.network.parsers.nmap_parser import NmapParser
from modules.network.parsers.enum4linux_parser import Enum4linuxParser
from modules.network.parsers.smb_parser import SmbParser
from modules.network.parsers.ldap_parser import LdapParser


class ServiceEnumerationPhase(NetworkPhaseBase):
    """Deep enumeration of discovered services."""

    PHASE_NUMBER = 3
    PHASE_NAME = "service_enumeration"
    PHASE_DESCRIPTION = "Service enumeration (SMB, LDAP, etc.)"

    def __init__(
        self,
        nmap: NmapTool,
        enum4linux: Enum4linuxTool,
        smbclient: SmbclientTool,
        ldapsearch: LdapsearchTool,
        nmap_parser: NmapParser,
        enum4linux_parser: Enum4linuxParser,
        smb_parser: SmbParser,
        ldap_parser: LdapParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.enum4linux = enum4linux
        self.smbclient = smbclient
        self.ldapsearch = ldapsearch
        self.nmap_parser = nmap_parser
        self.enum4linux_parser = enum4linux_parser
        self.smb_parser = smb_parser
        self.ldap_parser = ldap_parser

    def run(self, target: str, scan_results: Dict[str, Any],
            opsec_mode: str = "normal") -> Dict[str, Any]:
        """Execute service enumeration phase.

        Args:
            target: Target IP or hostname.
            scan_results: Results from port scanning phase.
            opsec_mode: Scanning intensity.

        Returns:
            Dict with enumeration results.
        """
        self.logger.info(f"=== Phase 3: Service Enumeration on {target} ===")
        self.notes.add_phase_start(self.PHASE_NAME)

        results = {
            "phase": self.PHASE_NAME,
            "target": target,
            "smb": {},
            "ldap": {},
            "nse_scripts": {},
            "success": False,
        }

        # Get open ports for this target
        host_data = scan_results.get("hosts", {}).get(target, {})
        open_ports = host_data.get("open_ports", [])
        port_numbers = [p["port"] for p in open_ports]

        # SMB Enumeration (ports 139, 445)
        if 445 in port_numbers or 139 in port_numbers:
            results["smb"] = self._enumerate_smb(target, opsec_mode)

        # LDAP Enumeration (ports 389, 636)
        if 389 in port_numbers or 636 in port_numbers:
            results["ldap"] = self._enumerate_ldap(target)

        # NSE Script Scanning for deeper analysis
        if open_ports and opsec_mode != "stealth":
            if self.opsec.check("nmap_script_scan"):
                results["nse_scripts"] = self._run_nse_scripts(target, port_numbers)

        # Honest success signal: SMB/LDAP/NSE enumeration are each gated
        # on matching open ports being present — a target with none of
        # 139/445/389/636 open genuinely has nothing for this phase to
        # enumerate. success reflects whether a tool actually ran,
        # tracked via the existing tools_used list.
        results["success"] = bool(self.tools_used)

        # Save parsed results
        parsed_file = self.output_dir / "service_enum_results.json"
        parsed_file.parent.mkdir(parents=True, exist_ok=True)
        parsed_file.write_text(json.dumps(results, indent=2, default=str))

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Enumerated SMB={bool(results['smb'])}, LDAP={bool(results['ldap'])}"
        )

        return results

    def _enumerate_smb(self, target: str, opsec_mode: str) -> Dict[str, Any]:
        """Perform comprehensive SMB enumeration."""
        self.logger.info(f"Enumerating SMB on {target}")
        smb_results: Dict[str, Any] = {
            "shares": [],
            "users": [],
            "groups": [],
            "password_policy": {},
            "null_session": False,
            "domain": "",
            "os_info": "",
        }

        # --- smbclient: Test null session and list shares ---
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis="SMB null session may be possible",
            command=f"smbclient -L //{target} -N",
            justification="Test anonymous SMB access for share enumeration",
            alternatives=["rpcclient", "crackmapexec"]
        )

        if self.smbclient.is_available():
            smb_result = self.smbclient.list_shares(target)
            self.tools_used.append("smbclient")
            if smb_result.success:
                parsed = self.smb_parser.parse_share_list(smb_result.stdout, target)
                smb_results["null_session"] = parsed.null_session
                smb_results["domain"] = parsed.domain

                if parsed.null_session:
                    self.logger.finding("medium", f"SMB null session possible on {target}")
                    self.findings.add(
                        finding_type="misconfiguration",
                        severity="medium",
                        confidence="confirmed",
                        target=f"{target}:445",
                        module="network",
                        phase=self.PHASE_NAME,
                        description="SMB null session allows anonymous share listing",
                        evidence=smb_result.stdout[:500],
                        recommendation="Disable null sessions: set RestrictAnonymous=1",
                    )

                # Test access to each share
                interesting_shares = self.smb_parser.get_interesting_shares(parsed)
                for share in parsed.shares:
                    share_info = {
                        "name": share.name,
                        "type": share.share_type,
                        "comment": share.comment,
                        "accessible": False,
                    }

                    # Test access
                    access_result = self.smbclient.test_share_access(target, share.name)
                    if access_result.success and "NT_STATUS" not in access_result.stdout:
                        share_info["accessible"] = True
                        share_info["anonymous"] = True
                        parsed_access = self.smb_parser.parse_share_access(
                            access_result.stdout, share.name
                        )
                        share_info["files"] = [f["name"] for f in parsed_access.files]

                        self.loot.add_share(
                            share_path=f"//{target}/{share.name}",
                            permissions="read",
                            source="smbclient",
                            module="network",
                            anonymous=True
                        )

                        self.findings.add(
                            finding_type="misconfiguration",
                            severity="high" if share.name not in ("IPC$",) else "low",
                            confidence="confirmed",
                            target=f"{target}:445",
                            module="network",
                            phase=self.PHASE_NAME,
                            description=f"Anonymous read access to share: {share.name}",
                            evidence=f"Share: //{target}/{share.name}\nFiles: {', '.join(share_info.get('files', [])[:10])}",
                            recommendation="Restrict share access to authenticated users only",
                        )

                    smb_results["shares"].append(share_info)

                self.workflow.record_result(
                    f"{len(parsed.shares)} shares found, "
                    f"null session: {parsed.null_session}"
                )
                self.notes.add_command_note(
                    f"smbclient -L //{target} -N",
                    f"{len(parsed.shares)} shares, null={parsed.null_session}"
                )

        # --- enum4linux: Full enumeration ---
        if not self.opsec.check("enum4linux"):
            self.logger.info("enum4linux blocked by OPSEC policy")
        elif self.enum4linux.is_available():
            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis="enum4linux will reveal users, groups, and policies",
                command=f"enum4linux -a {target}",
                justification="Comprehensive SMB/NetBIOS enumeration",
                alternatives=["enum4linux-ng", "rpcclient"]
            )

            enum_result = self.enum4linux.full_enum(target)
            self.tools_used.append("enum4linux")
            if enum_result.success or enum_result.stdout:
                parsed_enum = self.enum4linux_parser.parse(enum_result.stdout)

                # Extract users
                usernames = self.enum4linux_parser.get_usernames(parsed_enum)
                smb_results["users"] = usernames
                for username in usernames:
                    self.loot.add_user(
                        username=username,
                        source="enum4linux",
                        module="network",
                        domain=parsed_enum.domain or parsed_enum.workgroup,
                    )
                    self.logger.loot("user", username)

                if usernames:
                    self.findings.add(
                        finding_type="exposure",
                        severity="medium",
                        confidence="confirmed",
                        target=f"{target}:445",
                        module="network",
                        phase=self.PHASE_NAME,
                        description=f"{len(usernames)} users enumerated via SMB",
                        evidence=f"Users: {', '.join(usernames[:20])}",
                        recommendation="Restrict anonymous user enumeration via RestrictAnonymous",
                    )

                # Extract groups
                smb_results["groups"] = [g["name"] for g in parsed_enum.groups]

                # Extract password policy
                smb_results["password_policy"] = parsed_enum.password_policy
                if parsed_enum.password_policy:
                    min_len = parsed_enum.password_policy.get("min_length", "")
                    if min_len and int(min_len) < 8:
                        self.findings.add(
                            finding_type="misconfiguration",
                            severity="medium",
                            confidence="confirmed",
                            target=f"{target}:445",
                            module="network",
                            phase=self.PHASE_NAME,
                            description=f"Weak password policy: minimum length is {min_len}",
                            evidence=json.dumps(parsed_enum.password_policy, indent=2),
                            recommendation="Set minimum password length to at least 12 characters",
                        )

                    lockout = parsed_enum.password_policy.get("lockout_threshold", "")
                    if lockout and lockout.lower() in ("none", "0"):
                        self.findings.add(
                            finding_type="misconfiguration",
                            severity="medium",
                            confidence="confirmed",
                            target=f"{target}:445",
                            module="network",
                            phase=self.PHASE_NAME,
                            description="No account lockout policy configured",
                            evidence=f"Lockout threshold: {lockout}",
                            recommendation="Configure account lockout after 5-10 failed attempts",
                        )

                smb_results["os_info"] = parsed_enum.os_info
                smb_results["domain"] = parsed_enum.domain or parsed_enum.workgroup or smb_results["domain"]

                self.workflow.record_result(
                    f"{len(usernames)} users, {len(parsed_enum.groups)} groups enumerated"
                )
                self.notes.add_command_note(
                    f"enum4linux -a {target}",
                    f"{len(usernames)} users, {len(parsed_enum.groups)} groups"
                )

                # Attack path: user list for password spray
                if usernames:
                    self.workflow.add_attack_path(
                        name="Password Spray Attack",
                        description=f"{len(usernames)} users discovered - password spray viable",
                        steps=[
                            f"Save {len(usernames)} usernames to wordlist",
                            "Check password policy for lockout threshold",
                            "Spray common passwords (Season+Year, Company+123, etc.)",
                            "Test discovered credentials against SMB/WinRM/RDP",
                        ],
                        risk="high",
                        prerequisites=["User list from enumeration", "Password policy checked"],
                    )

        return smb_results

    def _enumerate_ldap(self, target: str) -> Dict[str, Any]:
        """Perform LDAP enumeration."""
        self.logger.info(f"Enumerating LDAP on {target}")
        ldap_results: Dict[str, Any] = {
            "base_dn": "",
            "naming_contexts": [],
            "domain": "",
            "users": [],
            "groups": [],
            "computers": [],
            "anonymous_bind": False,
        }

        if not self.ldapsearch.is_available():
            self.logger.warning("ldapsearch not available")
            return ldap_results

        # Step 1: Discover base DN
        self.workflow.add_step(
            phase=self.PHASE_NAME,
            hypothesis="LDAP anonymous bind may reveal directory structure",
            command=f"ldapsearch -x -H ldap://{target} -s base",
            justification="RootDSE query to discover base DN and naming contexts",
            alternatives=["nmap ldap-rootdse script"]
        )

        rootdse_result = self.ldapsearch.get_base_dn(target)
        self.tools_used.append("ldapsearch")
        if not rootdse_result.success and not rootdse_result.stdout:
            self.logger.warning(f"LDAP rootDSE query failed on {target}")
            self.workflow.record_result("LDAP rootDSE query failed")
            return ldap_results

        parsed = self.ldap_parser.parse_rootdse(rootdse_result.stdout, target)

        if parsed.errors:
            for err in parsed.errors:
                self.logger.warning(f"LDAP error: {err}")
            if not parsed.anonymous_bind:
                return ldap_results

        ldap_results["base_dn"] = parsed.base_dn
        ldap_results["naming_contexts"] = parsed.naming_contexts
        ldap_results["domain"] = parsed.domain_name
        ldap_results["anonymous_bind"] = parsed.anonymous_bind

        if parsed.anonymous_bind:
            self.findings.add(
                finding_type="misconfiguration",
                severity="medium",
                confidence="confirmed",
                target=f"{target}:389",
                module="network",
                phase=self.PHASE_NAME,
                description="LDAP anonymous bind is enabled",
                evidence=f"Base DN: {parsed.base_dn}\nNaming contexts: {', '.join(parsed.naming_contexts)}",
                recommendation="Disable anonymous LDAP binds unless explicitly required",
            )

        # Store base DN as loot
        if parsed.base_dn:
            self.loot.add(
                loot_type="config",
                value=f"LDAP Base DN: {parsed.base_dn}",
                source="ldapsearch",
                module="network",
                confidence="confirmed",
                metadata={"base_dn": parsed.base_dn, "domain": parsed.domain_name}
            )

        self.workflow.record_result(
            f"Base DN: {parsed.base_dn}, Anonymous bind: {parsed.anonymous_bind}"
        )
        self.notes.add_command_note(
            f"ldapsearch rootDSE on {target}",
            f"Base DN: {parsed.base_dn}"
        )

        # Step 2: Enumerate users if we have base DN
        if parsed.base_dn and parsed.anonymous_bind:
            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis="Anonymous LDAP will reveal user accounts",
                command=f"ldapsearch -x -H ldap://{target} -b '{parsed.base_dn}' '(objectClass=user)'",
                justification="Enumerate domain users via anonymous LDAP",
            )

            users_result = self.ldapsearch.enum_users(target, parsed.base_dn)
            if users_result.stdout:
                user_parsed = self.ldap_parser.parse(users_result.stdout, target)
                ldap_results["users"] = [
                    {"username": u["username"], "display_name": u.get("display_name", ""),
                     "email": u.get("email", "")}
                    for u in user_parsed.users
                ]

                for user in user_parsed.users:
                    if user["username"]:
                        self.loot.add_user(
                            username=user["username"],
                            source="ldapsearch",
                            module="network",
                            domain=parsed.domain_name,
                        )
                        self.logger.loot("user", user["username"])

                if user_parsed.users:
                    self.findings.add(
                        finding_type="exposure",
                        severity="medium",
                        confidence="confirmed",
                        target=f"{target}:389",
                        module="network",
                        phase=self.PHASE_NAME,
                        description=f"{len(user_parsed.users)} users enumerated via anonymous LDAP",
                        evidence=f"Users: {', '.join(u['username'] for u in user_parsed.users[:20])}",
                        recommendation="Disable anonymous LDAP enumeration",
                    )

                # Check for admin users
                admins = self.ldap_parser.get_admin_users(user_parsed)
                if admins:
                    self.findings.add(
                        finding_type="exposure",
                        severity="high",
                        confidence="confirmed",
                        target=f"{target}:389",
                        module="network",
                        phase=self.PHASE_NAME,
                        description=f"Admin users identified: {', '.join(a['username'] for a in admins)}",
                        evidence=f"Admin users with group memberships visible via anonymous LDAP",
                        recommendation="Restrict LDAP access to authenticated users",
                    )

                self.workflow.record_result(
                    f"{len(user_parsed.users)} users enumerated via LDAP"
                )

            # Enumerate groups
            groups_result = self.ldapsearch.enum_groups(target, parsed.base_dn)
            if groups_result.stdout:
                group_parsed = self.ldap_parser.parse(groups_result.stdout, target)
                ldap_results["groups"] = [
                    {"name": g["name"], "members": len(g.get("members", []))}
                    for g in group_parsed.groups
                ]

            # Enumerate computers
            computers_result = self.ldapsearch.enum_computers(target, parsed.base_dn)
            if computers_result.stdout:
                comp_parsed = self.ldap_parser.parse(computers_result.stdout, target)
                ldap_results["computers"] = [
                    {"name": c["name"], "os": c.get("os", "")}
                    for c in comp_parsed.computers
                ]

        return ldap_results

    def _run_nse_scripts(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Run NSE scripts for deeper enumeration."""
        nse_results: Dict[str, Any] = {}

        # SMB scripts
        if 445 in ports or 139 in ports:
            self.workflow.add_step(
                phase=self.PHASE_NAME,
                hypothesis="NSE SMB scripts will reveal additional SMB details",
                command=f"nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-vuln* {target}",
                justification="Deep SMB enumeration with NSE scripts",
            )

            result = self.nmap.smb_scripts(target)
            self.tools_used.append("nmap")
            if result.success:
                xml_path = self.nmap.get_xml_path("smb_scripts")
                if xml_path.exists():
                    parsed = self.nmap_parser.parse_xml(xml_path)
                    for host in parsed.live_hosts:
                        script_vulns = self.nmap_parser.extract_script_vulns(host)
                        for vuln in script_vulns:
                            nse_results[vuln["script"]] = vuln
                            self.findings.add(
                                finding_type="vulnerability",
                                severity=vuln.get("severity", "high"),
                                confidence="confirmed",
                                target=f"{target}:{vuln['port']}",
                                module="network",
                                phase=self.PHASE_NAME,
                                description=vuln["description"],
                                evidence=vuln.get("evidence", ""),
                                references=[f"CVE: {c}" for c in vuln.get("cves", [])],
                            )
                            self.logger.finding(vuln["severity"], vuln["description"])

                self.workflow.record_result(f"{len(nse_results)} NSE findings")

        return nse_results
