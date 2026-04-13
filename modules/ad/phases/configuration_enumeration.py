"""ReconForge AD Phase 3 - Configuration Enumeration.

Enumerates AD configuration and policies:
- Password policy (complexity, length, lockout, history)
- Trust relationships (domain/forest trusts)
- GPO discovery and enumeration
- Share enumeration (SYSVOL, NETLOGON, admin shares)
- Domain controller enumeration

Refactored to delegate to collectors → analyzers → attack_paths pipeline.

Author: Andrews Ferreira
"""

from typing import Any, Dict, List

from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.smbclient import ADSmbclientTool
from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool

from modules.ad.parsers.ldap_parser import ADLdapParser, LdapPasswordPolicy
from modules.ad.parsers.smb_parser import ADSmbParser
from modules.ad.parsers.enum4linux_ng_parser import Enum4linuxNgParser

from modules.ad.collectors.ldap_collector import LdapCollector
from modules.ad.collectors.smb_collector import SmbCollector
from modules.ad.analyzers.misconfiguration_analyzer import MisconfigurationAnalyzer
from modules.ad.analyzers.permission_analyzer import PermissionAnalyzer
from modules.ad.analyzers.trust_analyzer import TrustAnalyzer
from modules.ad.attack_paths.gpo_paths import GpoPathBuilder
from modules.ad.attack_paths.privilege_escalation_paths import PrivilegeEscalationPathBuilder

from modules.ad.base import ADPhaseBase


class ConfigurationEnumerationPhase(ADPhaseBase):
    """Phase 3: Configuration enumeration — policies, trusts, GPOs, shares."""

    PHASE_NUMBER = 3
    PHASE_NAME = "configuration_enumeration"
    PHASE_DESCRIPTION = "Configuration enumeration (policies, trusts, GPOs)"

    def __init__(
        self,
        ldapsearch: ADLdapsearchTool,
        smbclient: ADSmbclientTool,
        enum4linux_ng: Enum4linuxNgTool,
        ldap_parser: ADLdapParser,
        smb_parser: ADSmbParser,
        enum4linux_ng_parser: Enum4linuxNgParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ldapsearch = ldapsearch
        self.smbclient = smbclient
        self.enum4linux_ng = enum4linux_ng
        self.ldap_parser = ldap_parser
        self.smb_parser = smb_parser
        self.enum_parser = enum4linux_ng_parser

        # Collectors
        collector_kwargs = dict(
            logger=self.logger, runner=self.runner,
            opsec=self.opsec, output_dir=self.output_dir,
            opsec_mode=self.opsec_mode,
        )
        self.ldap_collector = LdapCollector(
            ldapsearch=ldapsearch, ldap_parser=ldap_parser, **collector_kwargs,
        )
        self.smb_collector = SmbCollector(
            smbclient=smbclient, enum4linux_ng=enum4linux_ng,
            smb_parser=smb_parser, enum4linux_ng_parser=enum4linux_ng_parser,
            **collector_kwargs,
        )

        # Analyzers
        self.misconfig_analyzer = MisconfigurationAnalyzer()
        self.permission_analyzer = PermissionAnalyzer()
        self.trust_analyzer = TrustAnalyzer()

        # Attack path builders
        self.gpo_builder = GpoPathBuilder()
        self.privesc_builder = PrivilegeEscalationPathBuilder()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        anonymous_ldap: bool = False,
        null_session: bool = False,
        username: str = "",
        password: str = "",
        opsec_mode: str = "normal",
    ) -> Dict[str, Any]:
        """Execute configuration enumeration phase."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"=== AD Phase 3: Configuration Enumeration on {target} ===")
        self.logger.info(f"{'='*60}")
        self.notes.add_phase_start(self.PHASE_NAME)

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "target": target,
            "domain": domain,
            "password_policy": {},
            "trusts": [],
            "gpos": [],
            "shares": [],
            "domain_controllers": [],
            "success": False,
        }

        can_ldap = (anonymous_ldap or (username and password)) and base_dn

        # ── Step 1: Password policy collection ───────────────────────
        if can_ldap:
            results["password_policy"] = self.ldap_collector.collect_password_policy(
                target, base_dn, username, password,
            )
            self.logger.info(
                f"Password policy: minLen={results['password_policy'].get('min_length','N/A')}, "
                f"complexity={results['password_policy'].get('complexity','N/A')}"
            )
        elif null_session and self.enum4linux_ng.is_available():
            self._enum_password_policy_smb(target, results, username, password)

        if results["password_policy"]:
            self.loot.add(
                loot_type="password_policy",
                value=(
                    f"minLen={results['password_policy'].get('min_length')}, "
                    f"complexity={results['password_policy'].get('complexity')}, "
                    f"lockout={results['password_policy'].get('lockout_threshold')}"
                ),
                source="ldap_query", module="ad", confidence="confirmed",
                metadata=results["password_policy"],
            )

        # ── Step 2: Trust relationships ──────────────────────────────
        if can_ldap:
            results["trusts"] = self.ldap_collector.collect_trusts(
                target, base_dn, username, password,
            )
            for t in results["trusts"]:
                self.loot.add(
                    loot_type="trust", value=t["partner"],
                    source="ldap_query", module="ad",
                    confidence="confirmed", metadata=t,
                )
            self.logger.info(f"Trusts: {len(results['trusts'])}")

        # ── Step 3: GPO enumeration ──────────────────────────────────
        if can_ldap:
            results["gpos"] = self.ldap_collector.collect_gpos(
                target, base_dn, username, password,
            )
            for g in results["gpos"]:
                self.loot.add(
                    loot_type="gpo",
                    value=g.get("display_name") or g.get("cn"),
                    source="ldap_query", module="ad",
                    metadata={"path": g.get("gpc_file_path"), "cn": g.get("cn")},
                )
            self.logger.info(f"GPOs: {len(results['gpos'])}")

        # ── Step 4: Share enumeration ────────────────────────────────
        results["shares"] = self.smb_collector.collect_shares(
            target, username, password, domain, null_session,
        )
        self.logger.info(f"Shares: {len(results['shares'])}")
        for s in results["shares"]:
            if s.get("accessible"):
                self.loot.add_share(
                    share_path=f"//{target}/{s['name']}",
                    permissions=s.get("permissions", "unknown"),
                    source="smbclient", module="ad",
                    anonymous=s.get("anonymous", False),
                )

        # ── Step 5: Domain controllers ───────────────────────────────
        if can_ldap:
            computers = self.ldap_collector.collect_computers(
                target, base_dn, username, password,
            )
            dcs = [c for c in computers if c.get("is_dc")]
            for dc in dcs:
                dc_name = dc.get("dns_hostname") or dc["cn"]
                results["domain_controllers"].append({
                    "hostname": dc_name,
                    "os": dc.get("os"),
                    "os_version": dc.get("os_version"),
                })
                self.loot.add(
                    loot_type="domain_controller", value=dc_name,
                    source="ldap_query", module="ad",
                    confidence="confirmed",
                    metadata={"os": dc.get("os"), "os_version": dc.get("os_version")},
                )

        # ── Step 6: Analysis ─────────────────────────────────────────
        misconfig_input = {"password_policy": results["password_policy"]}
        misconfig_result = self.misconfig_analyzer.analyze(misconfig_input, target=target)
        for f in misconfig_result.findings:
            self.findings.add(**f)

        trust_result = self.trust_analyzer.analyze(
            {"trusts": results["trusts"]}, target=target,
        )
        for f in trust_result.findings:
            self.findings.add(**f)

        perm_input = {"shares": results["shares"]}
        perm_result = self.permission_analyzer.analyze(perm_input, target=target)
        for f in perm_result.findings:
            self.findings.add(**f)

        # Info findings
        if results["gpos"]:
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description=f"{len(results['gpos'])} Group Policy Objects enumerated",
                evidence=", ".join(
                    g.get("display_name") or g.get("cn") for g in results["gpos"][:10]
                ),
            )

        # ── Step 7: Attack paths ─────────────────────────────────────
        gpo_input = {"gpos": results["gpos"], "shares": results["shares"]}
        gpo_paths = self.gpo_builder.build(gpo_input, target=target, domain=domain)

        privesc_input = {
            "password_policy": results["password_policy"],
            "trusts": results["trusts"],
        }
        privesc_paths = self.privesc_builder.build(
            privesc_input, target=target, domain=domain,
        )

        for chain in gpo_paths.chains + privesc_paths.chains:
            self.workflow.add_attack_path(
                name=chain.name, description=chain.description,
                steps=chain.steps, risk=chain.risk,
                prerequisites=chain.prerequisites,
                references=chain.references,
            )
        for s in gpo_paths.suggestions + privesc_paths.suggestions:
            self.workflow.suggest_next(
                command=s.command, justification=s.justification,
                priority=s.priority,
            )

        results["success"] = True
        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Policy: {'extracted' if results['password_policy'] else 'N/A'}, "
            f"Trusts: {len(results['trusts'])}, "
            f"GPOs: {len(results['gpos'])}, "
            f"Shares: {len(results['shares'])}"
        )
        return results

    # ------------------------------------------------------------------
    # Fallback: SMB password policy
    # ------------------------------------------------------------------

    def _enum_password_policy_smb(self, target: str, results: Dict,
                                  username: str, password: str) -> None:
        """Extract password policy via enum4linux-ng (SMB/RPC)."""
        run_result = self.enum4linux_ng.enum_password_policy(
            target, username=username, password=password,
        )
        if not run_result.success:
            return

        parsed = self.enum_parser.parse_text(run_result.stdout)
        if parsed.password_policy:
            pp = parsed.password_policy
            results["password_policy"] = {
                "min_length": int(pp.get("min_length", "0") or "0"),
                "complexity": pp.get("complexity", "").lower() in ("enabled", "true", "1"),
                "lockout_threshold": int(pp.get("lockout_threshold", "0") or "0"),
                "lockout_duration": pp.get("lockout_duration", ""),
                "history_length": int(pp.get("password_history", "0") or "0"),
            }
