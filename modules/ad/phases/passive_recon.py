"""ReconForge AD Phase 1 - Passive Reconnaissance.

Performs low-noise reconnaissance of the AD environment:
- DNS SRV record enumeration for DC discovery
- LDAP anonymous bind testing & RootDSE extraction
- SMB null session checks
- NetBIOS / SMB OS discovery
- Kerberos service detection (port 88)
- Domain / forest information gathering

Refactored to delegate to collectors → analyzers → attack_paths pipeline.

Author: Andrews Ferreira
"""

from typing import Any

from modules.ad.analyzers.permission_analyzer import PermissionAnalyzer
from modules.ad.attack_paths.acl_paths import AclPathBuilder
from modules.ad.base import ADPhaseBase
from modules.ad.collectors.dns_collector import DnsCollector
from modules.ad.collectors.kerberos_collector import KerberosCollector
from modules.ad.collectors.ldap_collector import LdapCollector
from modules.ad.collectors.smb_collector import SmbCollector
from modules.ad.parsers.enum4linux_ng_parser import Enum4linuxNgParser
from modules.ad.parsers.ldap_parser import ADLdapParser
from modules.ad.parsers.nmap_parser import ADNmapParser
from modules.ad.parsers.smb_parser import ADSmbParser
from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.nmap import ADNmapTool
from modules.ad.tools.smbclient import ADSmbclientTool


class PassiveReconPhase(ADPhaseBase):
    """Phase 1: Passive AD reconnaissance — low noise, high value.

    Delegates data gathering to collectors and analysis to analyzers.
    """

    PHASE_NUMBER = 1
    PHASE_NAME = "passive_recon"
    PHASE_DESCRIPTION = "Passive AD reconnaissance"

    def __init__(
        self,
        nmap: ADNmapTool,
        ldapsearch: ADLdapsearchTool,
        smbclient: ADSmbclientTool,
        enum4linux_ng: Enum4linuxNgTool,
        nmap_parser: ADNmapParser,
        ldap_parser: ADLdapParser,
        smb_parser: ADSmbParser,
        enum4linux_ng_parser: Enum4linuxNgParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.nmap = nmap
        self.ldapsearch = ldapsearch
        self.smbclient = smbclient
        self.enum4linux_ng = enum4linux_ng
        self.nmap_parser = nmap_parser
        self.ldap_parser = ldap_parser
        self.smb_parser = smb_parser
        self.enum_parser = enum4linux_ng_parser

        # Collector instances
        collector_kwargs = {
            "logger": self.logger, "runner": self.runner,
            "opsec": self.opsec, "output_dir": self.output_dir,
            "opsec_mode": self.opsec_mode,
        }
        self.dns_collector = DnsCollector(
            nmap=nmap, nmap_parser=nmap_parser, **collector_kwargs,
        )
        self.ldap_collector = LdapCollector(
            ldapsearch=ldapsearch, ldap_parser=ldap_parser, **collector_kwargs,
        )
        self.smb_collector = SmbCollector(
            smbclient=smbclient, enum4linux_ng=enum4linux_ng,
            smb_parser=smb_parser, enum4linux_ng_parser=enum4linux_ng_parser,
            **collector_kwargs,
        )
        # Passive recon only ever calls detect_kerberos(), which uses
        # self.nmap alone -- impacket/impacket_parser are never touched
        # here (they back collect_asrep_hashes(), used by later,
        # credentialed phases that construct their own real instances).
        self.kerberos_collector = KerberosCollector(
            nmap=nmap, impacket=None, impacket_parser=None,  # type: ignore[arg-type]
            **collector_kwargs,
        )

        # Analyzer / path builder
        self.permission_analyzer = PermissionAnalyzer()
        self.acl_path_builder = AclPathBuilder()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    # ADPhaseBase.run() declares **kwargs: Any deliberately loosely; every
    # real call site invokes this phase through its concrete type
    # (ad_module.py), never through the base type, so this narrower,
    # self-documenting signature carries no real substitutability risk.
    def run(self, target: str, domain: str = "",  # type: ignore[override]
            opsec_mode: str = "normal") -> dict[str, Any]:
        """Execute passive reconnaissance phase."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"=== AD Phase 1: Passive Reconnaissance on {target} ===")
        self.logger.info(f"{'='*60}")
        self.notes.add_phase_start(self.PHASE_NAME)

        results: dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "target": target,
            "domain": domain,
            "base_dn": "",
            "forest_name": "",
            "functional_level": "",
            "dc_hostname": "",
            "domain_sid": "",
            "anonymous_ldap": False,
            "null_session": False,
            "kerberos_detected": False,
            "smb_signing": "",
            "success": False,
        }

        # ── Step 1: DNS/Nmap service collection ──────────────────────
        ad_svc = self.dns_collector.collect_ad_services(target)
        if ad_svc:
            self._apply_ad_services(ad_svc, results)
            self._record_service_loot(ad_svc, target)

        # ── Step 2: DNS SRV records ──────────────────────────────────
        effective_domain = results.get("domain") or domain
        if effective_domain:
            srv = self.dns_collector.collect_srv_records(target, effective_domain)
            if srv:
                self.loot.add(
                    loot_type="dns_srv", value=srv,
                    source="dns_srv_lookup", module="ad",
                    metadata={"domain": effective_domain, "record_type": "SRV"},
                )

        # ── Step 3: LDAP anonymous bind ──────────────────────────────
        rootdse = self.ldap_collector.collect_rootdse(target)
        self._apply_rootdse(rootdse, results)

        # ── Step 4: SMB null session ─────────────────────────────────
        null_data = self.smb_collector.collect_null_session(target)
        results["null_session"] = null_data.get("allowed", False)
        if results["null_session"]:
            self.logger.finding("medium", "SMB null session ALLOWED — shares accessible anonymously")
            for share in null_data.get("shares", []):
                self.loot.add_share(
                    share_path=f"//{target}/{share['name']}",
                    permissions="anonymous", source="smb_null_session",
                    module="ad", anonymous=True,
                )

        # ── Step 5: Kerberos detection ───────────────────────────────
        if not results["kerberos_detected"]:
            results["kerberos_detected"] = self.kerberos_collector.detect_kerberos(target)
            if results["kerberos_detected"]:
                self.logger.info("Kerberos service confirmed on port 88")
                self.add_finding(
                    finding_type="exposure", severity="info",
                    confidence="confirmed", target=target,
                    description="Kerberos service detected (port 88) — confirms Active Directory",
                )

        # ── Step 6: Analysis via PermissionAnalyzer ──────────────────
        analysis_input = {
            "smb_signing": results["smb_signing"],
            "anonymous_ldap": results["anonymous_ldap"],
            "rootdse": rootdse,
            "null_session": results["null_session"],
            "null_session_shares": null_data.get("shares", []),
        }
        perm_result = self.permission_analyzer.analyze(analysis_input, target=target)
        for f in perm_result.findings:
            self.findings.add(**f)

        # ── Step 7: Attack path suggestions ──────────────────────────
        self._generate_workflow(target, results, perm_result.data)

        # Honest success signal: every probe in this phase is opportunistic
        # (no credentials required by design) and a negative result (e.g.
        # "anonymous LDAP denied") is a legitimate, successful check outcome
        # — not a failure. "success" previously meant only "the method
        # returned without raising" — always True — even when nothing
        # confirmed this target is even a working AD environment. Report
        # that honestly: success requires at least one positive signal.
        if (results["domain"] or results["kerberos_detected"]
                or results["anonymous_ldap"] or results["null_session"]):
            results["success"] = True
        else:
            self.logger.warning(
                "Passive reconnaissance found no positive AD signal — "
                "no domain/forest info, Kerberos, anonymous LDAP, or null session"
            )
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description="Passive reconnaissance found no confirmed Active Directory signal",
                recommendation=(
                    "Verify the target is a domain controller and reachable; "
                    "confirm ports 53/88/389 are open."
                ),
            )

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Domain: {results['domain'] or 'unknown'}, "
            f"Anon LDAP: {results['anonymous_ldap']}, "
            f"Null session: {results['null_session']}"
        )
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _apply_ad_services(self, ad_svc: dict, results: dict) -> None:
        """Apply Nmap AD service data to results."""
        for key in ("domain_name", "forest_name", "dc_hostname",
                     "functional_level", "smb_signing"):
            val = ad_svc.get(key, "")
            if val:
                results_key = {"domain_name": "domain", "ldap_base_dn": "base_dn"}.get(key, key)
                if not results.get(results_key):
                    results[results_key] = val
        if ad_svc.get("ldap_base_dn") and not results["base_dn"]:
            results["base_dn"] = ad_svc["ldap_base_dn"]
        if ad_svc.get("kerberos_detected"):
            results["kerberos_detected"] = True

        # Domain discovered finding
        if ad_svc.get("domain_name"):
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=results["target"],
                description=f"Active Directory domain discovered: {ad_svc['domain_name']}",
                evidence=(
                    f"Domain: {ad_svc.get('domain_name')}\n"
                    f"Forest: {ad_svc.get('forest_name')}\n"
                    f"DC: {ad_svc.get('dc_hostname')}\n"
                    f"Functional Level: {ad_svc.get('functional_level')}\n"
                    f"Base DN: {ad_svc.get('ldap_base_dn')}"
                ),
            )

    def _record_service_loot(self, ad_svc: dict, target: str) -> None:
        """Record discovered services as loot."""
        for svc in ad_svc.get("services", []):
            if svc.get("state") == "open":
                self.loot.add_service(
                    service=svc.get("service") or str(svc.get("port")),
                    version=f"{svc.get('product','')} {svc.get('version','')}".strip(),
                    port=svc.get("port"), source="nmap_ad_scan", module="ad",
                )
        if ad_svc.get("domain_name"):
            self.loot.add(
                loot_type="domain_info", value=ad_svc["domain_name"],
                source="nmap_ad_scan", module="ad", confidence="confirmed",
                metadata={
                    "forest": ad_svc.get("forest_name"),
                    "base_dn": ad_svc.get("ldap_base_dn"),
                    "dc_hostname": ad_svc.get("dc_hostname"),
                    "functional_level": ad_svc.get("functional_level"),
                },
            )

    def _apply_rootdse(self, rootdse: dict, results: dict) -> None:
        """Apply RootDSE data to results."""
        results["anonymous_ldap"] = rootdse.get("anonymous", False)
        if results["anonymous_ldap"]:
            self.logger.finding("medium", "Anonymous LDAP bind ALLOWED — extracting domain info")
            if rootdse.get("base_dn") and not results["base_dn"]:
                results["base_dn"] = rootdse["base_dn"]
            if rootdse.get("domain_name") and not results["domain"]:
                results["domain"] = rootdse["domain_name"]
            if rootdse.get("forest_name") and not results["forest_name"]:
                results["forest_name"] = rootdse["forest_name"]
            if rootdse.get("functional_level") and not results["functional_level"]:
                results["functional_level"] = rootdse["functional_level"]

            self.loot.add(
                loot_type="domain_info",
                value=rootdse.get("domain_name") or rootdse.get("base_dn", ""),
                source="ldap_anonymous", module="ad", confidence="confirmed",
                metadata={
                    "base_dn": rootdse.get("base_dn"),
                    "config_dn": rootdse.get("config_dn"),
                    "schema_dn": rootdse.get("schema_dn"),
                    "forest_name": rootdse.get("forest_name"),
                    "functional_level": rootdse.get("functional_level"),
                    "server_name": rootdse.get("server_name"),
                },
            )
        else:
            self.logger.info("Anonymous LDAP bind denied (expected in hardened environments)")

    def _generate_workflow(self, target: str, results: dict,
                           analysis_data: dict) -> None:
        """Generate attack workflow transitions from Phase 1."""
        domain = results.get("domain", "")
        base_dn = results.get("base_dn", "")

        if results["anonymous_ldap"] and base_dn:
            self.workflow.suggest_next(
                command=f"ldapsearch -x -H ldap://{target} -b '{base_dn}' '(objectClass=user)' sAMAccountName",
                justification="Anonymous LDAP → User Enumeration (no auth required)",
                priority="critical",
            )
            self.workflow.add_attack_path(
                name="Anonymous LDAP → Full Domain Enumeration",
                description="Anonymous LDAP bind allows unauthenticated domain enumeration",
                steps=[
                    f"Anonymous LDAP bind on {target}",
                    "Enumerate users, groups, computers via LDAP",
                    "Extract password policy",
                    "Identify privileged users and service accounts",
                    "Target AS-REP roastable / Kerberoastable accounts",
                ],
                risk="critical",
                prerequisites=["Anonymous LDAP bind enabled"],
                references=["https://attack.mitre.org/techniques/T1087/002/"],
            )

        if results["null_session"]:
            self.workflow.suggest_next(
                command=f"enum4linux-ng -A {target}",
                justification="Null session → Full SMB enumeration",
                priority="critical",
            )
            self.workflow.add_attack_path(
                name="SMB Null Session → User Enumeration → Password Spray",
                description="Null session access allows anonymous user enumeration",
                steps=[
                    f"SMB null session on {target}",
                    "Enumerate users via RID cycling",
                    "Extract password policy",
                    "Password spray with weak/common passwords",
                ],
                risk="high",
                prerequisites=["SMB null session allowed"],
            )

        acl_paths = self.acl_path_builder.build(analysis_data, target=target, domain=domain)
        for chain in acl_paths.chains:
            self.workflow.add_attack_path(
                name=chain.name, description=chain.description,
                steps=chain.steps, risk=chain.risk,
                prerequisites=chain.prerequisites,
                references=chain.references,
            )
        for s in acl_paths.suggestions:
            self.workflow.suggest_next(
                command=s.command, justification=s.justification,
                priority=s.priority,
            )

        if results["kerberos_detected"] and domain:
            self.workflow.suggest_next(
                command=f"GetNPUsers.py {domain}/ -dc-ip {target} -no-pass -usersfile users.txt",
                justification="Kerberos detected → AS-REP roasting",
                priority="high",
            )

        if domain:
            self.workflow.suggest_next(
                command=f"reconforge ad --target {target} --domain {domain} --phases identity",
                justification="Proceed to Phase 2: Identity Enumeration",
                priority="high",
            )
