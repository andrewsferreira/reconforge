"""ReconForge AD Phase 2 - Identity Enumeration.

Enumerates AD identities using results from Phase 1:
- User enumeration (LDAP queries, RID cycling, enum4linux-ng)
- Group enumeration (focus on privileged groups)
- Computer account enumeration
- Service account discovery (accounts with SPNs)
- AS-REP roastable user detection (GetNPUsers.py)
- Admin account identification

Refactored to delegate to collectors → analyzers → attack_paths pipeline.

Author: Andrews Ferreira
"""

from typing import Any, Dict, List

from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.enum4linux_ng import Enum4linuxNgTool
from modules.ad.tools.impacket import ImpacketTool
from modules.ad.tools.smbclient import ADSmbclientTool

from modules.ad.parsers.ldap_parser import ADLdapParser
from modules.ad.parsers.enum4linux_ng_parser import Enum4linuxNgParser
from modules.ad.parsers.impacket_parser import ImpacketParser

from modules.ad.collectors.ldap_collector import LdapCollector
from modules.ad.collectors.kerberos_collector import KerberosCollector
from modules.ad.collectors.smb_collector import SmbCollector
from modules.ad.analyzers.relationship_analyzer import RelationshipAnalyzer
from modules.ad.analyzers.misconfiguration_analyzer import MisconfigurationAnalyzer
from modules.ad.attack_paths.kerberoast_paths import KerberoastPathBuilder
from modules.ad.attack_paths.asrep_paths import AsrepPathBuilder

from modules.ad.base import ADPhaseBase


class IdentityEnumerationPhase(ADPhaseBase):
    """Phase 2: Identity enumeration — users, groups, computers, SPNs.

    Delegates collection to LdapCollector / KerberosCollector,
    analysis to RelationshipAnalyzer / MisconfigurationAnalyzer,
    and attack paths to Kerberoast / AsRep builders.
    """

    PHASE_NUMBER = 2
    PHASE_NAME = "identity_enumeration"
    PHASE_DESCRIPTION = "Identity enumeration (users, groups, SPNs)"

    def __init__(
        self,
        ldapsearch: ADLdapsearchTool,
        enum4linux_ng: Enum4linuxNgTool,
        impacket: ImpacketTool,
        smbclient: ADSmbclientTool,
        ldap_parser: ADLdapParser,
        enum4linux_ng_parser: Enum4linuxNgParser,
        impacket_parser: ImpacketParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ldapsearch = ldapsearch
        self.enum4linux_ng = enum4linux_ng
        self.impacket = impacket
        self.smbclient = smbclient
        self.ldap_parser = ldap_parser
        self.enum_parser = enum4linux_ng_parser
        self.impacket_parser = impacket_parser

        # Collectors
        collector_kwargs = dict(
            logger=self.logger, runner=self.runner,
            opsec=self.opsec, output_dir=self.output_dir,
            opsec_mode=self.opsec_mode,
        )
        self.ldap_collector = LdapCollector(
            ldapsearch=ldapsearch, ldap_parser=ldap_parser, **collector_kwargs,
        )
        self.kerberos_collector = KerberosCollector(
            nmap=None, impacket=impacket,
            impacket_parser=impacket_parser, **collector_kwargs,
        )
        self.smb_collector = SmbCollector(
            smbclient=smbclient, enum4linux_ng=enum4linux_ng,
            smb_parser=None, enum4linux_ng_parser=enum4linux_ng_parser,
            **collector_kwargs,
        )

        # Analyzers
        self.relationship_analyzer = RelationshipAnalyzer()
        self.misconfig_analyzer = MisconfigurationAnalyzer()

        # Attack path builders
        self.kerberoast_builder = KerberoastPathBuilder()
        self.asrep_builder = AsrepPathBuilder()

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
        """Execute identity enumeration phase."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"=== AD Phase 2: Identity Enumeration on {target} ===")
        self.logger.info(f"{'='*60}")
        self.notes.add_phase_start(self.PHASE_NAME)

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "target": target,
            "domain": domain,
            "users": [],
            "groups": [],
            "computers": [],
            "service_accounts": [],
            "asrep_users": [],
            "privileged_users": [],
            "total_users": 0,
            "total_groups": 0,
            "total_computers": 0,
            "success": False,
        }

        can_ldap = (anonymous_ldap or (username and password)) and base_dn

        # ── Step 1: LDAP collection ──────────────────────────────────
        if can_ldap:
            users = self.ldap_collector.collect_users(target, base_dn, username, password)
            groups = self.ldap_collector.collect_groups(target, base_dn, username, password)
            computers = self.ldap_collector.collect_computers(target, base_dn, username, password)
            spn_accounts = self.ldap_collector.collect_spn_accounts(target, base_dn, username, password)
            asrep_ldap = self.ldap_collector.collect_asrep_users(target, base_dn, username, password)

            results["users"] = users
            results["groups"] = groups
            results["computers"] = computers
            results["service_accounts"] = spn_accounts
            results["asrep_users"] = [u["username"] for u in asrep_ldap]

            # Add loot
            for u in users:
                self.loot.add_user(
                    username=u["username"], source="ldap_query",
                    module="ad", domain=domain,
                )
            for g in groups:
                self.loot.add(
                    loot_type="group", value=g["cn"],
                    source="ldap_query", module="ad",
                    metadata={"member_count": g["member_count"]},
                )
            for c in computers:
                self.loot.add(
                    loot_type="computer",
                    value=c.get("dns_hostname") or c["cn"],
                    source="ldap_query", module="ad",
                    metadata={"os": c.get("os"), "is_dc": c.get("is_dc")},
                )
            for sa in spn_accounts:
                self.loot.add(
                    loot_type="service_account", value=sa["username"],
                    source="ldap_spn_query", module="ad",
                    confidence="confirmed",
                    metadata={"spn": sa.get("spn"), "admin_count": sa.get("admin_count")},
                )

            self.logger.info(
                f"LDAP: {len(users)} users, {len(groups)} groups, "
                f"{len(computers)} computers, {len(spn_accounts)} SPNs"
            )

        # ── Step 2: RID cycling ──────────────────────────────────────
        if (null_session or opsec_mode == "aggressive") and opsec_mode != "stealth":
            rid = self.kerberos_collector.collect_rid_cycling(
                target, domain, username, password,
            )
            existing = {u["username"] for u in results["users"]}
            for uname in rid.get("users", []):
                if uname not in existing:
                    results["users"].append({"username": uname, "source": "rid_cycling"})
                    self.loot.add_user(
                        username=uname, source="rid_cycling", module="ad", domain=domain,
                    )
            self.logger.info(f"RID cycling: {len(rid.get('users',[]))} users")

        # ── Step 3: AS-REP hashes via impacket ───────────────────────
        asrep_hashes = self.kerberos_collector.collect_asrep_hashes(
            target, domain, username, password,
        )
        for h in asrep_hashes:
            if h["username"] not in results["asrep_users"]:
                results["asrep_users"].append(h["username"])
            self.loot.add_hash(
                hash_value=h["hash"], hash_type="krb5asrep",
                source="GetNPUsers.py", module="ad", username=h["username"],
            )

        # ── Step 4: enum4linux-ng ────────────────────────────────────
        if null_session and self.enum4linux_ng.is_available():
            e4l = self.smb_collector.collect_enum4linux(target, username, password)
            existing = {u["username"] for u in results["users"]}
            for user in e4l.get("users", []):
                uname = user.get("username", "")
                if uname and uname not in existing:
                    results["users"].append(user)
                    self.loot.add_user(
                        username=uname, source="enum4linux-ng",
                        module="ad", domain=domain,
                    )

        # ── Step 5: Analysis ─────────────────────────────────────────
        rel_result = self.relationship_analyzer.analyze(
            {"users": results["users"], "groups": results["groups"],
             "computers": results["computers"]},
            target=target,
        )
        results["privileged_users"] = rel_result.data.get("privileged_users", [])
        for f in rel_result.findings:
            self.findings.add(**f)

        misconfig_input = {
            "spn_accounts": results["service_accounts"],
            "asrep_users": [{"username": u} for u in results["asrep_users"]],
        }
        misconfig_result = self.misconfig_analyzer.analyze(misconfig_input, target=target)
        for f in misconfig_result.findings:
            self.findings.add(**f)

        # Info finding: enumeration summary
        if results["users"]:
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description=f"{len(results['users'])} domain users enumerated",
                evidence=f"Sample: {', '.join(u['username'] for u in results['users'][:10])}",
            )

        # ── Step 6: Attack paths ─────────────────────────────────────
        path_input = {
            "spn_accounts": results["service_accounts"],
            "kerberoastable": [sa["username"] for sa in results["service_accounts"]],
            "asrep_users": [{"username": u} for u in results["asrep_users"]],
            "asreproastable": results["asrep_users"],
            "privileged_users": results["privileged_users"],
        }
        kerb_paths = self.kerberoast_builder.build(path_input, target=target, domain=domain)
        asrep_paths = self.asrep_builder.build(path_input, target=target, domain=domain)

        for chain in kerb_paths.chains + asrep_paths.chains:
            self.workflow.add_attack_path(
                name=chain.name, description=chain.description,
                steps=chain.steps, risk=chain.risk,
                prerequisites=chain.prerequisites,
                references=chain.references,
            )
        for s in kerb_paths.suggestions + asrep_paths.suggestions:
            self.workflow.suggest_next(
                command=s.command, justification=s.justification,
                priority=s.priority,
            )

        # Privileged targeting
        if results["privileged_users"]:
            self.workflow.add_attack_path(
                name="Privileged Account Targeting",
                description="Known privileged accounts can be targeted",
                steps=[
                    "Target privileged users with phishing/credential harvesting",
                    "Check for password reuse across services",
                    "Attempt Kerberoasting if accounts have SPNs",
                    "Check for AS-REP roastability",
                ],
                risk="critical",
                prerequisites=["Privileged user list obtained"],
            )

        if results["users"]:
            self.workflow.suggest_next(
                command=f"reconforge ad --target {target} --domain {domain} --phases configuration",
                justification="Proceed to Phase 3: Configuration Enumeration",
                priority="high",
            )

        # ── Finalise ─────────────────────────────────────────────────
        results["total_users"] = len(results["users"])
        results["total_groups"] = len(results["groups"])
        results["total_computers"] = len(results["computers"])

        # Honest success signal: this phase has several independent,
        # best-effort collection paths (LDAP, RID cycling, AS-REP roasting,
        # enum4linux-ng) that can each legitimately return nothing (e.g. no
        # creds, stealth mode, hardened target) without any single call
        # actually failing. "success" previously meant only "the method
        # returned without raising" — always True — masking the case where
        # every path came back empty and the phase collected zero identity
        # data. Report that honestly instead.
        if (results["users"] or results["computers"]
                or results["service_accounts"] or results["asrep_users"]):
            results["success"] = True
        else:
            self.logger.warning(
                "Identity enumeration collected no data — no usable "
                "credentials/null-session/anonymous access"
            )
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description="Identity enumeration collected no users, computers, or service accounts",
                recommendation=(
                    "Provide domain credentials, or confirm null-session/anonymous "
                    "LDAP access, then re-run identity enumeration."
                ),
            )

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Users: {results['total_users']}, Groups: {results['total_groups']}, "
            f"Computers: {results['total_computers']}, "
            f"SPNs: {len(results['service_accounts'])}, "
            f"AS-REP: {len(results['asrep_users'])}"
        )

        return results
