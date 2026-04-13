"""ReconForge AD Phase 5 - Bloodhound Collection.

Collects comprehensive Active Directory graph data for attack path analysis:
- Run bloodhound-python with appropriate collection methods
- Parse generated JSON files (users, groups, computers, domains, sessions)
- Extract high-value targets from bloodhound data
- Identify shortest paths to Domain Admin
- Generate findings for critical attack paths

Refactored to delegate to collectors → analyzers → attack_paths pipeline.

Author: Andrews Ferreira
"""

from typing import Any, Dict, List

from modules.ad.tools.bloodhound import BloodhoundTool
from modules.ad.tools.netexec import NetexecTool

from modules.ad.parsers.bloodhound_parser import BloodhoundParser
from modules.ad.parsers.netexec_parser import NetexecParser

from modules.ad.collectors.bloodhound_collector import BloodhoundCollector
from modules.ad.analyzers.privilege_analyzer import PrivilegeAnalyzer
from modules.ad.attack_paths.kerberoast_paths import KerberoastPathBuilder
from modules.ad.attack_paths.asrep_paths import AsrepPathBuilder
from modules.ad.attack_paths.delegation_paths import DelegationPathBuilder
from modules.ad.attack_paths.acl_paths import AclPathBuilder

from modules.ad.base import ADPhaseBase


class BloodhoundCollectionPhase(ADPhaseBase):
    """Phase 5: Bloodhound collection — graph data and attack paths."""

    PHASE_NUMBER = 5
    PHASE_NAME = "bloodhound_collection"
    PHASE_DESCRIPTION = "Bloodhound collection and attack path analysis"

    def __init__(
        self,
        bloodhound: BloodhoundTool,
        netexec: NetexecTool,
        bloodhound_parser: BloodhoundParser,
        netexec_parser: NetexecParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.bloodhound = bloodhound
        self.netexec = netexec
        self.bloodhound_parser = bloodhound_parser
        self.netexec_parser = netexec_parser

        # Collector
        collector_kwargs = dict(
            logger=self.logger, runner=self.runner,
            opsec=self.opsec, output_dir=self.output_dir,
            opsec_mode=self.opsec_mode,
        )
        self.bh_collector = BloodhoundCollector(
            bloodhound=bloodhound, netexec=netexec,
            bloodhound_parser=bloodhound_parser,
            netexec_parser=netexec_parser,
            **collector_kwargs,
        )

        # Analyzer & path builders
        self.privilege_analyzer = PrivilegeAnalyzer()
        self.kerberoast_builder = KerberoastPathBuilder()
        self.asrep_builder = AsrepPathBuilder()
        self.delegation_builder = DelegationPathBuilder()
        self.acl_builder = AclPathBuilder()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        target: str,
        domain: str = "",
        username: str = "",
        password: str = "",
        dc_ip: str = "",
        opsec_mode: str = "normal",
    ) -> Dict[str, Any]:
        """Execute bloodhound collection phase."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"=== AD Phase 5: Bloodhound Collection on {target} ===")
        self.logger.info(f"{'='*60}")
        self.notes.add_phase_start(self.PHASE_NAME)

        results: Dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "target": target,
            "domain": domain,
            "users_collected": 0,
            "groups_collected": 0,
            "computers_collected": 0,
            "sessions_collected": 0,
            "domains_collected": 0,
            "high_value_targets": [],
            "da_users": [],
            "unconstrained_computers": [],
            "kerberoastable": [],
            "asreproastable": [],
            "attack_paths": [],
            "collection_method": "",
            "success": False,
        }

        # ── Step 1: Credential check ────────────────────────────────
        if not username or not password:
            self.logger.warning("Bloodhound collection requires authentication")
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description="Bloodhound collection skipped — credentials required",
                recommendation="Provide valid domain credentials for bloodhound collection",
            )
            return results

        # ── Step 2: Collection ───────────────────────────────────────
        collected = self.bh_collector.collect(
            target=target, domain=domain,
            username=username, password=password,
            dc_ip=dc_ip,
        )

        if not collected.success:
            self.logger.warning(
                f"Bloodhound collection failed: {', '.join(collected.errors)}"
            )
            self.notes.add_phase_end(self.PHASE_NAME, "Failed: no data collected")
            return results

        results["collection_method"] = collected.data.get("collection_method", "")
        results["users_collected"] = collected.data.get("users_collected", 0)
        results["groups_collected"] = collected.data.get("groups_collected", 0)
        results["computers_collected"] = collected.data.get("computers_collected", 0)
        results["sessions_collected"] = collected.data.get("sessions_collected", 0)
        results["domains_collected"] = collected.data.get("domains_collected", 0)

        self.logger.info(
            f"Collected: {results['users_collected']} users, "
            f"{results['groups_collected']} groups, "
            f"{results['computers_collected']} computers"
        )

        # ── Step 3: Privilege analysis ───────────────────────────────
        priv_input = {
            "bh_users": collected.data.get("users", []),
            "bh_groups": collected.data.get("groups", []),
            "bh_computers": collected.data.get("computers", []),
        }
        priv_result = self.privilege_analyzer.analyze(priv_input, target=target)
        for f in priv_result.findings:
            self.findings.add(**f)

        results["high_value_targets"] = priv_result.data.get("high_value_targets", [])
        results["da_users"] = priv_result.data.get("da_users", [])
        results["kerberoastable"] = priv_result.data.get("kerberoastable", [])
        results["asreproastable"] = priv_result.data.get("asreproastable", [])
        results["unconstrained_computers"] = priv_result.data.get("unconstrained_computers", [])

        # ── Step 4: DA path identification ───────────────────────────
        attack_paths = self._identify_da_paths(collected.data, results)
        results["attack_paths"] = attack_paths

        # Critical paths finding
        critical_paths = [p for p in attack_paths if p["risk"] == "critical"]
        if critical_paths:
            path_desc = "\n\n".join(
                f"[{p['type']}] {p['source']} → {p['target']}:\n"
                + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(p["steps"]))
                for p in critical_paths[:5]
            )
            self.add_finding(
                finding_type="vulnerability", severity="critical",
                confidence="confirmed", target=target,
                description=f"{len(critical_paths)} critical attack paths to Domain Admin",
                evidence=path_desc,
                recommendation=(
                    "Review and remediate each attack path. Prioritize "
                    "removing unnecessary delegations, SPNs, and pre-auth exemptions."
                ),
                references=["https://bloodhound.readthedocs.io/"],
            )

        # Collection summary finding
        self.add_finding(
            finding_type="exposure", severity="info",
            confidence="confirmed", target=target,
            description=(
                f"Bloodhound collection — "
                f"{results['users_collected']} users, "
                f"{results['groups_collected']} groups, "
                f"{results['computers_collected']} computers"
            ),
            evidence=(
                f"Method: {results['collection_method']}\n"
                f"HVTs: {len(results['high_value_targets'])}\n"
                f"DA members: {len(results['da_users'])}\n"
                f"Attack paths: {len(attack_paths)}"
            ),
        )

        # HVT loot
        for hvt in results["high_value_targets"]:
            self.loot.add(
                loot_type="high_value_target", value=hvt.get("name", ""),
                source="bloodhound_analysis", module="ad",
                confidence="confirmed",
                metadata={"type": hvt.get("type"), "reasons": hvt.get("reasons")},
            )

        # ── Step 5: Attack path building ─────────────────────────────
        path_data = {
            "kerberoastable": results["kerberoastable"],
            "asreproastable": results["asreproastable"],
            "bloodhound_attack_paths": attack_paths,
        }
        for builder in [self.kerberoast_builder, self.asrep_builder, self.acl_builder]:
            bp_result = builder.build(path_data, target=target, domain=domain)
            for chain in bp_result.chains:
                self.workflow.add_attack_path(
                    name=chain.name, description=chain.description,
                    steps=chain.steps, risk=chain.risk,
                    prerequisites=chain.prerequisites,
                    references=chain.references,
                )
            for s in bp_result.suggestions:
                self.workflow.suggest_next(
                    command=s.command, justification=s.justification,
                    priority=s.priority,
                )

        # BH CE recommendation
        self.workflow.suggest_next(
            command="Upload collected JSON/ZIP to BloodHound CE for interactive graph analysis",
            justification="Neo4j-backed queries reveal complex multi-hop attack paths",
            priority="high",
        )

        results["success"] = True
        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"Users: {results['users_collected']}, "
            f"Groups: {results['groups_collected']}, "
            f"HVTs: {len(results['high_value_targets'])}, "
            f"DA: {len(results['da_users'])}"
        )
        return results

    # ------------------------------------------------------------------
    # DA Path Identification
    # ------------------------------------------------------------------

    def _identify_da_paths(self, collected: Dict, results: Dict) -> List[Dict]:
        """Identify potential paths to Domain Admin."""
        paths: List[Dict] = []
        bh_users = collected.get("users", [])
        bh_computers = collected.get("computers", [])

        # Kerberoastable → DA
        for user in bh_users:
            if getattr(user, "has_spn", False) and getattr(user, "enabled", True):
                for gid in getattr(user, "member_of", []):
                    if self._is_privileged_group(gid):
                        paths.append({
                            "type": "kerberoast_to_da",
                            "source": getattr(user, "sam_account_name", ""),
                            "target": "Domain Admin",
                            "steps": [
                                f"Kerberoast {getattr(user, 'sam_account_name', '')}",
                                "Crack TGS hash offline",
                                "Authenticate and escalate via group membership",
                            ],
                            "risk": "critical",
                        })
                        break

        # AS-REP → DA
        for user in bh_users:
            if getattr(user, "dont_req_preauth", False) and getattr(user, "enabled", True):
                for gid in getattr(user, "member_of", []):
                    if self._is_privileged_group(gid):
                        paths.append({
                            "type": "asrep_to_da",
                            "source": getattr(user, "sam_account_name", ""),
                            "target": "Domain Admin",
                            "steps": [
                                f"AS-REP roast {getattr(user, 'sam_account_name', '')}",
                                "Crack hash offline",
                                "Authenticate and escalate",
                            ],
                            "risk": "critical",
                        })
                        break

        # Unconstrained delegation → DA via TGT theft
        for comp in bh_computers:
            if getattr(comp, "unconstraineddelegation", False) and not getattr(comp, "is_dc", False):
                paths.append({
                    "type": "unconstrained_to_da",
                    "source": getattr(comp, "hostname", ""),
                    "target": "Domain Admin",
                    "steps": [
                        f"Compromise {getattr(comp, 'hostname', '')}",
                        "Coerce DC auth (PrinterBug / PetitPotam)",
                        "Capture DC TGT → DCSync",
                    ],
                    "risk": "critical",
                })

        self.logger.info(f"Identified {len(paths)} potential DA attack paths")
        return paths

    @staticmethod
    def _is_privileged_group(group_id: str) -> bool:
        """Check if group ID matches a known privileged group."""
        gl = group_id.lower()
        return any(hvg in gl for hvg in (
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "account operators", "backup operators",
        ))
