"""ReconForge AD Phase 4 - Delegation Discovery.

Discovers delegation configurations across the AD environment:
- Unconstrained delegation (TrustedForDelegation / UAC 524288)
- Constrained delegation (msDS-AllowedToDelegateTo)
- Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
- Machine Account Quota (for RBCD attack feasibility)
- Cross-reference with impacket findDelegation.py

Refactored to delegate to collectors → analyzers → attack_paths pipeline.

Author: Andrews Ferreira
"""

from typing import Any

from modules.ad.analyzers.misconfiguration_analyzer import MisconfigurationAnalyzer
from modules.ad.attack_paths.delegation_paths import DelegationPathBuilder
from modules.ad.base import ADPhaseBase
from modules.ad.collectors.delegation_collector import DelegationCollector
from modules.ad.parsers.delegation_parser import DelegationParser
from modules.ad.parsers.ldap_parser import ADLdapParser
from modules.ad.tools.advanced_impacket import AdvancedImpacketTool
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.netexec import NetexecTool


class DelegationDiscoveryPhase(ADPhaseBase):
    """Phase 4: Delegation discovery — unconstrained, constrained, RBCD."""

    PHASE_NUMBER = 4
    PHASE_NAME = "delegation_discovery"
    PHASE_DESCRIPTION = "Delegation discovery (unconstrained, constrained, RBCD)"

    def __init__(
        self,
        ldapsearch: ADLdapsearchTool,
        advanced_impacket: AdvancedImpacketTool,
        netexec: NetexecTool,
        ldap_parser: ADLdapParser,
        delegation_parser: DelegationParser,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.ldapsearch = ldapsearch
        self.advanced_impacket = advanced_impacket
        self.netexec = netexec
        self.ldap_parser = ldap_parser
        self.delegation_parser = delegation_parser

        # Collector
        collector_kwargs = {
            "logger": self.logger, "runner": self.runner,
            "opsec": self.opsec, "output_dir": self.output_dir,
            "opsec_mode": self.opsec_mode,
        }
        self.delegation_collector = DelegationCollector(
            ldapsearch=ldapsearch,
            advanced_impacket=advanced_impacket,
            netexec=netexec,
            ldap_parser=ldap_parser,
            delegation_parser=delegation_parser,
            **collector_kwargs,
        )

        # Analyzer & path builder
        self.misconfig_analyzer = MisconfigurationAnalyzer()
        self.delegation_path_builder = DelegationPathBuilder()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    # ADPhaseBase.run() declares **kwargs: Any deliberately loosely; every
    # real call site invokes this phase through its concrete type
    # (ad_module.py), never through the base type, so this narrower,
    # self-documenting signature carries no real substitutability risk.
    def run(  # type: ignore[override]
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        opsec_mode: str = "normal",
    ) -> dict[str, Any]:
        """Execute delegation discovery phase."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"=== AD Phase 4: Delegation Discovery on {target} ===")
        self.logger.info(f"{'='*60}")
        self.notes.add_phase_start(self.PHASE_NAME)

        results: dict[str, Any] = {
            "phase": self.PHASE_NAME,
            "target": target,
            "domain": domain,
            "unconstrained_delegation": [],
            "constrained_delegation": [],
            "rbcd": [],
            "machine_account_quota": -1,
            "total_unconstrained": 0,
            "total_constrained": 0,
            "total_rbcd": 0,
            "success": False,
        }

        # ── Step 1: Collection ───────────────────────────────────────
        collected = self.delegation_collector.collect(
            target=target, domain=domain, base_dn=base_dn,
            username=username, password=password,
        )

        if not collected.success:
            self.logger.warning(
                f"Delegation collection did not complete: {', '.join(collected.errors)}"
            )
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description="Delegation discovery could not run any query — results incomplete",
                evidence="; ".join(collected.errors) or "No delegation query completed",
                recommendation=(
                    "Provide domain credentials and confirm ldapsearch/impacket "
                    "connectivity, then re-run delegation discovery."
                ),
            )
            self.notes.add_phase_end(self.PHASE_NAME, "Failed: no delegation data collected")
            return results

        results["unconstrained_delegation"] = collected.data.get("unconstrained", [])
        results["constrained_delegation"] = collected.data.get("constrained", [])
        results["rbcd"] = collected.data.get("rbcd", [])
        results["machine_account_quota"] = collected.data.get("machine_account_quota", -1)

        self.logger.info(
            f"Delegation: UC={len(results['unconstrained_delegation'])}, "
            f"CD={len(results['constrained_delegation'])}, "
            f"RBCD={len(results['rbcd'])}, "
            f"MAQ={results['machine_account_quota']}"
        )

        # ── Step 2: Loot ─────────────────────────────────────────────
        self._record_delegation_loot(results)

        # ── Step 3: Analysis ─────────────────────────────────────────
        analysis_input = {
            "unconstrained_delegation": results["unconstrained_delegation"],
            "constrained_delegation": results["constrained_delegation"],
            "rbcd": results["rbcd"],
            "machine_account_quota": results["machine_account_quota"],
        }
        misconfig_result = self.misconfig_analyzer.analyze(analysis_input, target=target)
        for f in misconfig_result.findings:
            self.findings.add(**f)

        # DC unconstrained (informational)
        dc_uc = [e for e in results["unconstrained_delegation"]
                 if getattr(e, "is_dc", False)]
        if dc_uc:
            self.add_finding(
                finding_type="exposure", severity="info",
                confidence="confirmed", target=target,
                description=f"Domain Controllers with unconstrained delegation (expected): {len(dc_uc)}",
                evidence=", ".join(getattr(e, "account_name", str(e)) for e in dc_uc),
            )

        # Constrained without protocol transition
        no_proto = [e for e in results["constrained_delegation"]
                    if not getattr(e, "protocol_transition", False)]
        if no_proto:
            detail = "\n".join(
                f"  {getattr(e, 'account_name', '')} → "
                f"{', '.join(getattr(e, 'allowed_to_delegate_to', []))}"
                for e in no_proto
            )
            self.add_finding(
                finding_type="exposure", severity="high",
                confidence="confirmed", target=target,
                description=f"Constrained delegation (no protocol transition) on {len(no_proto)} account(s)",
                evidence=f"Accounts:\n{detail}",
                recommendation="Review delegation targets; ensure only required services listed.",
            )

        # ── Step 4: Attack paths ─────────────────────────────────────
        path_input = {
            "unconstrained_delegation": results["unconstrained_delegation"],
            "constrained_delegation": results["constrained_delegation"],
            "rbcd": results["rbcd"],
            "machine_account_quota": results["machine_account_quota"],
        }
        deleg_paths = self.delegation_path_builder.build(
            path_input, target=target, domain=domain,
        )
        for chain in deleg_paths.chains:
            self.workflow.add_attack_path(
                name=chain.name, description=chain.description,
                steps=chain.steps, risk=chain.risk,
                prerequisites=chain.prerequisites,
                references=chain.references,
            )
        for s in deleg_paths.suggestions:
            self.workflow.suggest_next(
                command=s.command, justification=s.justification,
                priority=s.priority,
            )

        # Phase transition
        if domain:
            self.workflow.suggest_next(
                command=f"reconforge ad --target {target} --domain {domain} --phases bloodhound",
                justification="Proceed to Phase 5: Bloodhound Collection",
                priority="high",
            )

        # ── Finalise ─────────────────────────────────────────────────
        results["total_unconstrained"] = len(results["unconstrained_delegation"])
        results["total_constrained"] = len(results["constrained_delegation"])
        results["total_rbcd"] = len(results["rbcd"])
        results["success"] = True

        self.notes.add_phase_end(
            self.PHASE_NAME,
            f"UC: {results['total_unconstrained']}, "
            f"CD: {results['total_constrained']}, "
            f"RBCD: {results['total_rbcd']}, "
            f"MAQ: {results['machine_account_quota']}"
        )
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _record_delegation_loot(self, results: dict) -> None:
        """Record delegation data as loot entries."""
        for entry in results["unconstrained_delegation"]:
            if not getattr(entry, "is_dc", False):
                self.loot.add(
                    loot_type="delegation",
                    value=getattr(entry, "account_name", str(entry)),
                    source="delegation_discovery", module="ad",
                    confidence="confirmed",
                    metadata={
                        "type": "unconstrained",
                        "account_type": getattr(entry, "account_type", ""),
                        "dn": getattr(entry, "dn", ""),
                    },
                )

        for entry in results["constrained_delegation"]:
            self.loot.add(
                loot_type="delegation",
                value=getattr(entry, "account_name", str(entry)),
                source="delegation_discovery", module="ad",
                confidence="confirmed",
                metadata={
                    "type": "constrained",
                    "protocol_transition": getattr(entry, "protocol_transition", False),
                    "targets": getattr(entry, "allowed_to_delegate_to", []),
                },
            )

        for entry in results["rbcd"]:
            self.loot.add(
                loot_type="delegation",
                value=getattr(entry, "target_account", str(entry)),
                source="delegation_discovery", module="ad",
                confidence="confirmed",
                metadata={
                    "type": "rbcd",
                    "allowed_principals": getattr(entry, "allowed_principals", []),
                    "dn": getattr(entry, "target_dn", ""),
                },
            )

        maq = results.get("machine_account_quota", -1)
        if maq >= 0:
            self.loot.add(
                loot_type="config",
                value=f"MachineAccountQuota={maq}",
                source="ldap_maq_query", module="ad",
                confidence="confirmed",
                metadata={"quota": maq},
            )
