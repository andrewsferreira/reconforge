"""ReconForge AD Attack Paths — User → Admin escalation paths.

Author: Andrews Ferreira

Builds comprehensive privilege escalation paths combining
multiple techniques: password spray, trust exploitation, etc.
"""

from typing import Any, Dict
from modules.ad.attack_paths.base import (
    AttackPathBuilderBase, AttackPathResult, AttackChain, NextStepSuggestion,
)


class PrivilegeEscalationPathBuilder(AttackPathBuilderBase):
    """Build privilege escalation paths from combined analysis."""

    BUILDER_NAME = "privesc"

    def build(
        self, analysis_data: Dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        self._build_password_spray(analysis_data, target, domain, result)
        self._build_trust_exploitation(analysis_data, target, domain, result)
        self._build_privileged_targeting(analysis_data, target, domain, result)

        # Phase transition suggestions
        if domain:
            result.suggestions.append(NextStepSuggestion(
                command=f"reconforge ad --target {target} --domain {domain} --phases bloodhound",
                justification="Proceed to Bloodhound Collection for graph-based attack path analysis",
                priority="high",
            ))

        return result

    def _build_password_spray(
        self, data: Dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        policy = data.get("password_policy", {})
        if not policy:
            return

        no_lockout = policy.get("lockout_threshold", 0) == 0
        weak_length = policy.get("min_length", 99) < 8
        no_complexity = not policy.get("complexity", True)

        if no_lockout or (weak_length and no_complexity):
            risk = "high" if no_lockout else "medium"
            result.chains.append(AttackChain(
                name="Weak Password Policy → Password Spraying",
                description="Weak password policy makes spraying viable",
                steps=[
                    "Compile user list from enumeration",
                    f"Policy: minLen={policy.get('min_length', 'N/A')}, "
                    f"lockout={policy.get('lockout_threshold', 'N/A')}",
                    "Spray with common passwords (Season+Year, Company+123)",
                    "Use crackmapexec or kerbrute for spray",
                ],
                risk=risk,
                prerequisites=["User list", "Password policy analysis"],
                references=["https://attack.mitre.org/techniques/T1110/003/"],
                chain_type="password_spray",
            ))
            result.suggestions.append(NextStepSuggestion(
                command=(
                    f"crackmapexec smb {target} -u users.txt -p 'Spring2026!' "
                    f"--continue-on-success"
                ),
                justification=f"Weak policy → password spray viable",
                priority="high",
            ))

    def _build_trust_exploitation(
        self, data: Dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        trusts = data.get("trusts", [])
        for trust in trusts:
            partner = trust.get("partner", "")
            direction = trust.get("direction", "")
            result.chains.append(AttackChain(
                name=f"Trust Exploitation: {partner}",
                description=f"Trust to {partner} ({direction}) may enable lateral movement",
                steps=[
                    f"Enumerate {partner} domain",
                    "Check for SID filtering bypass",
                    "Attempt cross-domain Kerberoasting",
                    "Look for shared service accounts",
                ],
                risk="medium",
                prerequisites=[f"Trust to {partner}"],
                references=["https://attack.mitre.org/techniques/T1482/"],
                chain_type="trust_exploitation",
            ))

    def _build_privileged_targeting(
        self, data: Dict, target: str, domain: str, result: AttackPathResult,
    ) -> None:
        privileged = data.get("privileged_users", [])
        if privileged:
            result.chains.append(AttackChain(
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
                chain_type="privileged_targeting",
            ))
