"""ReconForge AD Attack Paths — ACL abuse chains.

Author: Andrews Ferreira

Identifies ACL-based attack paths: GenericAll, WriteDacl,
GenericWrite, ForceChangePassword, etc.
"""

from typing import Any

from modules.ad.attack_paths.base import (
    AttackChain,
    AttackPathBuilderBase,
    AttackPathResult,
    NextStepSuggestion,
)


class AclPathBuilder(AttackPathBuilderBase):
    """Build ACL abuse attack paths from Bloodhound data."""

    BUILDER_NAME = "acl"

    def build(
        self, analysis_data: dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        # Bloodhound attack paths (pre-computed in privilege analyzer)
        bh_paths = analysis_data.get("bloodhound_attack_paths", [])

        for path in bh_paths:
            path_type = path.get("type", "")
            source = path.get("source", "")
            path_target = path.get("target", "")
            steps = path.get("steps", [])
            risk = path.get("risk", "high")

            result.chains.append(AttackChain(
                name=f"Attack Path: {path_type}",
                description=f"{source} → {path_target}",
                steps=steps,
                risk=risk,
                source=source,
                target=path_target,
                chain_type=path_type,
            ))

        # Session-based credential theft
        session_paths = analysis_data.get("session_paths", [])
        for sp in session_paths:
            result.chains.append(AttackChain(
                name=f"Session Credential Theft: {sp.get('host', '')}",
                description=f"DA session on {sp.get('host', '')}",
                steps=[
                    f"Gain admin access to {sp.get('host', '')}",
                    f"Extract credentials for {sp.get('user', '')} (active session)",
                    "Authenticate as Domain Admin",
                ],
                risk="critical",
                source=sp.get("host", ""),
                target=sp.get("user", ""),
                chain_type="session_to_da",
            ))

        # SMB relay if applicable
        if analysis_data.get("smb_relay_viable"):
            result.chains.append(AttackChain(
                name="SMB Relay Attack",
                description="SMB signing not required — NTLM relay attacks possible",
                steps=[
                    "Set up ntlmrelayx.py listener",
                    "Trigger authentication (Responder / PetitPotam)",
                    "Relay credentials to target services",
                ],
                risk="high",
                prerequisites=["SMB signing disabled/not required", "Network MitM position"],
                references=["https://attack.mitre.org/techniques/T1557/001/"],
                chain_type="smb_relay",
            ))
            result.suggestions.append(NextStepSuggestion(
                command="ntlmrelayx.py -tf targets.txt -smb2support",
                justification="SMB signing disabled → relay attack vector",
                priority="high",
            ))

        return result
