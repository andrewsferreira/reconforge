"""ReconForge AD Attack Paths — GPO abuse opportunities.

Author: Andrews Ferreira
"""

from typing import Any, Dict
from modules.ad.attack_paths.base import (
    AttackPathBuilderBase, AttackPathResult, AttackChain, NextStepSuggestion,
)


class GpoPathBuilder(AttackPathBuilderBase):
    """Build GPO abuse attack paths."""

    BUILDER_NAME = "gpo"

    def build(
        self, analysis_data: Dict[str, Any],
        target: str = "", domain: str = "", **kwargs,
    ) -> AttackPathResult:
        result = AttackPathResult(builder=self.BUILDER_NAME)

        gpos = analysis_data.get("gpos", [])
        shares = analysis_data.get("shares", [])

        # GPO credential hunting
        if gpos:
            result.chains.append(AttackChain(
                name="GPO Credential Hunting",
                description="GPOs may contain GPP passwords or sensitive configuration",
                steps=[
                    "Enumerate GPO file paths in SYSVOL",
                    "Search for cpassword in Groups.xml / ScheduledTasks.xml",
                    "Decrypt GPP passwords with gpp-decrypt",
                    "Use recovered credentials for lateral movement",
                ],
                risk="medium",
                prerequisites=["SYSVOL or GPO file path accessible"],
                references=["https://attack.mitre.org/techniques/T1552/006/"],
                chain_type="gpo",
            ))
            result.suggestions.append(NextStepSuggestion(
                command=f"python3 Get-GPPPassword.py or findstr /S cpassword \\\\{target}\\SYSVOL\\",
                justification="Check GPOs for Group Policy Preferences passwords",
                priority="medium",
            ))

        # SYSVOL accessible
        sysvol_accessible = any(
            s.get("name") == "SYSVOL" and s.get("accessible")
            for s in shares
        )
        if sysvol_accessible:
            result.chains.append(AttackChain(
                name="SYSVOL Credential Hunting",
                description="SYSVOL is accessible — may contain GPP passwords or scripts with creds",
                steps=[
                    f"Mount SYSVOL: smbclient //{target}/SYSVOL",
                    "Search for cpassword in XML files (GPP)",
                    "Search for scripts with hardcoded credentials",
                    "Check for sensitive configuration files",
                ],
                risk="medium",
                prerequisites=["SYSVOL share accessible"],
                references=["https://attack.mitre.org/techniques/T1552/006/"],
                chain_type="gpo",
            ))

        return result
