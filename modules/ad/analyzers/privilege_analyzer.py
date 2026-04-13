"""ReconForge AD Analyzer — Privilege & admin rights analysis.

Author: Andrews Ferreira

Analyzes delegation abuse potential, admin rights distribution,
and high-value target identification from Bloodhound data.
"""

from typing import Any, Dict, List, Set
from modules.ad.analyzers.base import AnalyzerBase, AnalysisResult


HIGH_VALUE_GROUPS: Set[str] = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "dnsadmins",
    "group policy creator owners",
    "exchange windows permissions",
    "exchange trusted subsystem",
}


class PrivilegeAnalyzer(AnalyzerBase):
    """Analyze admin rights and high-value targets."""

    ANALYZER_NAME = "privileges"

    def analyze(self, collected_data: Dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze privilege structure from Bloodhound or LDAP data.

        Expected keys (Bloodhound):
            - bh_users: list of BloodhoundUser objects
            - bh_groups: list of BloodhoundGroup objects
            - bh_computers: list of BloodhoundComputer objects
        """
        target = kwargs.get("target", "")
        result = AnalysisResult(analyzer=self.ANALYZER_NAME)

        bh_users = collected_data.get("bh_users", [])
        bh_groups = collected_data.get("bh_groups", [])
        bh_computers = collected_data.get("bh_computers", [])

        hvts: List[Dict] = []
        da_users: List[str] = []
        kerberoastable: List[str] = []
        asreproastable: List[str] = []
        unconstrained_computers: List[str] = []

        # Analyze users
        for user in bh_users:
            reasons: List[str] = []
            is_hvt = False

            if getattr(user, "is_high_value", False):
                is_hvt = True
                reasons.append("Marked as high value")
            if getattr(user, "admin_count", False):
                is_hvt = True
                reasons.append("AdminCount=1")
            if getattr(user, "unconstraineddelegation", False):
                is_hvt = True
                reasons.append("Unconstrained delegation")
            if getattr(user, "has_spn", False) and getattr(user, "enabled", True):
                kerberoastable.append(getattr(user, "sam_account_name", ""))
                reasons.append("Kerberoastable")
            if getattr(user, "dont_req_preauth", False) and getattr(user, "enabled", True):
                asreproastable.append(getattr(user, "sam_account_name", ""))
                reasons.append("AS-REP roastable")

            if is_hvt:
                hvts.append({
                    "name": getattr(user, "sam_account_name", ""),
                    "type": "user",
                    "reasons": reasons,
                    "enabled": getattr(user, "enabled", True),
                })

        # Analyze groups
        for group in bh_groups:
            gname = (getattr(group, "name", "") or "").lower()
            pname = (getattr(group, "principal_name", "") or "").lower()

            is_priv = any(hvg in gname or hvg in pname for hvg in HIGH_VALUE_GROUPS)
            if is_priv or getattr(group, "is_high_value", False):
                member_count = getattr(group, "member_count", 0)
                hvts.append({
                    "name": getattr(group, "name", "") or getattr(group, "principal_name", ""),
                    "type": "group",
                    "reasons": [f"Privileged group with {member_count} members"],
                    "member_count": member_count,
                })

                # Track DA members
                if "domain admins" in gname or "domain admins" in pname:
                    for member in getattr(group, "members", []):
                        mid = member.get("ObjectIdentifier", "") if isinstance(member, dict) else str(member)
                        if mid:
                            da_users.append(mid)

        # Analyze computers
        for comp in bh_computers:
            if getattr(comp, "unconstraineddelegation", False) and not getattr(comp, "is_dc", False):
                hostname = getattr(comp, "hostname", "")
                unconstrained_computers.append(hostname)
                hvts.append({
                    "name": hostname,
                    "type": "computer",
                    "reasons": ["Unconstrained delegation (non-DC)"],
                })

        # Generate findings
        if kerberoastable:
            result.findings.append(self._make_finding(
                finding_type="vulnerability", severity="high",
                confidence="confirmed", target=target,
                description=f"{len(kerberoastable)} Kerberoastable accounts discovered",
                evidence=f"Accounts: {', '.join(kerberoastable[:20])}",
                recommendation="Remove unnecessary SPNs. Use gMSA.",
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                phase="bloodhound_collection",
            ))

        if asreproastable:
            result.findings.append(self._make_finding(
                finding_type="vulnerability", severity="high",
                confidence="confirmed", target=target,
                description=f"{len(asreproastable)} AS-REP roastable accounts discovered",
                evidence=f"Accounts: {', '.join(asreproastable[:20])}",
                recommendation="Enable pre-authentication for all accounts.",
                references=["https://attack.mitre.org/techniques/T1558/004/"],
                phase="bloodhound_collection",
            ))

        if unconstrained_computers:
            result.findings.append(self._make_finding(
                finding_type="misconfiguration", severity="critical",
                confidence="confirmed", target=target,
                description=f"{len(unconstrained_computers)} non-DC computers with unconstrained delegation",
                evidence=f"Hosts: {', '.join(unconstrained_computers[:10])}",
                recommendation="Replace unconstrained delegation with constrained delegation or RBCD.",
                references=["https://attack.mitre.org/techniques/T1558/"],
                phase="bloodhound_collection",
            ))

        result.data["high_value_targets"] = hvts
        result.data["da_users"] = da_users
        result.data["kerberoastable"] = kerberoastable
        result.data["asreproastable"] = asreproastable
        result.data["unconstrained_computers"] = unconstrained_computers

        return result
