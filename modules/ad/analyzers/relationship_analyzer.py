"""ReconForge AD Analyzer — Relationship & group membership analysis.

Author: Andrews Ferreira

Analyzes group memberships, nesting, privileged groups, and
identifies high-value identity relationships.
"""

from typing import Any, Dict, List, Set
from modules.ad.analyzers.base import AnalyzerBase, AnalysisResult


PRIVILEGED_GROUPS: Set[str] = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
}


class RelationshipAnalyzer(AnalyzerBase):
    """Analyze AD relationship/group membership data."""

    ANALYZER_NAME = "relationships"

    def analyze(self, collected_data: Dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze identity relationships.

        Expected keys:
            - users: list of user dicts
            - groups: list of group dicts
            - computers: list of computer dicts
        """
        target = kwargs.get("target", "")
        result = AnalysisResult(analyzer=self.ANALYZER_NAME)

        users = collected_data.get("users", [])
        groups = collected_data.get("groups", [])
        computers = collected_data.get("computers", [])

        # Identify privileged users
        privileged_users = self._find_privileged_users(users)
        result.data["privileged_users"] = privileged_users

        if privileged_users:
            result.findings.append(self._make_finding(
                finding_type="exposure",
                severity="critical",
                confidence="confirmed",
                target=target,
                description=f"Privileged user accounts discovered ({len(privileged_users)})",
                evidence=f"Privileged users: {', '.join(privileged_users[:20])}",
                recommendation="Audit privileged accounts, enforce tiered admin model",
                references=["https://attack.mitre.org/techniques/T1087/002/"],
                phase="identity_enumeration",
            ))

        # Privileged group membership analysis
        priv_groups = self._analyze_privileged_groups(groups, target)
        result.findings.extend(priv_groups["findings"])
        result.data["privileged_groups"] = priv_groups["groups"]

        # Domain controllers
        dcs = [c for c in computers if c.get("is_dc")]
        result.data["domain_controllers"] = [
            c.get("dns_hostname") or c.get("cn") for c in dcs
        ]
        if dcs:
            dc_names = ", ".join(result.data["domain_controllers"])
            result.findings.append(self._make_finding(
                finding_type="exposure",
                severity="info",
                confidence="confirmed",
                target=target,
                description=f"Domain controller(s) enumerated: {dc_names}",
                evidence=f"DC count: {len(dcs)}",
                phase="identity_enumeration",
            ))

        # Summary counts
        result.data["total_users"] = len(users)
        result.data["total_groups"] = len(groups)
        result.data["total_computers"] = len(computers)
        result.insights.append(
            f"Enumerated {len(users)} users, {len(groups)} groups, "
            f"{len(computers)} computers"
        )

        return result

    def _find_privileged_users(self, users: List[Dict]) -> List[str]:
        """Return list of privileged usernames."""
        privileged: List[str] = []
        for u in users:
            if u.get("is_admin"):
                privileged.append(u["username"])
                continue
            for group_dn in u.get("member_of", []):
                for pg in PRIVILEGED_GROUPS:
                    if pg.lower() in group_dn.lower():
                        privileged.append(u["username"])
                        break
        return list(set(privileged))

    def _analyze_privileged_groups(
        self, groups: List[Dict], target: str,
    ) -> Dict[str, Any]:
        """Analyze privileged groups and generate findings."""
        findings: List[Dict] = []
        priv_group_info: List[Dict] = []

        for g in groups:
            cn = g.get("cn", "")
            if cn not in PRIVILEGED_GROUPS:
                continue
            members = g.get("members", [])
            member_names = [self._dn_to_username(m) for m in members[:20]]
            priv_group_info.append({
                "name": cn,
                "member_count": len(members),
                "members": member_names,
            })
            if member_names:
                findings.append(self._make_finding(
                    finding_type="exposure",
                    severity="high",
                    confidence="confirmed",
                    target=target,
                    description=f"Privileged group '{cn}' has {len(members)} member(s)",
                    evidence=f"Members: {', '.join(member_names)}",
                    recommendation=f"Audit {cn} membership — apply least privilege",
                    phase="identity_enumeration",
                ))
        return {"findings": findings, "groups": priv_group_info}

    @staticmethod
    def _dn_to_username(dn: str) -> str:
        """Extract CN from a distinguished name."""
        for part in dn.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
        return dn
