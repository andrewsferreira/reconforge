"""ReconForge AD Analyzer — Permission & ACL analysis.

Author: Andrews Ferreira

Analyzes access control: SMB signing, anonymous LDAP, null sessions,
share permissions, admin share exposure.
"""

from typing import Any

from modules.ad.analyzers.base import AnalysisResult, AnalyzerBase


class PermissionAnalyzer(AnalyzerBase):
    """Analyze AD permission posture from collected data."""

    ANALYZER_NAME = "permissions"

    def analyze(self, collected_data: dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze permission-related data.

        Expected keys in collected_data:
            - smb_signing: str ("disabled", "enabled_not_required", etc.)
            - anonymous_ldap: bool
            - null_session: bool
            - shares: list of share dicts
        """
        target = kwargs.get("target", "")
        result = AnalysisResult(analyzer=self.ANALYZER_NAME)

        # SMB signing analysis
        smb_signing = collected_data.get("smb_signing", "")
        if smb_signing in ("disabled", "enabled_not_required"):
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="high",
                confidence="confirmed",
                target=target,
                description="SMB signing is not required — relay attack possible",
                evidence=f"SMB signing status: {smb_signing}",
                recommendation="Enable and require SMB signing on all domain controllers",
                references=["https://attack.mitre.org/techniques/T1557/001/"],
                phase="passive_recon",
            ))
            result.insights.append("SMB relay attacks are viable")
            result.data["smb_relay_viable"] = True

        # Anonymous LDAP
        if collected_data.get("anonymous_ldap"):
            rootdse = collected_data.get("rootdse", {})
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description="Anonymous LDAP bind is enabled on the domain controller",
                evidence=(
                    f"Base DN: {rootdse.get('base_dn', 'N/A')}\n"
                    f"Domain: {rootdse.get('domain_name', 'N/A')}\n"
                    f"Forest: {rootdse.get('forest_name', 'N/A')}"
                ),
                recommendation=(
                    "Disable anonymous LDAP bind: set dsHeuristics attribute "
                    "fLDAPBlockAnonOps or restrict via network policy"
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1018/",
                    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/"
                    "identity/anonymous-ldap-operations-active-directory-disabled",
                ],
                phase="passive_recon",
            ))
            result.insights.append("Anonymous LDAP allows unauthenticated enumeration")

        # Null session
        if collected_data.get("null_session"):
            null_shares = collected_data.get("null_session_shares", [])
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description="SMB null session is allowed — anonymous share enumeration possible",
                evidence=f"Shares found: {', '.join(s.get('name','') for s in null_shares)}",
                recommendation="Disable null session access via Group Policy (RestrictAnonymous)",
                references=["https://attack.mitre.org/techniques/T1021/002/"],
                phase="passive_recon",
            ))

        # Share access analysis
        shares = collected_data.get("shares", [])
        accessible = [s for s in shares if s.get("accessible")]
        if accessible:
            share_names = ", ".join(s["name"] for s in accessible)
            severity = "high" if any(s.get("anonymous") for s in accessible) else "medium"
            result.findings.append(self._make_finding(
                finding_type="exposure",
                severity=severity,
                confidence="confirmed",
                target=target,
                description=f"Accessible SMB shares: {share_names}",
                evidence=f"Shares: {share_names}",
                recommendation=(
                    "Review share permissions. Remove anonymous access. "
                    "Ensure SYSVOL/NETLOGON don't contain sensitive scripts."
                ),
                phase="configuration_enumeration",
            ))
            result.data["accessible_shares"] = [s["name"] for s in accessible]

        return result
