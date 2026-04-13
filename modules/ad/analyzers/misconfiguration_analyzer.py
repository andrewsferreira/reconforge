"""ReconForge AD Analyzer — Misconfiguration detection.

Author: Andrews Ferreira

Analyzes password policies, delegation configs, Kerberos settings,
and other common AD misconfigurations.
"""

from typing import Any, Dict, List
from modules.ad.analyzers.base import AnalyzerBase, AnalysisResult


class MisconfigurationAnalyzer(AnalyzerBase):
    """Detect AD misconfigurations from collected data."""

    ANALYZER_NAME = "misconfigurations"

    def analyze(self, collected_data: Dict[str, Any], **kwargs) -> AnalysisResult:
        """Analyze for misconfigurations.

        Expected keys:
            - password_policy: dict
            - unconstrained_delegation: list
            - constrained_delegation: list
            - rbcd: list
            - machine_account_quota: int
            - spn_accounts: list
            - asrep_users: list
        """
        target = kwargs.get("target", "")
        result = AnalysisResult(analyzer=self.ANALYZER_NAME)

        self._analyze_password_policy(collected_data, target, result)
        self._analyze_delegation(collected_data, target, result)
        self._analyze_kerberos(collected_data, target, result)
        self._analyze_maq(collected_data, target, result)

        return result

    # ── Password policy ───────────────────────────────────────────

    def _analyze_password_policy(
        self, data: Dict, target: str, result: AnalysisResult,
    ) -> None:
        policy = data.get("password_policy", {})
        if not policy:
            return

        result.data["password_policy"] = policy

        # No complexity
        if not policy.get("complexity"):
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description="Password complexity is not enforced",
                evidence="pwdProperties indicates complexity disabled",
                recommendation="Enable password complexity requirements via Default Domain Policy",
                references=["https://attack.mitre.org/techniques/T1110/003/"],
                phase="configuration_enumeration",
            ))

        # Short minimum length
        min_len = policy.get("min_length", 99)
        if min_len < 8:
            sev = "critical" if min_len < 5 else "high"
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity=sev,
                confidence="confirmed",
                target=target,
                description=f"Minimum password length is only {min_len} characters",
                evidence=f"minPwdLength: {min_len}",
                recommendation="Set minimum password length to at least 12 characters",
                phase="configuration_enumeration",
            ))

        # No lockout
        lockout = policy.get("lockout_threshold", 0)
        if lockout == 0:
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description="No account lockout threshold — unlimited password guessing",
                evidence="lockoutThreshold: 0",
                recommendation="Set account lockout threshold (e.g., 5 attempts)",
                references=["https://attack.mitre.org/techniques/T1110/"],
                phase="configuration_enumeration",
            ))
            result.data["password_spray_viable"] = True

        # No history
        if policy.get("history_length", 0) == 0:
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="medium",
                confidence="confirmed",
                target=target,
                description="No password history — users can reuse passwords",
                evidence="pwdHistoryLength: 0",
                recommendation="Set password history to at least 12 remembered passwords",
                phase="configuration_enumeration",
            ))

    # ── Delegation ───────────────────────────────────────────────

    def _analyze_delegation(
        self, data: Dict, target: str, result: AnalysisResult,
    ) -> None:
        # Unconstrained non-DC
        unconstrained = data.get("unconstrained_delegation", [])
        non_dc = [e for e in unconstrained if not getattr(e, "is_dc", False)]
        if non_dc:
            accounts = ", ".join(getattr(e, "account_name", str(e)) for e in non_dc)
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description=f"Unconstrained delegation found on {len(non_dc)} non-DC account(s)",
                evidence=f"Accounts: {accounts}",
                recommendation=(
                    "Replace unconstrained delegation with constrained delegation "
                    "or RBCD. Remove TrustedForDelegation flag from non-DC accounts."
                ),
                references=["https://attack.mitre.org/techniques/T1558/"],
                phase="delegation_discovery",
            ))

        # Constrained with protocol transition
        constrained = data.get("constrained_delegation", [])
        proto_trans = [e for e in constrained if getattr(e, "protocol_transition", False)]
        if proto_trans:
            detail = "\n".join(
                f"  {getattr(e, 'account_name', '')} → "
                f"{', '.join(getattr(e, 'allowed_to_delegate_to', []))}"
                for e in proto_trans
            )
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description=f"Constrained delegation WITH protocol transition on {len(proto_trans)} account(s)",
                evidence=f"Accounts with S4U2Self + S4U2Proxy:\n{detail}",
                recommendation="Remove TrustedToAuthForDelegation flag. Use RBCD instead.",
                references=["https://attack.mitre.org/techniques/T1550/003/"],
                phase="delegation_discovery",
            ))

        # RBCD
        rbcd = data.get("rbcd", [])
        if rbcd:
            detail = "\n".join(
                f"  {getattr(e, 'target_account', '')} ← "
                f"{', '.join(getattr(e, 'allowed_principals', []))}"
                for e in rbcd
            )
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="critical",
                confidence="confirmed",
                target=target,
                description=f"Resource-Based Constrained Delegation on {len(rbcd)} account(s)",
                evidence=f"RBCD configurations:\n{detail}",
                recommendation="Audit msDS-AllowedToActOnBehalfOfOtherIdentity. Remove unnecessary entries.",
                references=["https://attack.mitre.org/techniques/T1550/003/"],
                phase="delegation_discovery",
            ))

    # ── Kerberos ────────────────────────────────────────────────

    def _analyze_kerberos(
        self, data: Dict, target: str, result: AnalysisResult,
    ) -> None:
        # SPN accounts (Kerberoasting)
        spn_accounts = data.get("spn_accounts", [])
        if spn_accounts:
            evidence = "Accounts: " + ", ".join(
                f"{a.get('username', '')} ({', '.join(a.get('spn', [])[:2])})"
                for a in spn_accounts[:10]
            )
            result.findings.append(self._make_finding(
                finding_type="vulnerability",
                severity="high",
                confidence="confirmed",
                target=target,
                description=f"{len(spn_accounts)} service account(s) with SPNs — Kerberoasting targets",
                evidence=evidence,
                recommendation=(
                    "Use Group Managed Service Accounts (gMSA) with strong, "
                    "rotated passwords. Remove SPNs from non-service accounts."
                ),
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                phase="identity_enumeration",
            ))
            result.data["kerberoastable_count"] = len(spn_accounts)

        # AS-REP roastable
        asrep = data.get("asrep_users", [])
        if asrep:
            names = [a.get("username", "") for a in asrep if a.get("username")]
            result.findings.append(self._make_finding(
                finding_type="vulnerability",
                severity="high",
                confidence="confirmed",
                target=target,
                description=f"{len(names)} AS-REP roastable user(s) — pre-authentication disabled",
                evidence=f"Users: {', '.join(names)}",
                recommendation=(
                    "Enable Kerberos pre-authentication for all accounts. "
                    "Enforce strong passwords on affected accounts."
                ),
                references=["https://attack.mitre.org/techniques/T1558/004/"],
                phase="identity_enumeration",
            ))
            result.data["asrep_count"] = len(names)

    # ── MachineAccountQuota ─────────────────────────────────────

    def _analyze_maq(
        self, data: Dict, target: str, result: AnalysisResult,
    ) -> None:
        maq = data.get("machine_account_quota", -1)
        if maq > 0:
            result.findings.append(self._make_finding(
                finding_type="misconfiguration",
                severity="high",
                confidence="confirmed",
                target=target,
                description=f"MachineAccountQuota is {maq} — authenticated users can create computer accounts",
                evidence=f"ms-DS-MachineAccountQuota: {maq}",
                recommendation="Set ms-DS-MachineAccountQuota to 0",
                references=["https://attack.mitre.org/techniques/T1098/"],
                phase="delegation_discovery",
            ))
            result.data["maq"] = maq
