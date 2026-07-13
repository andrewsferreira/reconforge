"""ReconForge AD Collector — Delegation data gathering.

Author: Andrews Ferreira

Collects unconstrained, constrained, and RBCD delegation data,
plus MachineAccountQuota for RBCD feasibility.
"""

import re
from typing import Any, Dict, List, Tuple

from modules.ad.collectors.base import CollectorBase, CollectorResult
from modules.ad.tools.ldapsearch import ADLdapsearchTool
from modules.ad.tools.advanced_impacket import AdvancedImpacketTool
from modules.ad.tools.netexec import NetexecTool
from modules.ad.parsers.ldap_parser import ADLdapParser
from modules.ad.parsers.delegation_parser import DelegationParser


class DelegationCollector(CollectorBase):
    """Pure delegation data collection — unconstrained, constrained, RBCD."""

    COLLECTOR_NAME = "delegation"

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

    def collect(
        self,
        target: str,
        domain: str = "",
        base_dn: str = "",
        username: str = "",
        password: str = "",
        **kwargs,
    ) -> CollectorResult:
        """Collect all delegation data.

        success reflects whether at least one delegation-gathering query
        actually completed (LDAP bind + search returned, or findDelegation.py
        ran) — not merely that this method returned without raising. Each
        query silently returns [] on tool-unavailable, opsec-block, missing
        base_dn, or a failed LDAP run alike; without tracking which of
        those happened, a total collection failure (e.g. every LDAP bind
        rejected) would be indistinguishable in the output from a genuinely
        clean environment with zero delegations configured.
        """
        result = CollectorResult(source=self.COLLECTOR_NAME)

        if not base_dn and domain:
            base_dn = ",".join(f"DC={p}" for p in domain.split("."))

        unconstrained, unconstrained_ok = self._query_unconstrained(
            target, base_dn, username, password
        )
        constrained, constrained_ok = self._query_constrained(
            target, base_dn, username, password
        )
        rbcd, rbcd_ok = self._query_rbcd(
            target, base_dn, username, password
        )
        result.data["unconstrained"] = unconstrained
        result.data["constrained"] = constrained
        result.data["rbcd"] = rbcd

        # Merge with findDelegation.py if available
        fd, find_delegation_ok = self._run_find_delegation(target, domain, username, password)
        if fd:
            result.data["unconstrained"] = self._merge_unique(
                result.data["unconstrained"], fd.get("unconstrained", []),
                key="account_name",
            )
            result.data["constrained"] = self._merge_unique(
                result.data["constrained"], fd.get("constrained", []),
                key="account_name",
            )
            result.data["rbcd"] = self._merge_unique(
                result.data["rbcd"], fd.get("rbcd", []),
                key="target_account",
            )

        result.data["machine_account_quota"] = self._check_maq(
            target, domain, username, password
        )

        result.success = unconstrained_ok or constrained_ok or rbcd_ok or find_delegation_ok
        if not result.success:
            result.errors.append(
                "No delegation query completed — ldapsearch/findDelegation.py "
                "unavailable, opsec-blocked, missing base DN, or every LDAP "
                "run failed. Results reflect zero visibility, not a confirmed "
                "absence of delegation."
            )
        return result

    # ── LDAP queries ───────────────────────────────────────────────

    def _query_unconstrained(self, target: str, base_dn: str,
                             username: str, password: str) -> Tuple[List, bool]:
        if not self.ldapsearch.is_available() or not base_dn:
            return [], False
        if not self.opsec.check("ldapsearch"):
            return [], False

        bind = self.ldapsearch._bind_args(target, 389, username, password)
        cmd = (
            f"ldapsearch {bind} -b '{base_dn}' "
            f"'(userAccountControl:1.2.840.113556.1.4.803:=524288)' "
            f"sAMAccountName userAccountControl dn objectClass dNSHostName"
        )
        run = self.ldapsearch.runner.run(
            cmd, timeout=120,
            output_file=self.output_dir / "ldap_unconstrained.txt",
        )
        if not run.success:
            return [], False
        return self.delegation_parser.parse_unconstrained(run.stdout), True

    def _query_constrained(self, target: str, base_dn: str,
                           username: str, password: str) -> Tuple[List, bool]:
        if not self.ldapsearch.is_available() or not base_dn:
            return [], False
        if not self.opsec.check("ldapsearch"):
            return [], False

        bind = self.ldapsearch._bind_args(target, 389, username, password)
        cmd = (
            f"ldapsearch {bind} -b '{base_dn}' "
            f"'(msDS-AllowedToDelegateTo=*)' "
            f"sAMAccountName msDS-AllowedToDelegateTo "
            f"userAccountControl dn objectClass"
        )
        run = self.ldapsearch.runner.run(
            cmd, timeout=120,
            output_file=self.output_dir / "ldap_constrained.txt",
        )
        if not run.success:
            return [], False
        return self.delegation_parser.parse_constrained(run.stdout), True

    def _query_rbcd(self, target: str, base_dn: str,
                    username: str, password: str) -> Tuple[List, bool]:
        if not self.ldapsearch.is_available() or not base_dn:
            return [], False
        if not self.opsec.check("ldapsearch"):
            return [], False

        bind = self.ldapsearch._bind_args(target, 389, username, password)
        cmd = (
            f"ldapsearch {bind} -b '{base_dn}' "
            f"'(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' "
            f"sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity "
            f"dn objectClass"
        )
        run = self.ldapsearch.runner.run(
            cmd, timeout=120,
            output_file=self.output_dir / "ldap_rbcd.txt",
        )
        if not run.success:
            return [], False
        return self.delegation_parser.parse_rbcd(run.stdout), True

    def _run_find_delegation(self, target: str, domain: str,
                             username: str, password: str) -> Tuple[Dict, bool]:
        if not self.advanced_impacket.is_available("finddelegation"):
            return {}, False
        if not username or not password:
            return {}, False
        if not self.opsec.check("impacket_finddelegation"):
            return {}, False

        run = self.advanced_impacket.find_delegation(
            target=domain, domain=domain,
            username=username, password=password,
            dc_ip=target,
        )
        if not run.success:
            return {}, False
        return self.delegation_parser.parse_find_delegation(run.stdout), True

    def _check_maq(self, target: str, domain: str,
                   username: str, password: str) -> int:
        """Return MachineAccountQuota value (-1 if unknown)."""
        if not domain:
            return -1
        run = self.advanced_impacket.get_machine_account_quota(
            target=target, domain=domain,
            username=username, password=password,
            dc_ip=target,
        )
        if not run.success:
            return -1
        match = re.search(
            r"ms-DS-MachineAccountQuota:\s*(\d+)",
            run.stdout, re.IGNORECASE,
        )
        return int(match.group(1)) if match else -1

    @staticmethod
    def _merge_unique(existing: List, new: List, key: str) -> List:
        """Merge two lists of objects deduplicating by attribute name."""
        seen = {getattr(e, key, None) for e in existing}
        for item in new:
            val = getattr(item, key, None)
            if val and val not in seen:
                existing.append(item)
                seen.add(val)
        return existing
