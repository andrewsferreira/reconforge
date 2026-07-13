"""ReconForge AD - Delegation Discovery Parser.

Parses delegation-related output from:
- findDelegation.py (impacket) : Tabular delegation listing
- ldapsearch queries           : Raw LDAP delegation attributes

Delegation types parsed:
- Unconstrained delegation (TrustedForDelegation / UAC 524288)
- Constrained delegation (msDS-AllowedToDelegateTo)
- Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)

Author: Andrews Ferreira
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List

from modules.ad.parsers.ldif_utils import split_ldif_entries


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class UnconstrainedDelegation:
    """An account with unconstrained delegation configured."""
    account_name: str = ""
    account_type: str = ""  # user or computer
    dn: str = ""
    object_sid: str = ""
    user_account_control: int = 0
    is_dc: bool = False

    @property
    def risk(self) -> str:
        """Unconstrained delegation is always critical (except DCs)."""
        if self.is_dc:
            return "info"
        return "critical"


@dataclass
class ConstrainedDelegation:
    """An account with constrained delegation configured."""
    account_name: str = ""
    account_type: str = ""  # user or computer
    dn: str = ""
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    protocol_transition: bool = False  # TrustedToAuthForDelegation
    user_account_control: int = 0

    @property
    def risk(self) -> str:
        if self.protocol_transition:
            return "critical"
        return "high"


@dataclass
class RBCDelegation:
    """An account with Resource-Based Constrained Delegation."""
    target_account: str = ""  # The account that can be impersonated
    target_dn: str = ""
    allowed_principals: List[str] = field(default_factory=list)
    raw_descriptor: str = ""

    @property
    def risk(self) -> str:
        return "critical"


class DelegationParser:
    """Parse delegation discovery output from various tools."""

    # ------------------------------------------------------------------
    # findDelegation.py (impacket) output
    # ------------------------------------------------------------------

    def parse_find_delegation(self, text: str) -> Dict[str, list]:
        """Parse impacket findDelegation.py output.

        The output is typically a table with columns:
        AccountName  AccountType  DelegationType  DelegationRightsTo

        Args:
            text: Raw stdout from findDelegation.py.

        Returns:
            Dict with 'unconstrained', 'constrained', and 'rbcd' lists.
        """
        unconstrained: List[UnconstrainedDelegation] = []
        constrained: List[ConstrainedDelegation] = []
        rbcd: List[RBCDelegation] = []

        in_table = False
        for line in text.splitlines():
            line = line.strip()

            # Detect table header
            if "AccountName" in line and "DelegationType" in line:
                in_table = True
                continue

            # Skip separator lines
            if line.startswith("-") or not line:
                continue

            if not in_table:
                continue

            # Parse table row (space-separated or tab-separated)
            parts = re.split(r"\s{2,}|\t+", line)
            if len(parts) < 3:
                continue

            account_name = parts[0].strip()
            account_type = parts[1].strip() if len(parts) > 1 else ""
            delegation_type = parts[2].strip() if len(parts) > 2 else ""
            delegation_target = parts[3].strip() if len(parts) > 3 else ""

            dtype_lower = delegation_type.lower()

            if "unconstrained" in dtype_lower:
                entry = UnconstrainedDelegation(
                    account_name=account_name,
                    account_type=account_type,
                )
                unconstrained.append(entry)

            elif "constrained" in dtype_lower and "resource" not in dtype_lower:
                targets = [t.strip() for t in delegation_target.split(",")
                           if t.strip()]
                entry = ConstrainedDelegation(
                    account_name=account_name,
                    account_type=account_type,
                    allowed_to_delegate_to=targets,
                    protocol_transition="w/ Protocol Transition" in delegation_type
                                        or "protocol" in dtype_lower,
                )
                constrained.append(entry)

            elif "resource" in dtype_lower or "rbcd" in dtype_lower:
                principals = [t.strip() for t in delegation_target.split(",")
                              if t.strip()]
                entry = RBCDelegation(
                    target_account=account_name,
                    allowed_principals=principals,
                )
                rbcd.append(entry)

        return {
            "unconstrained": unconstrained,
            "constrained": constrained,
            "rbcd": rbcd,
        }

    # ------------------------------------------------------------------
    # LDAP-based parsing
    # ------------------------------------------------------------------

    def parse_unconstrained(self, text: str) -> List[UnconstrainedDelegation]:
        """Parse LDAP query output for unconstrained delegation.

        Expects ldapsearch output filtered by:
        userAccountControl:1.2.840.113556.1.4.803:=524288

        Args:
            text: Raw ldapsearch stdout.

        Returns:
            List of UnconstrainedDelegation entries.
        """
        entries: List[UnconstrainedDelegation] = []

        for block in self._split_ldap_entries(text):
            sam = self._first(block, "samaccountname")
            if not sam:
                continue

            uac = self._int_val(block, "useraccountcontrol")
            entry = UnconstrainedDelegation(
                account_name=sam,
                dn=self._first(block, "dn"),
                user_account_control=uac,
                # SERVER_TRUST_ACCOUNT = 0x2000 → domain controller
                is_dc=bool(uac & 0x2000),
            )

            # Determine account type
            obj_class = " ".join(self._all(block, "objectclass")).lower()
            if "computer" in obj_class:
                entry.account_type = "computer"
            else:
                entry.account_type = "user"

            entries.append(entry)

        return entries

    def parse_constrained(self, text: str) -> List[ConstrainedDelegation]:
        """Parse LDAP query output for constrained delegation.

        Expects ldapsearch output containing msDS-AllowedToDelegateTo.

        Args:
            text: Raw ldapsearch stdout.

        Returns:
            List of ConstrainedDelegation entries.
        """
        entries: List[ConstrainedDelegation] = []

        for block in self._split_ldap_entries(text):
            sam = self._first(block, "samaccountname")
            delegates = self._all(block, "msds-allowedtodelegateto")
            if not sam:
                continue

            uac = self._int_val(block, "useraccountcontrol")
            entry = ConstrainedDelegation(
                account_name=sam,
                dn=self._first(block, "dn"),
                allowed_to_delegate_to=delegates,
                user_account_control=uac,
                # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
                protocol_transition=bool(uac & 0x1000000),
            )

            obj_class = " ".join(self._all(block, "objectclass")).lower()
            if "computer" in obj_class:
                entry.account_type = "computer"
            else:
                entry.account_type = "user"

            entries.append(entry)

        return entries

    def parse_rbcd(self, text: str) -> List[RBCDelegation]:
        """Parse LDAP query output for Resource-Based Constrained Delegation.

        Expects ldapsearch output containing
        msDS-AllowedToActOnBehalfOfOtherIdentity.

        Args:
            text: Raw ldapsearch stdout.

        Returns:
            List of RBCDelegation entries.
        """
        entries: List[RBCDelegation] = []

        for block in self._split_ldap_entries(text):
            sam = self._first(block, "samaccountname")
            raw_sd = self._first(
                block, "msds-allowedtoactonbehalfofotheridentity"
            )
            if not sam or not raw_sd:
                continue

            entry = RBCDelegation(
                target_account=sam,
                target_dn=self._first(block, "dn"),
                raw_descriptor=raw_sd,
            )

            # Try to extract SIDs from the security descriptor
            sid_matches = re.findall(r"S-1-5-[\d-]+", raw_sd)
            if sid_matches:
                entry.allowed_principals = sid_matches

            entries.append(entry)

        return entries

    def parse_ldap_delegation(self, text: str) -> Dict[str, list]:
        """Parse a general LDAP delegation query that may contain
        all delegation types mixed together.

        Args:
            text: Raw ldapsearch stdout.

        Returns:
            Dict with 'unconstrained', 'constrained', and 'rbcd' lists.
        """
        unconstrained: List[UnconstrainedDelegation] = []
        constrained: List[ConstrainedDelegation] = []
        rbcd: List[RBCDelegation] = []

        for block in self._split_ldap_entries(text):
            sam = self._first(block, "samaccountname")
            if not sam:
                continue

            uac = self._int_val(block, "useraccountcontrol")
            delegates = self._all(block, "msds-allowedtodelegateto")
            rbcd_attr = self._first(
                block, "msds-allowedtoactonbehalfofotheridentity"
            )

            obj_class = " ".join(self._all(block, "objectclass")).lower()
            acct_type = "computer" if "computer" in obj_class else "user"

            # Check unconstrained (TRUSTED_FOR_DELEGATION = 0x80000)
            if uac & 0x80000:
                unconstrained.append(UnconstrainedDelegation(
                    account_name=sam,
                    account_type=acct_type,
                    dn=self._first(block, "dn"),
                    user_account_control=uac,
                    is_dc=bool(uac & 0x2000),
                ))

            # Check constrained
            if delegates:
                constrained.append(ConstrainedDelegation(
                    account_name=sam,
                    account_type=acct_type,
                    dn=self._first(block, "dn"),
                    allowed_to_delegate_to=delegates,
                    user_account_control=uac,
                    protocol_transition=bool(uac & 0x1000000),
                ))

            # Check RBCD
            if rbcd_attr:
                entry = RBCDelegation(
                    target_account=sam,
                    target_dn=self._first(block, "dn"),
                    raw_descriptor=rbcd_attr,
                )
                sid_matches = re.findall(r"S-1-5-[\d-]+", rbcd_attr)
                if sid_matches:
                    entry.allowed_principals = sid_matches
                rbcd.append(entry)

        return {
            "unconstrained": unconstrained,
            "constrained": constrained,
            "rbcd": rbcd,
        }

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _split_ldap_entries(text: str) -> List[Dict[str, List[str]]]:
        """Split ldapsearch text output into attribute dicts.

        Shared with ADLdapParser._split_entries via ldif_utils.split_ldif_entries.
        """
        return split_ldif_entries(text)

    @staticmethod
    def _first(d: Dict[str, List[str]], key: str,
               default: str = "") -> str:
        vals = d.get(key, [])
        return vals[0] if vals else default

    @staticmethod
    def _all(d: Dict[str, List[str]], key: str) -> List[str]:
        return d.get(key, [])

    @staticmethod
    def _int_val(d: Dict[str, List[str]], key: str,
                 default: int = 0) -> int:
        val = d.get(key, [""])[0] if d.get(key) else ""
        try:
            return int(val)
        except (ValueError, TypeError):
            return default
