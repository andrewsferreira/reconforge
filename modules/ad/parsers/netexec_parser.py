"""ReconForge AD - NetExec Output Parser.

Parses netexec (nxc / crackmapexec) text output:
- SMB enumeration results (hosts, shares, users, OS info)
- LDAP enumeration results (users, descriptions)
- SMB signing status

Author: Andrews Ferreira
"""

import re
from dataclasses import dataclass
from typing import Dict, List


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NetexecHost:
    """A host discovered by netexec SMB scan."""
    ip: str = ""
    hostname: str = ""
    domain: str = ""
    os: str = ""
    signing: bool = True
    smbv1: bool = False
    port: int = 445

    @property
    def fqdn(self) -> str:
        if self.hostname and self.domain:
            return f"{self.hostname}.{self.domain}"
        return self.hostname or self.ip


@dataclass
class NetexecShare:
    """A share discovered by netexec --shares."""
    name: str = ""
    share_type: str = ""
    remark: str = ""
    read: bool = False
    write: bool = False
    host: str = ""


@dataclass
class NetexecUser:
    """A user discovered by netexec LDAP or SMB enumeration."""
    username: str = ""
    description: str = ""
    badpwdcount: int = 0
    domain: str = ""
    admin: bool = False


class NetexecParser:
    """Parse netexec / nxc / crackmapexec text output."""

    # ------------------------------------------------------------------
    # SMB output
    # ------------------------------------------------------------------

    def parse_smb_output(self, text: str) -> Dict[str, object]:
        """Parse netexec SMB enumeration output.

        Extracts hosts, shares, and user information from the
        combined SMB scan output.

        Args:
            text: Raw stdout from netexec smb command.

        Returns:
            Dict with 'hosts', 'shares', and 'users' keys.
        """
        hosts: List[NetexecHost] = []
        shares: List[NetexecShare] = []
        users: List[NetexecUser] = []

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Host discovery line:
            # SMB  10.0.0.1  445  DC01  [*] Windows Server 2019 ...
            host_match = re.match(
                r"SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s+(.*)",
                line,
            )
            if host_match:
                host = NetexecHost(
                    ip=host_match.group(1),
                    port=int(host_match.group(2)),
                    hostname=host_match.group(3),
                    os=host_match.group(4).strip(),
                )
                # Check signing in OS info line
                if "signing:True" in line or "(signing:True)" in line:
                    host.signing = True
                elif "signing:False" in line or "(signing:False)" in line:
                    host.signing = False
                # Check SMBv1
                if "SMBv1:True" in line or "(SMBv1:True)" in line:
                    host.smbv1 = True

                # Extract domain from the os info
                domain_match = re.search(
                    r"\(name:(\S+)\)\s*\(domain:(\S+)\)", line
                )
                if domain_match:
                    host.hostname = domain_match.group(1)
                    host.domain = domain_match.group(2)

                hosts.append(host)
                continue

            # Share enumeration line:
            # SMB  10.0.0.1  445  DC01  ADMIN$  ... READ,WRITE
            share_match = re.match(
                r"SMB\s+(\S+)\s+\d+\s+\S+\s+(\S+)\s+(.*)",
                line,
            )
            if share_match and any(kw in line.upper() for kw in
                                   ("READ", "WRITE", "NO ACCESS")):
                share = NetexecShare(
                    host=share_match.group(1),
                    name=share_match.group(2),
                    remark=share_match.group(3).strip(),
                )
                share.read = "READ" in line.upper()
                share.write = "WRITE" in line.upper()
                shares.append(share)
                continue

            # User enumeration line:
            # SMB  10.0.0.1  445  DC01  [+] corp.local\admin:pass (Pwn3d!)
            user_match = re.match(
                r"SMB\s+\S+\s+\d+\s+\S+\s+\[\+\]\s+(?:(\S+)\\)?(\S+?):",
                line,
            )
            if user_match:
                user = NetexecUser(
                    domain=user_match.group(1) or "",
                    username=user_match.group(2),
                    admin="Pwn3d!" in line,
                )
                users.append(user)

        return {
            "hosts": hosts,
            "shares": shares,
            "users": users,
        }

    # ------------------------------------------------------------------
    # LDAP output
    # ------------------------------------------------------------------

    def parse_ldap_output(self, text: str) -> List[NetexecUser]:
        """Parse netexec LDAP enumeration output.

        Args:
            text: Raw stdout from netexec ldap command.

        Returns:
            List of NetexecUser objects.
        """
        users: List[NetexecUser] = []

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # LDAP user line variants:
            # LDAP  10.0.0.1  389  DC01  username  description
            ldap_match = re.match(
                r"LDAP\s+\S+\s+\d+\s+\S+\s+(\S+)\s*(.*)",
                line,
            )
            if ldap_match:
                username = ldap_match.group(1)
                # Skip non-user info lines
                if username.startswith("[") or username in (
                    "Enumerated", "Getting", "Total",
                ):
                    continue
                user = NetexecUser(
                    username=username,
                    description=ldap_match.group(2).strip(),
                )
                users.append(user)

        return users

    # ------------------------------------------------------------------
    # Signing status
    # ------------------------------------------------------------------

    def parse_signing_status(self, text: str) -> Dict[str, bool]:
        """Parse SMB signing status from netexec output.

        Args:
            text: Raw stdout from netexec smb / signing check.

        Returns:
            Dict mapping IP → signing_required (True/False).
        """
        signing: Dict[str, bool] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Standard host line with signing info
            match = re.match(r"SMB\s+(\S+)\s+\d+\s+\S+", line)
            if match:
                ip = match.group(1)
                if "signing:True" in line:
                    signing[ip] = True
                elif "signing:False" in line:
                    signing[ip] = False

        return signing
