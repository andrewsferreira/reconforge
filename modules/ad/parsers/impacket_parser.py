"""ReconForge AD - Impacket Output Parser.

Parses output from:
- GetADUsers.py  : User table
- GetNPUsers.py  : AS-REP hashes
- lookupsid.py   : RID cycling results
- rpcdump.py     : RPC endpoint listing

Author: Andrews Ferreira
"""

import re
from dataclasses import dataclass, field


@dataclass
class ImpacketUser:
    """A user parsed from GetADUsers output."""
    username: str = ""
    email: str = ""
    password_last_set: str = ""
    last_logon: str = ""
    description: str = ""


@dataclass
class ASREPHash:
    """An AS-REP hash from GetNPUsers output."""
    username: str = ""
    hash: str = ""


@dataclass
class RIDEntry:
    """A SID-to-name mapping from lookupsid."""
    rid: int = 0
    name: str = ""
    sid_type: str = ""  # SidTypeUser, SidTypeGroup, SidTypeAlias, etc.
    full_sid: str = ""


@dataclass
class RPCEndpoint:
    """An RPC endpoint from rpcdump."""
    uuid: str = ""
    annotation: str = ""
    bindings: list[str] = field(default_factory=list)


class ImpacketParser:
    """Parse Impacket tool outputs."""

    # ------------------------------------------------------------------
    # GetADUsers.py
    # ------------------------------------------------------------------

    def parse_getadusers(self, text: str) -> list[ImpacketUser]:
        """Parse GetADUsers.py output.

        Expected format (tab / multi-space delimited table):
        Name   Email  PasswordLastSet  LastLogon  ...
        """
        users: list[ImpacketUser] = []
        lines = text.strip().splitlines()

        # Find the header line
        header_idx = -1
        for i, line in enumerate(lines):
            if "Name" in line and "PasswordLastSet" in line:
                header_idx = i
                break
        if header_idx < 0:
            return users

        # Skip separator line (dashes)
        data_start = header_idx + 1
        if data_start < len(lines) and lines[data_start].startswith("-"):
            data_start += 1

        for line in lines[data_start:]:
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # Split on 2+ spaces
            parts = re.split(r"\s{2,}", line)
            if len(parts) >= 4:
                users.append(ImpacketUser(
                    username=parts[0].strip(),
                    email=parts[1].strip() if len(parts) > 1 else "",
                    password_last_set=parts[2].strip() if len(parts) > 2 else "",
                    last_logon=parts[3].strip() if len(parts) > 3 else "",
                    description=parts[4].strip() if len(parts) > 4 else "",
                ))
            elif len(parts) >= 1:
                users.append(ImpacketUser(username=parts[0].strip()))

        return users

    # ------------------------------------------------------------------
    # GetNPUsers.py (AS-REP)
    # ------------------------------------------------------------------

    def parse_getnpusers(self, text: str) -> list[ASREPHash]:
        """Parse GetNPUsers.py output for AS-REP hashes.

        Hashes look like: $krb5asrep$23$user@DOMAIN:...
        """
        hashes: list[ASREPHash] = []

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("$krb5asrep$"):
                # Extract username from hash
                m = re.match(r"\$krb5asrep\$\d+\$([^@:]+)", line)
                username = m.group(1) if m else "unknown"
                hashes.append(ASREPHash(username=username, hash=line))

        # Also look for "User ... doesn't have UF_DONT_REQUIRE_PREAUTH"
        # or "[-] User ... doesn't require pre-auth" messages
        return hashes

    def parse_getnpusers_vulnerable(self, text: str) -> list[str]:
        """Extract usernames that are AS-REP roastable (even without hash capture)."""
        vulnerable: list[str] = []
        for line in text.splitlines():
            if "$krb5asrep$" in line:
                m = re.match(r"\$krb5asrep\$\d+\$([^@:]+)", line.strip())
                if m:
                    vulnerable.append(m.group(1))
        return vulnerable

    # ------------------------------------------------------------------
    # lookupsid.py (RID cycling)
    # ------------------------------------------------------------------

    def parse_lookupsid(self, text: str) -> list[RIDEntry]:
        """Parse lookupsid.py output.

        Format:  500: CORP\\Administrator (SidTypeUser)
        """
        entries: list[RIDEntry] = []

        for line in text.splitlines():
            m = re.match(
                r"\s*(\d+):\s+\S+\\(.+?)\s+\((SidType\w+)\)",
                line
            )
            if m:
                entries.append(RIDEntry(
                    rid=int(m.group(1)),
                    name=m.group(2).strip(),
                    sid_type=m.group(3),
                ))

        return entries

    def extract_users_from_rid(self, entries: list[RIDEntry]) -> list[str]:
        """Filter RID entries to return only usernames."""
        return [e.name for e in entries if e.sid_type == "SidTypeUser"]

    def extract_groups_from_rid(self, entries: list[RIDEntry]) -> list[str]:
        """Filter RID entries to return only group names."""
        return [e.name for e in entries if e.sid_type in ("SidTypeGroup", "SidTypeAlias")]

    # ------------------------------------------------------------------
    # rpcdump.py
    # ------------------------------------------------------------------

    def parse_rpcdump(self, text: str) -> list[RPCEndpoint]:
        """Parse rpcdump.py output."""
        endpoints: list[RPCEndpoint] = []
        current: RPCEndpoint | None = None

        for line in text.splitlines():
            line = line.rstrip()

            # New endpoint block
            m = re.match(r"Protocol:\s+\[(.+?)\]", line)
            if m:
                if current:
                    endpoints.append(current)
                current = RPCEndpoint()
                current.bindings.append(m.group(1))
                continue

            if current is None:
                continue

            m = re.match(r"Provider:\s+(.+)", line)
            if m:
                current.annotation = m.group(1).strip()

            m = re.match(r"UUID\s*:\s*([\w-]+)", line)
            if m:
                current.uuid = m.group(1)

            m = re.match(r"Bindings:\s+(.+)", line)
            if m:
                current.bindings.append(m.group(1).strip())

        if current:
            endpoints.append(current)

        return endpoints
