"""ReconForge Enum4linux Parser - Parse enum4linux output.

Extracts:
- Workgroup/domain name
- Users and RIDs
- Groups and members
- Shares and access level
- Password policy
- OS information
- Null session status
"""

import re
from dataclasses import dataclass, field


@dataclass
class Enum4linuxResult:
    """Parsed enum4linux output."""
    target: str = ""
    workgroup: str = ""
    domain: str = ""
    os_info: str = ""
    server_type: str = ""
    users: list[dict[str, str]] = field(default_factory=list)
    groups: list[dict[str, str]] = field(default_factory=list)
    shares: list[dict[str, str]] = field(default_factory=list)
    password_policy: dict[str, str] = field(default_factory=dict)
    null_session: bool = False
    sessions: list[str] = field(default_factory=list)
    domain_sid: str = ""
    raw_output: str = ""
    errors: list[str] = field(default_factory=list)


class Enum4linuxParser:
    """Parse enum4linux text output into structured data."""

    def parse(self, text: str) -> Enum4linuxResult:
        """Parse full enum4linux output.

        Args:
            text: Raw enum4linux output text.

        Returns:
            Enum4linuxResult with extracted data.
        """
        result = Enum4linuxResult(raw_output=text)

        if not text.strip():
            result.errors.append("Empty output")
            return result

        self._parse_target(text, result)
        self._parse_workgroup(text, result)
        self._parse_null_session(text, result)
        self._parse_os_info(text, result)
        self._parse_users(text, result)
        self._parse_groups(text, result)
        self._parse_shares(text, result)
        self._parse_password_policy(text, result)
        self._parse_domain_sid(text, result)

        return result

    def _parse_target(self, text: str, result: Enum4linuxResult):
        """Extract target IP."""
        match = re.search(r"Target\s*\.+\s*(\S+)", text)
        if match:
            result.target = match.group(1)

    def _parse_workgroup(self, text: str, result: Enum4linuxResult):
        """Extract workgroup/domain name."""
        match = re.search(r"Workgroup\s*\.+\s*(\S+)", text, re.IGNORECASE)
        if match:
            result.workgroup = match.group(1)

        match = re.search(r"Domain Name:\s*(\S+)", text, re.IGNORECASE)
        if match:
            result.domain = match.group(1)

    def _parse_null_session(self, text: str, result: Enum4linuxResult):
        """Check if null session is possible."""
        if any(indicator in text.lower() for indicator in
               ["null session", "session setup ok",
                "server allows session using username"]):
            result.null_session = True

    def _parse_os_info(self, text: str, result: Enum4linuxResult):
        """Extract OS information."""
        match = re.search(
            r"OS=\[([^\]]+)\]\s*Server=\[([^\]]+)\]", text
        )
        if match:
            result.os_info = match.group(1)
            result.server_type = match.group(2)

    def _parse_users(self, text: str, result: Enum4linuxResult):
        """Extract user accounts."""
        # Pattern: user:[username] rid:[rid]
        for match in re.finditer(
            r"user:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]", text
        ):
            result.users.append({
                "username": match.group(1),
                "rid": match.group(2),
            })

        # Also try S-1-5-21 format
        for match in re.finditer(
            r"(S-1-5-21-[\d-]+)\s+(\S+)\s+\(Local User\)", text
        ):
            username = match.group(2)
            if not any(u["username"] == username for u in result.users):
                result.users.append({
                    "username": username,
                    "sid": match.group(1),
                })

    def _parse_groups(self, text: str, result: Enum4linuxResult):
        """Extract groups."""
        # Pattern: group:[groupname] rid:[rid]
        for match in re.finditer(
            r"group:\[([^\]]+)\]\s+rid:\[0x([0-9a-fA-F]+)\]", text
        ):
            result.groups.append({
                "name": match.group(1),
                "rid": match.group(2),
            })

    def _parse_shares(self, text: str, result: Enum4linuxResult):
        """Extract share information."""
        # Disk shares
        for match in re.finditer(
            r"\t(\S+)\s+Disk\s+(.*)", text
        ):
            share_name = match.group(1).strip()
            comment = match.group(2).strip()
            result.shares.append({
                "name": share_name,
                "type": "Disk",
                "comment": comment,
            })

        # IPC shares
        for match in re.finditer(
            r"\t(\S+)\s+IPC\s+(.*)", text
        ):
            share_name = match.group(1).strip()
            comment = match.group(2).strip()
            result.shares.append({
                "name": share_name,
                "type": "IPC",
                "comment": comment,
            })

        # Check share access
        for match in re.finditer(
            r"//[^/]+/(\S+)\s+Mapping:\s+(\S+)\s+Listing:\s+(\S+)", text
        ):
            share_name = match.group(1)
            for share in result.shares:
                if share["name"] == share_name:
                    share["mapping"] = match.group(2)
                    share["listing"] = match.group(3)

    def _parse_password_policy(self, text: str, result: Enum4linuxResult):
        """Extract password policy."""
        policy_patterns = {
            "min_length": r"Minimum password length:\s*(\d+)",
            "history_length": r"Password history length:\s*(\d+)",
            "max_age": r"Maximum password age:\s*(.+?)$",
            "min_age": r"Minimum password age:\s*(.+?)$",
            "lockout_threshold": r"Account Lockout Threshold:\s*(\S+)",
            "complexity": r"Password Complexity Flags:\s*(\S+)",
        }

        for key, pattern in policy_patterns.items():
            match = re.search(pattern, text, re.MULTILINE)
            if match:
                result.password_policy[key] = match.group(1).strip()

    def _parse_domain_sid(self, text: str, result: Enum4linuxResult):
        """Extract domain SID."""
        match = re.search(r"Domain Sid:\s*(S-1-5-21-[\d-]+)", text)
        if match:
            result.domain_sid = match.group(1)

    def get_usernames(self, result: Enum4linuxResult) -> list[str]:
        """Get a clean list of usernames."""
        return [u["username"] for u in result.users]

    def get_accessible_shares(self, result: Enum4linuxResult) -> list[dict]:
        """Get shares that appear accessible."""
        accessible = []
        for share in result.shares:
            if share.get("mapping") == "OK" or share.get("listing") == "OK":
                accessible.append(share)
        return accessible
