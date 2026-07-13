"""ReconForge AD - enum4linux-ng Output Parser.

Parses enum4linux-ng text and JSON output to extract:
- Domain / workgroup information
- Users, groups, shares
- Password policies
- OS information
- RID cycling results

Author: Andrews Ferreira
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class Enum4linuxNgResult:
    """Structured result from enum4linux-ng output."""
    domain: str = ""
    workgroup: str = ""
    os_info: str = ""
    smb_signing: str = ""
    users: List[Dict[str, str]] = field(default_factory=list)
    groups: List[Dict[str, str]] = field(default_factory=list)
    shares: List[Dict[str, str]] = field(default_factory=list)
    password_policy: Dict[str, str] = field(default_factory=dict)
    rid_users: List[Dict[str, str]] = field(default_factory=list)
    domain_sid: str = ""
    null_session: bool = False
    raw: str = ""


class Enum4linuxNgParser:
    """Parse enum4linux-ng output into structured data."""

    # ------------------------------------------------------------------
    # JSON parsing (preferred when -oJ is used)
    # ------------------------------------------------------------------

    def parse_json(self, json_path: Path) -> Enum4linuxNgResult:
        """Parse enum4linux-ng JSON output file."""
        result = Enum4linuxNgResult()
        try:
            data = json.loads(Path(json_path).read_text())
        except (json.JSONDecodeError, FileNotFoundError, OSError):
            return result

        # Target / domain info
        target_info = data.get("target", {})
        result.workgroup = target_info.get("workgroup", "")

        os_info = data.get("os_info", {})
        result.os_info = os_info.get("OS", "")
        result.smb_signing = os_info.get("signing", "")

        # Domain SID
        result.domain_sid = data.get("domain_sid", "")

        # Users
        for username, attrs in data.get("users", {}).items():
            result.users.append({
                "username": username,
                "full_name": attrs.get("Full Name", ""),
                "description": attrs.get("Description", ""),
                "rid": str(attrs.get("RID", "")),
            })

        # Groups
        for groupname, attrs in data.get("groups", {}).items():
            result.groups.append({
                "group": groupname,
                "rid": str(attrs.get("RID", "")),
                "members": attrs.get("members", []),
            })

        # Shares
        for share_name, attrs in data.get("shares", {}).items():
            result.shares.append({
                "name": share_name,
                "type": attrs.get("type", ""),
                "comment": attrs.get("comment", ""),
                "access": attrs.get("access", ""),
            })

        # Password policy
        pp = data.get("policy", data.get("password_policy", {}))
        if isinstance(pp, dict):
            result.password_policy = {k: str(v) for k, v in pp.items()}

        return result

    # ------------------------------------------------------------------
    # Text parsing (fallback)
    # ------------------------------------------------------------------

    def parse_text(self, text: str) -> Enum4linuxNgResult:
        """Parse enum4linux-ng plain text output."""
        result = Enum4linuxNgResult(raw=text)

        # Domain / workgroup
        m = re.search(r"Domain Name:\s*(.+)", text, re.I)
        if m:
            result.domain = m.group(1).strip()
        m = re.search(r"Workgroup:\s*(.+)", text, re.I)
        if m:
            result.workgroup = m.group(1).strip()

        # OS info
        m = re.search(r"OS:\s*(.+)", text, re.I)
        if m:
            result.os_info = m.group(1).strip()

        # SMB signing
        m = re.search(r"(?:SMB\s+)?[Ss]igning.*?:\s*(.+)", text)
        if m:
            result.smb_signing = m.group(1).strip()

        # Null session detection
        if re.search(r"null session|anonymous.*allowed|null.*auth", text, re.I):
            result.null_session = True

        # Domain SID
        m = re.search(r"Domain SID:\s*(S-1-[\d-]+)", text)
        if m:
            result.domain_sid = m.group(1)

        # Users  ("user:[username] rid:[0x1f4]"  or table rows)
        for m in re.finditer(
            r"user:\[([^\]]+)\]\s*rid:\[([^\]]+)\]", text
        ):
            result.users.append({"username": m.group(1), "rid": m.group(2)})

        # Groups
        for m in re.finditer(
            r"group:\[([^\]]+)\]\s*rid:\[([^\]]+)\]", text
        ):
            result.groups.append({"group": m.group(1), "rid": m.group(2)})

        # Shares
        for m in re.finditer(
            r"(\S+)\s+(?:Disk|IPC|Printer)\s+(.*)", text
        ):
            result.shares.append({
                "name": m.group(1),
                "comment": m.group(2).strip(),
            })

        # Password policy
        result.password_policy = self._extract_password_policy(text)

        # RID cycling
        for m in re.finditer(
            r"(\d+):\s+\S+\\(\S+)\s+\((?:SidTypeUser|SidTypeGroup|SidTypeAlias)\)", text
        ):
            result.rid_users.append({"rid": m.group(1), "name": m.group(2)})

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_password_policy(text: str) -> Dict[str, str]:
        """Extract password policy fields from text."""
        policy: Dict[str, str] = {}
        patterns = {
            "min_length": r"(?:Minimum password length|min\.?\s*password\s*length)[:\s]+(\d+)",
            "complexity": r"(?:Password Complexity|complexity)[:\s]+(\S+)",
            "lockout_threshold": r"(?:Account Lockout Threshold|lockout threshold)[:\s]+(\d+)",
            "lockout_duration": r"(?:Account Lockout Duration|lockout duration|Reset Account Lockout)[:\s]+([\d:]+\s*\w*)",
            "password_history": r"(?:Password History Length|password history)[:\s]+(\d+)",
            "max_password_age": r"(?:Maximum Password Age|max\.?\s*password\s*age)[:\s]+(\S+)",
            "min_password_age": r"(?:Minimum Password Age|min\.?\s*password\s*age)[:\s]+(\S+)",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, text, re.I)
            if m:
                policy[key] = m.group(1).strip()
        return policy
